// Offline analysis uses two passes: classify complete flows, then filter in capture order.
// Queues are closed and drained explicitly; packet accounting never relies on sleeps.
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "filter_rules.h"

using namespace PacketAnalyzer;
using namespace DPI;

template<class T> class Queue {
    std::mutex mutex;
    std::condition_variable available, space;
    std::queue<T> items;
    bool closed = false;
public:
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex);
        space.wait(lock, [&] { return items.size() < 128 || closed; });
        if (closed) return;
        items.push(std::move(item));
        available.notify_one();
    }
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex);
        available.wait(lock, [&] { return !items.empty() || closed; });
        if (items.empty()) return {};
        auto item = std::move(items.front()); items.pop(); space.notify_one(); return item;
    }
    void close() { std::lock_guard<std::mutex> lock(mutex); closed = true; available.notify_all(); space.notify_all(); }
};

std::string scope(const RawPacket& raw, const ParsedPacket& p) {
    auto value = std::to_string(raw.section_id) + "/" + std::to_string(raw.interface_id) + "/" +
        std::to_string(raw.link_type) + "/" + std::to_string(p.link_interface_index);
    for (auto vlan : p.vlan_ids) value += "/" + std::to_string(vlan);
    return value + "|";
}
std::string tuple(const RawPacket& raw, const ParsedPacket& p) {
    auto a = p.src_ip + ":" + std::to_string(p.src_port);
    auto b = p.dest_ip + ":" + std::to_string(p.dest_port);
    if (a > b) std::swap(a, b);
    return scope(raw, p) + std::to_string(p.protocol) + "|" + a + "|" + b;
}
std::string fragmentKey(const RawPacket& raw, const ParsedPacket& p) {
    // Only a first IPv6 fragment may expose the final transport after extension headers.
    const auto protocol = p.ip_version == 4 ? std::to_string(p.protocol) : "v6";
    return scope(raw, p) + p.src_ip + "|" + p.dest_ip + "|" + protocol + "|" + std::to_string(p.fragment_id);
}
// Retain associations rather than payload bytes. Once a complete datagram is
// accounted for, the same on-wire ID can safely start a new datagram.
class FragmentIndex {
    struct Assembly {
        size_t group = 0;
        bool first = false;
        std::optional<size_t> end;
        std::map<size_t, size_t> spans;
        void record(size_t start, size_t finish) {
            auto next = spans.lower_bound(start);
            if (next != spans.begin() && std::prev(next)->second >= start) --next;
            while (next != spans.end() && next->first <= finish) {
                start = std::min(start, next->first);
                finish = std::max(finish, next->second);
                next = spans.erase(next);
            }
            spans.emplace(start, finish);
        }
        bool complete() const {
            return first && end && spans.size() == 1 && spans.begin()->first == 0 && spans.begin()->second >= *end;
        }
    };
    std::unordered_map<std::string, Assembly> active;
    std::vector<std::string> flows;
    std::vector<size_t> packetGroups;
public:
    void track(const RawPacket& raw, const ParsedPacket& p, const std::string& flow) {
        auto identity = fragmentKey(raw, p);
        auto found = active.find(identity);
        const bool first = p.fragment_offset == 0;
        if (found == active.end() || (first && found->second.first && flows[found->second.group] != flow)) {
            if (flows.size() >= 200000) throw std::runtime_error("Fragmented datagram limit reached; split the capture.");
            Assembly fresh;
            fresh.group = flows.size();
            flows.emplace_back();
            found = active.insert_or_assign(identity, std::move(fresh)).first;
        }
        auto& group = found->second;
        if (packetGroups.size() >= 2000000) throw std::runtime_error("Fragment record limit reached; split the capture.");
        packetGroups.push_back(group.group);
        if (first) { flows[group.group] = flow; group.first = true; }
        if (p.fragment_data_offset && p.packet_end >= p.fragment_data_offset) {
            const size_t finish = p.fragment_offset + p.packet_end - p.fragment_data_offset;
            group.record(p.fragment_offset, finish);
            if (!p.more_fragments && !p.truncated) group.end = finish;
        }
        if (group.complete()) active.erase(found);
    }
    const std::string& flowAt(size_t fragmentOrdinal) const { return flows.at(packetGroups.at(fragmentOrdinal)); }
};
class Resolver {
    struct Epoch { uint32_t syn = 0; unsigned generation = 0; bool hasSyn = false; };
    std::unordered_map<std::string, Epoch> epochs;
public:
    std::string key(const RawPacket& raw, const ParsedPacket& p) {
        if (!p.has_tcp && !p.has_udp) return {};
        auto base = tuple(raw, p);
        if (!p.has_tcp) return base;
        auto found = epochs.find(base);
        if (found == epochs.end()) {
            if (epochs.size() >= 200000) throw std::runtime_error("Capture exceeds 200000 tracked TCP flows; split the capture and retry.");
            found = epochs.emplace(base, Epoch{}).first;
        }
        auto& epoch = found->second;
        if ((p.tcp_flags & 0x12) == 0x02 && (!epoch.hasSyn || epoch.syn != p.seq_number)) {
            if (epoch.hasSyn) ++epoch.generation;
            epoch.syn = p.seq_number; epoch.hasSyn = true;
        }
        return base + "#" + std::to_string(epoch.generation);
    }
};

struct Job {
    ParsedPacket parsed;
    std::string key;
    std::vector<uint8_t> payload;
};
struct Stream {
    bool initialized = false, exhausted = false;
    uint32_t next = 0;
    std::vector<uint8_t> bytes;
    std::map<uint32_t, std::vector<uint8_t>> pending;
    size_t pendingBytes = 0;
    static constexpr size_t LIMIT = 65536;
    void append(uint32_t seq, const std::vector<uint8_t>& data) {
        if (exhausted || data.empty()) return;
        if (!initialized) { initialized = true; next = seq; }
        auto distance = static_cast<int32_t>(seq - next);
        if (distance > 0) {
            if (pending.size() >= 32 || size_t(distance) > LIMIT || bytes.size() + pendingBytes + data.size() > LIMIT) { exhausted = true; return; }
            if (!pending.count(seq)) { pending.emplace(seq, data); pendingBytes += data.size(); }
            return;
        }
        size_t skip = distance < 0 ? size_t(-int64_t(distance)) : 0;
        if (skip < data.size()) {
            if (bytes.size() + data.size() - skip > LIMIT) { exhausted = true; return; }
            bytes.insert(bytes.end(), data.begin() + skip, data.end());
            next += static_cast<uint32_t>(data.size() - skip);
        }
        for (auto it = pending.begin(); it != pending.end();) {
            if (static_cast<int32_t>(it->first - next) > 0) { ++it; continue; }
            auto segment = std::move(it->second);
            auto sequence = it->first;
            pendingBytes -= segment.size();
            it = pending.erase(it);
            append(sequence, segment);
            it = pending.begin();
        }
    }
};
struct Flow {
    AppType app = AppType::UNKNOWN, base = AppType::UNKNOWN;
    std::string domain, blockedReason;
    std::unique_ptr<Stream> streams[2];
    bool synSeen[2]{false, false};
    uint32_t initialSeq[2]{0, 0};
    bool inspectionDone = false;
    std::optional<std::list<Flow*>::iterator> activePosition;
};
AppType baseApp(const ParsedPacket& p) {
    if ((p.has_tcp || p.has_udp) && (p.src_port == 53 || p.dest_port == 53)) return AppType::DNS;
    if (p.has_udp && (p.src_port == 443 || p.dest_port == 443)) return AppType::QUIC;
    if (p.has_tcp && (p.src_port == 443 || p.dest_port == 443)) return AppType::HTTPS;
    if (p.has_tcp && (p.src_port == 80 || p.dest_port == 80 || p.src_port == 8080 || p.dest_port == 8080)) return AppType::HTTP;
    return AppType::UNKNOWN;
}
std::optional<std::string> dnsDomain(const ParsedPacket& p) {
    if (p.is_fragment || p.parse_status != ParseStatus::Ok || !p.payload_data) return {};
    if (p.src_port != 53 && p.dest_port != 53) return {};
    auto data = p.payload_data; auto length = p.payload_length;
    if (p.has_tcp) {
        if (length < 2) return {};
        size_t size = (size_t(data[0]) << 8) | data[1];
        if (size > length - 2) return {};
        data += 2; length = size;
    }
    return DNSExtractor::extractQuery(data, length);
}
class Worker {
    const FilterRules& rules;
    size_t maxFlows, maxStreams;
    std::list<Flow*> activeFlows;
    std::thread thread;
    void release(Flow& flow) {
        if (flow.activePosition) {
            activeFlows.erase(*flow.activePosition);
            flow.activePosition.reset();
        }
        for (auto& stream : flow.streams) stream.reset();
        flow.inspectionDone = true;
    }
    void touch(Flow& flow) {
        if (flow.activePosition) {
            activeFlows.splice(activeFlows.begin(), activeFlows, *flow.activePosition);
            return;
        }
        if (activeFlows.size() >= maxStreams) {
            release(*activeFlows.back());
            ++inspectionLimited;
        }
        activeFlows.push_front(&flow);
        flow.activePosition = activeFlows.begin();
    }
public:
    Queue<Job> queue;
    std::unordered_map<std::string, Flow> flows;
    uint64_t processed = 0, inspectionLimited = 0;
    std::string error;
    Worker(const FilterRules& r, size_t count) : rules(r), maxFlows(200000 / count + 1), maxStreams(std::max(size_t(2), size_t(256) / count)) {}
    ~Worker() { finish(); }
    void start() { thread = std::thread([this] {
        while (auto job = queue.pop()) {
            ++processed;
            if (!error.empty()) continue;
            try { inspect(*job); } catch (const std::exception& e) { error = e.what(); }
        }
        for (auto& item : flows) for (auto& stream : item.second.streams) stream.reset();
    }); }
    void finish() { queue.close(); if (thread.joinable()) thread.join(); }
    void inspect(Job& job) {
        const auto& p = job.parsed;
        if (job.key.empty() || (baseApp(p) == AppType::DNS && !p.is_fragment)) return;
        auto found = flows.find(job.key);
        if (found == flows.end()) {
            if (flows.size() >= maxFlows) throw std::runtime_error("Flow limit reached; split the capture before analysis.");
            found = flows.emplace(job.key, Flow{}).first;
        }
        auto& flow = found->second;
        if (flow.base == AppType::UNKNOWN) flow.base = baseApp(p);
        if (flow.app == AppType::UNKNOWN) flow.app = flow.base;
        auto networkReason = rules.networkReason(p.src_ip, p.dest_ip, p.protocol, p.has_arp, p.src_port, p.dest_port, p.has_tcp || p.has_udp);
        if (!networkReason.empty()) flow.blockedReason = networkReason;
        if (!p.has_tcp || p.is_fragment || p.parse_status != ParseStatus::Ok || flow.inspectionDone) return;
        const unsigned direction = (p.src_ip + ":" + std::to_string(p.src_port)) >
            (p.dest_ip + ":" + std::to_string(p.dest_port)) ? 1 : 0;
        if (p.tcp_flags & 0x02) { flow.synSeen[direction] = true; flow.initialSeq[direction] = p.seq_number + 1; }
        if (job.payload.empty()) {
            if (p.tcp_flags & TCPFlags::RST) release(flow);
            return;
        }
        touch(flow);
        auto& stream = flow.streams[direction];
        if (!stream) {
            stream = std::make_unique<Stream>();
            if (flow.synSeen[direction]) { stream->initialized = true; stream->next = flow.initialSeq[direction]; }
        }
        stream->append(p.seq_number + ((p.tcp_flags & 0x02) ? 1 : 0), job.payload);
        auto host = SNIExtractor::extract(stream->bytes.data(), stream->bytes.size());
        bool http = false;
        if (!host) { host = HTTPHostExtractor::extract(stream->bytes.data(), stream->bytes.size()); http = bool(host); }
        if (host) {
            flow.domain = *host; flow.app = sniToAppType(*host);
            if (http && flow.app == AppType::HTTPS) flow.app = AppType::HTTP;
            if (flow.base == AppType::UNKNOWN) flow.base = http ? AppType::HTTP : AppType::TLS;
            if (rules.matchDomain(*host)) flow.blockedReason = "Domain";
            flow.inspectionDone = true;
        } else if (stream->exhausted) { ++inspectionLimited; flow.inspectionDone = true; }
        // Once a complete handshake/request is classified, release the bounded stream buffers.
        if (flow.inspectionDone || (p.tcp_flags & TCPFlags::RST)) release(flow);
    }
};

struct Stats {
    uint64_t packets = 0, bytes = 0, forwarded = 0, dropped = 0, tcp = 0, udp = 0, icmp = 0, icmpv6 = 0, arp = 0, ipv6 = 0;
    uint64_t malformed = 0, truncated = 0, unsupported = 0, fragments = 0;
    std::map<AppType, uint64_t> apps;
    std::map<std::string, AppType> domains;
    std::map<std::string, uint64_t> reasons;
};
class Engine {
    const FilterRules& rules;
    unsigned lbs, fps;
    std::vector<std::unique_ptr<Worker>> workers;
    std::vector<uint64_t> dispatched;
    FragmentIndex fragments;
    size_t workerFor(const std::string& key) const { return std::hash<std::string>{}(key) % workers.size(); }
public:
    Engine(const FilterRules& r, unsigned l, unsigned f) : rules(r), lbs(l), fps(f), dispatched(l) {
        for (unsigned i = 0; i < l * f; ++i) workers.push_back(std::make_unique<Worker>(rules, l * f));
    }
    bool process(const std::string& input, const std::string& output) {
        PcapReader reader;
        if (!reader.open(input)) throw std::runtime_error(reader.errorMessage());
        for (auto& worker : workers) worker->start();
        std::string firstPassError;
        try {
            std::cout << "[Reader] Classifying flows and visible hostnames...\n" << std::flush;
            Resolver resolver;
            RawPacket raw;
            while (reader.readNextPacket(raw)) {
                ParsedPacket p; PacketParser::parse(raw, p);
                auto key = resolver.key(raw, p);
                if (p.is_fragment) fragments.track(raw, p, key);
                Job job; job.key = key; job.parsed = p; job.parsed.payload_data = nullptr;
                if (p.has_tcp && !p.is_fragment && p.parse_status == ParseStatus::Ok && p.payload_data)
                    job.payload.assign(p.payload_data, p.payload_data + std::min(p.payload_length, size_t(65536)));
                auto index = workerFor(key.empty() ? std::to_string(raw.link_type) : key);
                ++dispatched[index / fps];
                workers[index]->queue.push(std::move(job));
            }
            if (reader.hasError()) firstPassError = reader.errorMessage();
        } catch (const std::exception& e) { firstPassError = e.what(); }
        for (auto& worker : workers) worker->finish();
        if (!firstPassError.empty()) throw std::runtime_error(firstPassError);
        for (auto& worker : workers) if (!worker->error.empty()) throw std::runtime_error(worker->error);
        reader.close();
        if (!reader.open(input)) throw std::runtime_error(reader.errorMessage());
        PcapWriter writer;
        if (!writer.open(output, reader)) throw std::runtime_error(writer.errorMessage());
        std::cout << "[Writer] Applying rules in original capture order...\n" << std::flush;
        Stats stats; Resolver resolver; RawPacket raw;
        size_t fragmentOrdinal = 0;
        while (reader.readNextPacket(raw)) {
            ParsedPacket p; PacketParser::parse(raw, p);
            ++stats.packets; stats.bytes += raw.data.size();
            if (p.has_ip && p.protocol == 6) ++stats.tcp;
            if (p.has_ip && p.protocol == 17) ++stats.udp;
            if (p.has_ip && p.protocol == 1) ++stats.icmp;
            if (p.has_ip && p.protocol == 58) ++stats.icmpv6;
            if (p.has_arp) ++stats.arp;
            if (p.ip_version == 6) ++stats.ipv6;
            if (p.is_fragment) ++stats.fragments;
            if (p.parse_status == ParseStatus::Malformed) ++stats.malformed;
            if (p.parse_status == ParseStatus::Truncated) ++stats.truncated;
            if (p.parse_status == ParseStatus::Unsupported) ++stats.unsupported;
            auto key = resolver.key(raw, p);
            if (p.is_fragment) key = fragments.flowAt(fragmentOrdinal++);
            auto reason = rules.networkReason(p.src_ip, p.dest_ip, p.protocol, p.has_arp, p.src_port, p.dest_port, p.has_tcp || p.has_udp);
            auto app = baseApp(p);
            std::string domain;
            if (!key.empty()) {
                auto& flows = workers[workerFor(key)]->flows;
                auto found = flows.find(key);
                if (found != flows.end()) {
                    app = found->second.app; domain = found->second.domain;
                    if (reason.empty()) reason = found->second.blockedReason;
                    if (reason.empty() && rules.matchApp(found->second.base)) reason = "Application";
                }
            }
            if (auto query = dnsDomain(p)) { domain = *query; app = AppType::DNS; }
            if (reason.empty() && rules.matchApp(app)) reason = "Application";
            if (reason.empty() && !domain.empty() && rules.matchDomain(domain)) reason = "Domain";
            ++stats.apps[app];
            if (!domain.empty()) stats.domains[domain] = app;
            if (!reason.empty()) { ++stats.dropped; ++stats.reasons[reason]; }
            else {
                if (!writer.write(raw)) throw std::runtime_error(writer.errorMessage());
                ++stats.forwarded;
            }
        }
        if (reader.hasError()) throw std::runtime_error(reader.errorMessage());
        if (!writer.close()) throw std::runtime_error(writer.errorMessage());
        report(stats);
        return true;
    }
    void report(const Stats& s) {
        std::cout << "\nPROCESSING REPORT\n";
        std::cout << "Total Packets : " << s.packets << "\nTotal Bytes   : " << s.bytes
            << "\nTCP Packets   : " << s.tcp << "\nUDP Packets   : " << s.udp
            << "\nICMP Packets  : " << s.icmp << "\nICMPv6 Packets: " << s.icmpv6
            << "\nARP Packets   : " << s.arp << "\nIPv6 Packets  : " << s.ipv6
            << "\nFragments     : " << s.fragments << "\nMalformed     : " << s.malformed
            << "\nTruncated     : " << s.truncated << "\nUnsupported   : " << s.unsupported
            << "\nForwarded     : " << s.forwarded << "\nDropped       : " << s.dropped << "\n";
        uint64_t limited = 0; for (auto& worker : workers) limited += worker->inspectionLimited;
        std::cout << "Inspection limited: " << limited << "\nTHREAD STATISTICS\n";
        for (size_t i = 0; i < dispatched.size(); ++i) std::cout << "LB" << i << " dispatched : " << dispatched[i] << "\n";
        for (size_t i = 0; i < workers.size(); ++i) std::cout << "FP" << i << " processed  : " << workers[i]->processed << "\n";
        std::cout << "APPLICATION BREAKDOWN\n";
        for (const auto& item : s.apps) std::cout << std::left << std::setw(15) << appTypeToString(item.first)
            << "  " << std::right << item.second << "  " << std::fixed << std::setprecision(1)
            << (s.packets ? 100.0 * item.second / s.packets : 0) << "%\n";
        std::cout << "[Detected Domains/SNIs]\n";
        for (const auto& item : s.domains) std::cout << "  - " << item.first << " -> " << appTypeToString(item.second) << "\n";
        std::cout << "[Blocking Reasons]\n";
        for (const auto& item : s.reasons) std::cout << item.first << ": " << item.second << "\n";
    }
};
int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "DPI Engine: input.pcap[ng] output.pcap[ng] [options]\n"
            << "--block-ip <IPv4|IPv6|CIDR>  --block-domain <domain|*.domain>\n"
            << "--block-app <name>  --block-port <[tcp:|udp:]port[-port]>\n"
            << "--block-protocol <tcp|udp|icmp|icmpv6|arp>\n"
            << "--lbs <1-16 dispatch groups>  --fps <1-16 workers per group>\n"
            << "Filters saved captures. Live firewall enforcement is a separate explicit control in the web app.\n";
        return argc == 2 && std::string(argv[1]) == "--help" ? 0 : 1;
    }
    std::string output = argv[2];
    std::string staging;
    try {
        if (std::filesystem::weakly_canonical(argv[1]) == std::filesystem::weakly_canonical(output))
            throw std::invalid_argument("Input and output must be different files.");
        if (std::filesystem::exists(output)) throw std::invalid_argument("Output already exists; choose a new filename.");
        FilterRules rules; unsigned lbs = 2, fps = 2;
        for (int i = 3; i < argc; ++i) {
            const std::string arg = argv[i];
            if (i + 1 >= argc) throw std::invalid_argument("Missing value for " + arg);
            const std::string value = argv[++i];
            if (arg == "--block-ip") rules.addIP(value);
            else if (arg == "--block-app") rules.addApp(value);
            else if (arg == "--block-domain") rules.addDomain(value);
            else if (arg == "--block-port") rules.addPort(value);
            else if (arg == "--block-protocol") rules.addProtocol(value);
            else if (arg == "--lbs") lbs = number(value, 16);
            else if (arg == "--fps") fps = number(value, 16);
            else throw std::invalid_argument("Unknown option: " + arg);
        }
        if (!lbs || !fps) throw std::invalid_argument("Thread counts must be between 1 and 16.");
        std::cout << "DPI ENGINE v3.0 — complete capture filtering\n";
        staging = output + ".partial-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        Engine engine(rules, lbs, fps); engine.process(argv[1], staging);
        std::filesystem::rename(staging, output);
        std::cout << "Output written to: " << output << "\n"; return 0;
    } catch (const std::exception& e) {
        if (!staging.empty()) { std::error_code ignored; std::filesystem::remove(staging, ignored); }
        std::cerr << "Analysis failed: " << e.what() << "\n";
        return 1;
    }
}
