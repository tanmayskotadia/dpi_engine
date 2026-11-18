#include "packet_parser.h"
#include <algorithm>
#include <functional>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

using namespace PacketAnalyzer;
using Bytes = std::vector<uint8_t>;

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void set16(Bytes& bytes, size_t offset, uint16_t value) {
    bytes.at(offset) = static_cast<uint8_t>(value >> 8);
    bytes.at(offset + 1) = static_cast<uint8_t>(value);
}
void set32(Bytes& bytes, size_t offset, uint32_t value) {
    set16(bytes, offset, static_cast<uint16_t>(value >> 16));
    set16(bytes, offset + 2, static_cast<uint16_t>(value));
}
void append(Bytes& bytes, const Bytes& tail) { bytes.insert(bytes.end(), tail.begin(), tail.end()); }
Bytes tcp(const Bytes& payload = {}, unsigned words = 5) {
    Bytes bytes(words * 4, 0);
    set16(bytes, 0, 40000); set16(bytes, 2, 443);
    set32(bytes, 4, 0x01020304); set32(bytes, 8, 0x05060708);
    bytes[12] = static_cast<uint8_t>(words << 4); bytes[13] = 0x18;
    append(bytes, payload);
    return bytes;
}
Bytes udp(const Bytes& payload = {}) {
    Bytes bytes(8, 0);
    set16(bytes, 0, 53000); set16(bytes, 2, 53);
    set16(bytes, 4, static_cast<uint16_t>(8 + payload.size()));
    append(bytes, payload);
    return bytes;
}
Bytes ipv4(uint8_t protocol, const Bytes& payload, unsigned words = 5) {
    Bytes bytes(words * 4, 0);
    bytes[0] = static_cast<uint8_t>(0x40 | words);
    set16(bytes, 2, static_cast<uint16_t>(bytes.size() + payload.size()));
    set16(bytes, 4, 0x1234); bytes[8] = 64; bytes[9] = protocol;
    const Bytes source{192, 0, 2, 1}, destination{198, 51, 100, 2};
    std::copy(source.begin(), source.end(), bytes.begin() + 12);
    std::copy(destination.begin(), destination.end(), bytes.begin() + 16);
    append(bytes, payload);
    return bytes;
}
Bytes ipv6(uint8_t next, const Bytes& payload) {
    Bytes bytes(40, 0);
    bytes[0] = 0x60; bytes[6] = next; bytes[7] = 64;
    set16(bytes, 4, static_cast<uint16_t>(payload.size()));
    set16(bytes, 8, 0x2001); set16(bytes, 10, 0x0db8); bytes[23] = 1;
    set16(bytes, 24, 0x2001); set16(bytes, 26, 0x0db8); bytes[39] = 2;
    append(bytes, payload);
    return bytes;
}
Bytes ethernet(uint16_t type, const Bytes& payload) {
    Bytes bytes(14, 0);
    for (size_t i = 0; i < 12; ++i) bytes[i] = static_cast<uint8_t>(i);
    set16(bytes, 12, type);
    append(bytes, payload);
    return bytes;
}
RawPacket raw(Bytes bytes, uint32_t link = 1) {
    RawPacket packet;
    packet.data = std::move(bytes);
    packet.link_type = link;
    packet.header.incl_len = packet.header.orig_len = static_cast<uint32_t>(packet.data.size());
    return packet;
}
ParsedPacket parsed(const RawPacket& packet) {
    ParsedPacket result;
    require(PacketParser::parse(packet, result), result.parse_error.c_str());
    return result;
}
void safeView(const RawPacket& packet, const ParsedPacket& result) {
    require(result.packet_end <= packet.data.size(), "Network bound exceeds capture");
    require(result.payload_offset <= packet.data.size(), "Payload offset exceeds capture");
    require(result.payload_length <= packet.data.size() - result.payload_offset, "Payload length exceeds capture");
    require(!result.has_tcp || !result.has_udp, "Conflicting transport flags");
    if (result.fragment_offset) require(!result.has_tcp && !result.has_udp && !result.has_icmp, "Later fragment was parsed as transport");
    if (result.payload_length) require(result.payload_data == packet.data.data() + result.payload_offset, "Payload pointer does not match offset");
    else require(result.payload_data == nullptr, "Empty payload has a non-null pointer");
}
void malformed(RawPacket packet, ParseStatus expected) {
    ParsedPacket result;
    require(!PacketParser::parse(packet, result), "Invalid packet accepted");
    require(result.parse_status == expected, "Wrong parse error category");
    require(!result.parse_error.empty(), "Missing per-packet diagnostic");
    safeView(packet, result);
}
} // namespace

int main() {
    unsigned passed = 0, failed = 0;
    const auto run = [&](const char* name, const std::function<void()>& test) {
        try { test(); ++passed; std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& error) { ++failed; std::cerr << "FAIL " << name << ": " << error.what() << '\n'; }
    };

    run("IPv4 TCP options and Ethernet padding", [] {
        auto packet = raw(ethernet(0x0800, ipv4(6, tcp({1, 2, 3}, 6), 6)));
        packet.data.resize(100, 0xaa);
        packet.header.incl_len = packet.header.orig_len = 100;
        auto result = parsed(packet);
        require(result.src_ip == "192.0.2.1" && result.dest_ip == "198.51.100.2", "IPv4 addresses incorrect");
        require(result.has_tcp && result.src_port == 40000 && result.dest_port == 443, "TCP ports incorrect");
        require(result.seq_number == 0x01020304 && result.ack_number == 0x05060708, "Unaligned TCP integer reads incorrect");
        require(result.ip_offset == 14 && result.transport_offset == 38 && result.payload_offset == 62, "Option offsets incorrect");
        require(result.payload_length == 3 && result.payload_data[2] == 3, "Ethernet padding included as payload");
        safeView(packet, result);
    });
    run("UDP length excludes bytes beyond datagram", [] {
        auto body = udp({7, 8}); append(body, {0xaa, 0xbb, 0xcc});
        auto packet = raw(ethernet(0x0800, ipv4(17, body)));
        auto result = parsed(packet);
        require(result.has_udp && result.src_port == 53000 && result.dest_port == 53, "UDP ports incorrect");
        require(result.payload_length == 2 && result.payload_data[1] == 8, "UDP length was not respected");
    });
    run("VLAN and QinQ preserve ordered VLAN identifiers", [] {
        Bytes tags(8, 0); set16(tags, 0, 0xa064); set16(tags, 2, 0x8100);
        set16(tags, 4, 200); set16(tags, 6, 0x0800); append(tags, ipv4(17, udp({1})));
        auto packet = raw(ethernet(0x88a8, tags));
        auto result = parsed(packet);
        require(result.vlan_count == 2 && result.vlan_ids == std::vector<uint16_t>({100, 200}), "QinQ IDs incorrect");
        require(result.ip_offset == 22 && result.payload_offset == 50 && result.payload_length == 1, "QinQ offsets incorrect");
        auto truncated = raw(ethernet(0x8100, {0, 1, 8}));
        malformed(truncated, ParseStatus::Truncated);
    });
    run("IPv6 UDP addresses and payload", [] {
        auto packet = raw(ethernet(0x86dd, ipv6(17, udp({1, 2, 3}))));
        auto result = parsed(packet);
        require(result.has_ip && result.ip_version == 6 && result.has_udp, "IPv6 UDP not recognized");
        require(result.src_ip == "2001:db8::1" && result.dest_ip == "2001:db8::2", "IPv6 address formatting incorrect");
        require(result.transport_offset == 54 && result.payload_offset == 62 && result.payload_length == 3, "IPv6 offsets incorrect");
    });
    run("IPv6 canonical address formatting", [] {
        Bytes address(16, 0);
        require(PacketParser::ipv6ToString(address.data()) == "::", "Unspecified IPv6 incorrect");
        address[15] = 1;
        require(PacketParser::ipv6ToString(address.data()) == "::1", "Loopback IPv6 incorrect");
        address.assign(16, 0); set16(address, 0, 0xabcd); set16(address, 6, 1); set16(address, 12, 2); set16(address, 14, 3);
        require(PacketParser::ipv6ToString(address.data()) == "abcd::1:0:0:2:3", "Longest first zero-run tie was not canonical");
        address.assign(16, 0); address[10] = address[11] = 0xff; address[12] = 192; address[14] = 2; address[15] = 1;
        require(PacketParser::ipv6ToString(address.data()) == "::ffff:192.0.2.1", "IPv4-mapped IPv6 incorrect");
    });
    run("IPv6 hop-by-hop routing destination and AH chain", [] {
        Bytes extensions(40, 0);
        extensions[0] = 43; extensions[8] = 60; extensions[16] = 51;
        extensions[24] = 6; extensions[25] = 2; // AH = (2 + 2) * 4.
        append(extensions, tcp({9}));
        auto packet = raw(ethernet(0x86dd, ipv6(0, extensions)));
        auto result = parsed(packet);
        require(result.protocol == 6 && result.has_tcp && result.transport_offset == 94, "Extension traversal incorrect");
        require(result.payload_offset == 114 && result.payload_length == 1, "Extension payload incorrect");
    });
    run("IPv6 ESP and no-next-header remain opaque", [] {
        auto esp = raw(ipv6(50, {1, 2, 3, 4}), 101);
        auto result = parsed(esp);
        require(!result.has_tcp && !result.has_udp && result.payload_length == 4, "ESP was misparsed");
        auto noNext = raw(ipv6(59, {1, 2, 3, 4}), 229);
        result = parsed(noNext);
        require(result.payload_length == 0 && result.payload_offset == noNext.data.size(), "No-next-header bytes exposed as payload");
    });
    run("IPv4 first and later fragments never invent transport", [] {
        auto datagram = udp(Bytes(24, 0x41));
        Bytes firstData(datagram.begin(), datagram.begin() + 16);
        auto firstIp = ipv4(17, firstData); set16(firstIp, 6, 0x2000);
        auto first = raw(ethernet(0x0800, firstIp));
        auto result = parsed(first);
        require(result.is_fragment && result.more_fragments && result.fragment_offset == 0 && result.fragment_id == 0x1234, "First fragment metadata incorrect");
        require(result.has_udp && result.payload_length == 8, "UDP first fragment length rejected");
        auto laterIp = ipv4(17, Bytes(datagram.begin() + 16, datagram.end())); set16(laterIp, 6, 2);
        auto later = raw(ethernet(0x0800, laterIp)); result = parsed(later);
        require(result.is_fragment && !result.more_fragments && result.fragment_offset == 16, "Later fragment offset incorrect");
        require(!result.has_udp && result.src_port == 0 && result.payload_length == 16, "Later fragment interpreted as UDP");
        auto shortIp = ipv4(6, Bytes(16, 0)); set16(shortIp, 6, 0x2000);
        result = parsed(raw(shortIp, 228));
        require(!result.has_tcp && result.payload_length == 16, "Split IPv4 TCP header misparsed");
    });
    run("IPv6 noninitial fragment does not traverse fragment bytes", [] {
        Bytes fragment(24, 0); fragment[0] = 60; set16(fragment, 2, 0x0019); set32(fragment, 4, 0xdeadbeef);
        fragment[8] = 6; // Bytes resemble a destination header but are not one.
        auto packet = raw(ipv6(44, fragment), 101);
        auto result = parsed(packet);
        require(result.has_fragment_header && result.is_fragment && result.fragment_offset == 24 && result.more_fragments, "IPv6 fragment metadata incorrect");
        require(result.fragment_id == 0xdeadbeef && result.protocol == 60 && !result.has_tcp && result.payload_offset == 48, "Noninitial extension bytes traversed");
    });
    run("IPv6 first and atomic fragment handling", [] {
        Bytes fragment(8, 0); fragment[0] = 17; set32(fragment, 4, 5); append(fragment, udp({1, 2}));
        auto result = parsed(raw(ipv6(44, fragment), 229));
        require(result.has_fragment_header && !result.is_fragment && result.has_udp, "Atomic fragment not decoded");
        set16(fragment, 2, 1); set16(fragment, 12, 32);
        result = parsed(raw(ipv6(44, fragment), 229));
        require(result.is_fragment && result.has_udp && result.payload_length == 2, "First IPv6 UDP fragment rejected");
        Bytes incomplete(16, 0); incomplete[0] = 6; set16(incomplete, 2, 1);
        malformed(raw(ipv6(44, incomplete), 229), ParseStatus::Malformed);
    });
    run("ARP endpoints and Ethernet padding", [] {
        Bytes arp(28, 0); set16(arp, 0, 1); set16(arp, 2, 0x0800);
        arp[4] = 6; arp[5] = 4; set16(arp, 6, 1);
        arp[14] = 192; arp[16] = 2; arp[17] = 1;
        arp[24] = 192; arp[26] = 2; arp[27] = 2;
        auto packet = raw(ethernet(0x0806, arp)); packet.data.resize(60, 0);
        auto result = parsed(packet);
        require(result.has_arp && !result.has_ip && result.arp_operation == 1, "ARP not recognized");
        require(result.src_ip == "192.0.2.1" && result.dest_ip == "192.0.2.2", "ARP endpoints incorrect");
        require(result.payload_length == 0 && result.packet_end == 42, "ARP padding included");
        arp.pop_back(); malformed(raw(ethernet(0x0806, arp)), ParseStatus::Truncated);
    });
    run("ICMP ICMPv6 and unknown IP protocols", [] {
        auto v4 = parsed(raw(ipv4(1, {8, 0, 0, 0, 0, 1, 0, 2}), 101));
        require(v4.has_icmp && v4.icmp_type == 8 && v4.icmp_code == 0 && !v4.has_tcp, "ICMP incorrect");
        auto v6 = parsed(raw(ipv6(58, {128, 0, 0, 0, 0, 1, 0, 2}), 229));
        require(v6.has_icmp && v6.icmp_type == 128, "ICMPv6 incorrect");
        auto other = parsed(raw(ipv4(99, {1, 2, 3}), 228));
        require(other.has_ip && other.protocol == 99 && !other.has_tcp && !other.has_udp && other.payload_length == 3, "Unknown protocol discarded");
    });
    run("Linux cooked v1 and v2", [] {
        Bytes sll(16, 0); set16(sll, 2, 1); set16(sll, 4, 6); set16(sll, 14, 0x0800);
        append(sll, ipv4(17, udp({4})));
        auto result = parsed(raw(sll, 113));
        require(result.has_udp && result.ip_offset == 16 && result.payload_offset == 44, "SLL offsets incorrect");
        Bytes sll2(20, 0); set16(sll2, 0, 0x86dd); set32(sll2, 4, 42); set16(sll2, 8, 1); sll2[11] = 6;
        append(sll2, ipv6(17, udp({5})));
        result = parsed(raw(sll2, 276));
        require(result.has_udp && result.ip_version == 6 && result.link_interface_index == 42 && result.payload_offset == 68, "SLL2 metadata incorrect");
        malformed(raw(Bytes(15), 113), ParseStatus::Truncated);
        malformed(raw(Bytes(19), 276), ParseStatus::Truncated);
    });
    run("NULL and LOOP honor capture byte order", [] {
        Bytes little{2, 0, 0, 0}; append(little, ipv4(17, udp()));
        auto packet = raw(little, 0); packet.source_little_endian = true;
        require(parsed(packet).has_udp, "Little-endian NULL failed");
        Bytes big{0, 0, 0, 2}; append(big, ipv4(17, udp()));
        packet = raw(big, 0); packet.source_little_endian = false;
        require(parsed(packet).has_udp, "Big-endian NULL failed");
        packet.link_type = 108; packet.source_little_endian = true;
        require(parsed(packet).has_udp, "LOOP must always read big-endian family");
        for (uint8_t family : {24, 28, 30}) {
            Bytes loop{0, 0, 0, family}; append(loop, ipv6(59, {}));
            require(parsed(raw(loop, 108)).ip_version == 6, "IPv6 loopback family not recognized");
        }
    });
    run("IP and transport malformed lengths report errors", [] {
        auto ip = ipv4(6, tcp()); ip[0] = 0x44;
        malformed(raw(ip, 101), ParseStatus::Malformed);
        ip = ipv4(6, tcp()); set16(ip, 2, 19);
        malformed(raw(ip, 228), ParseStatus::Malformed);
        ip = ipv4(6, tcp()); ip[32] = 0x40;
        malformed(raw(ip, 228), ParseStatus::Malformed);
        ip = ipv4(6, tcp()); ip[32] = 0xf0;
        malformed(raw(ip, 228), ParseStatus::Malformed);
        auto body = udp(); set16(body, 4, 7);
        malformed(raw(ipv4(17, body), 101), ParseStatus::Malformed);
        set16(body, 4, 20);
        malformed(raw(ipv6(17, body), 229), ParseStatus::Malformed);
        auto mismatch = ipv6(59, {}); mismatch[0] = 0x40;
        malformed(raw(mismatch, 229), ParseStatus::Malformed);
    });
    run("Truncated IPv6 preserves usable endpoints", [] {
        auto bytes = ipv6(17, udp(Bytes(16, 0x44)));
        auto packet = raw(bytes, 101); packet.data.resize(49); packet.header.incl_len = 49;
        ParsedPacket result;
        require(!PacketParser::parse(packet, result) && result.truncated && result.parse_status == ParseStatus::Truncated, "Truncated IPv6 accepted");
        require(result.has_ip && result.src_ip == "2001:db8::1", "Truncated IPv6 endpoints lost");
        safeView(packet, result);
        Bytes extension(16, 0); extension[0] = 17; extension[1] = 1;
        bytes = ipv6(0, extension); packet = raw(bytes, 229); packet.data.resize(48); packet.header.incl_len = 48;
        malformed(packet, ParseStatus::Truncated);
    });
    run("Invalid extension chains are bounded", [] {
        Bytes extension(8, 0); extension[0] = 17; extension[1] = 5;
        malformed(raw(ipv6(0, extension), 229), ParseStatus::Malformed);
        Bytes duplicate(16, 0); duplicate[0] = 44; duplicate[8] = 59;
        malformed(raw(ipv6(44, duplicate), 229), ParseStatus::Malformed);
        Bytes misplaced(16, 0); misplaced[0] = 0; misplaced[8] = 59;
        malformed(raw(ipv6(60, misplaced), 229), ParseStatus::Malformed);
        auto jumbo = ipv6(0, Bytes(8, 0)); set16(jumbo, 4, 0);
        malformed(raw(jumbo, 229), ParseStatus::Unsupported);
    });
    run("Parser resets metadata and exposes unsupported framing", [] {
        ParsedPacket result;
        auto valid = raw(ethernet(0x0800, ipv4(6, tcp({1}))));
        require(PacketParser::parse(valid, result) && result.has_tcp, "Setup failed");
        auto unknown = raw(Bytes(20, 0), 999);
        require(!PacketParser::parse(unknown, result) && result.unsupported && result.parse_status == ParseStatus::Unsupported, "Unsupported link not reported");
        require(!result.has_ip && !result.has_tcp && result.src_ip.empty() && result.payload_length == 0, "Metadata leaked between packets");
        malformed(raw(ethernet(0x88cc, Bytes(20))), ParseStatus::Unsupported);
    });
    run("Every truncated prefix keeps views inside captured bytes", [] {
        const std::vector<RawPacket> fixtures{
            raw(ethernet(0x0800, ipv4(6, tcp({1, 2, 3}, 6), 6))),
            raw(ethernet(0x86dd, ipv6(17, udp({1, 2, 3})))),
            raw(ipv6(58, {128, 0, 0, 0, 0, 0, 0, 0}), 229),
        };
        for (const auto& fixture : fixtures) {
            for (size_t size = 0; size < fixture.data.size(); ++size) {
                auto packet = fixture; packet.data.resize(size); packet.header.incl_len = static_cast<uint32_t>(size);
                ParsedPacket result;
                require(!PacketParser::parse(packet, result), "Truncated prefix accepted");
                require(!result.parse_error.empty(), "Truncated prefix has no diagnostic");
                safeView(packet, result);
            }
        }
    });
    run("Deterministic mutated frames preserve parser invariants", [] {
        std::mt19937 random(0x5afe);
        for (unsigned iteration = 0; iteration < 10000; ++iteration) {
            auto packet = iteration % 2
                ? raw(ethernet(0x0800, ipv4(6, tcp(Bytes(32, 0x55)))))
                : raw(ethernet(0x86dd, ipv6(17, udp(Bytes(32, 0xaa)))));
            for (unsigned change = 0; change < 5; ++change) packet.data[random() % packet.data.size()] = static_cast<uint8_t>(random());
            ParsedPacket result;
            const bool success = PacketParser::parse(packet, result);
            require(success == (result.parse_status == ParseStatus::Ok), "Return value and parse status disagree");
            if (!success) require(!result.parse_error.empty(), "Parse failure without diagnostic");
            safeView(packet, result);
        }
    });
    std::cout << passed << " passed, " << failed << " failed\n";
    return failed ? 1 : 0;
}
