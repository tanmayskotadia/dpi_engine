#ifndef FILTER_RULES_H
#define FILTER_RULES_H

#include <array>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>
#include "types.h"

namespace DPI {
inline std::string lowerText(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return std::tolower(c); });
    return value;
}
inline std::string normalizeDomain(std::string value) {
    value = lowerText(value);
    if (!value.empty() && value.back() == '.') value.pop_back();
    return value;
}
inline bool domainMatches(const std::string& host, const std::string& rule) {
    const bool wildcard = rule.compare(0, 2, "*.") == 0;
    const std::string base = wildcard ? rule.substr(2) : rule;
    return (!wildcard && host == base) || (host.size() > base.size() &&
        host.compare(host.size() - base.size(), base.size(), base) == 0 && host[host.size() - base.size() - 1] == '.');
}
inline bool validDomain(const std::string& value) {
    if (value.empty() || value.size() > 253) return false;
    size_t start = 0;
    while (start < value.size()) {
        auto end = value.find('.', start);
        if (end == std::string::npos) end = value.size();
        if (end == start || end - start > 63 || value[start] == '-' || value[end - 1] == '-') return false;
        for (size_t i = start; i < end; ++i) if (!(std::isalnum(static_cast<unsigned char>(value[i])) || value[i] == '-')) return false;
        start = end + 1;
    }
    return value.back() != '.';
}
inline unsigned number(const std::string& text, unsigned maximum) {
    if (text.empty() || text.size() > 10) throw std::invalid_argument("Invalid number: " + text);
    unsigned long long value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') throw std::invalid_argument("Invalid number: " + text);
        value = value * 10 + (c - '0');
        if (value > maximum) throw std::invalid_argument("Number out of range: " + text);
    }
    return static_cast<unsigned>(value);
}
struct Address {
    std::array<uint8_t, 16> bytes{};
    unsigned bits = 0;
};
inline Address parseAddress(const std::string& text) {
    Address result;
    if (text.find(':') == std::string::npos) {
        size_t start = 0;
        for (unsigned i = 0; i < 4; ++i) {
            const auto end = text.find('.', start);
            if ((i < 3) != (end != std::string::npos)) throw std::invalid_argument("Invalid IPv4 address");
            auto part = text.substr(start, end == std::string::npos ? end : end - start);
            if (part.size() > 1 && part[0] == '0') throw std::invalid_argument("Invalid IPv4 address");
            result.bytes[i] = static_cast<uint8_t>(number(part, 255));
            start = end + 1;
        }
        result.bits = 32;
        return result;
    }
    const auto compressed = text.find("::");
    if (text.find('.') != std::string::npos && compressed != std::string::npos && text.find('.') < compressed)
        throw std::invalid_argument("Embedded IPv4 must be the final IPv6 address component");
    if (compressed != std::string::npos && text.find("::", compressed + 2) != std::string::npos) throw std::invalid_argument("Invalid IPv6 address");
    auto groups = [](const std::string& part) {
        std::vector<uint16_t> values;
        if (part.empty()) return values;
        size_t pos = 0;
        while (pos < part.size()) {
            auto end = part.find(':', pos);
            auto group = part.substr(pos, end == std::string::npos ? end : end - pos);
            if (group.find('.') != std::string::npos) {
                if (end != std::string::npos) throw std::invalid_argument("Invalid IPv6 address");
                auto v4 = parseAddress(group);
                values.push_back((v4.bytes[0] << 8) | v4.bytes[1]);
                values.push_back((v4.bytes[2] << 8) | v4.bytes[3]);
            } else {
                if (group.empty() || group.size() > 4) throw std::invalid_argument("Invalid IPv6 address");
                unsigned value = 0;
                for (unsigned char c : group) {
                    if (!std::isxdigit(c)) throw std::invalid_argument("Invalid IPv6 address");
                    value = value * 16 + (std::isdigit(c) ? c - '0' : std::tolower(c) - 'a' + 10);
                }
                values.push_back(static_cast<uint16_t>(value));
            }
            if (end == std::string::npos) break;
            pos = end + 1;
            if (pos == part.size()) throw std::invalid_argument("Invalid IPv6 address");
        }
        return values;
    };
    auto left = groups(text.substr(0, compressed));
    auto right = compressed == std::string::npos ? std::vector<uint16_t>{} : groups(text.substr(compressed + 2));
    if ((compressed == std::string::npos && left.size() != 8) || (compressed != std::string::npos && left.size() + right.size() >= 8)) throw std::invalid_argument("Invalid IPv6 address");
    for (size_t i = 0; i < left.size(); ++i) { result.bytes[i * 2] = left[i] >> 8; result.bytes[i * 2 + 1] = left[i] & 255; }
    for (size_t i = 0; i < right.size(); ++i) { auto offset = (8 - right.size() + i) * 2; result.bytes[offset] = right[i] >> 8; result.bytes[offset + 1] = right[i] & 255; }
    result.bits = 128;
    return result;
}
struct NetworkRule {
    Address address;
    unsigned prefix;
    bool matches(const std::string& value) const {
        if (value.empty()) return false;
        try {
            auto candidate = parseAddress(value);
            if (candidate.bits != address.bits) return false;
            for (unsigned bit = 0; bit < prefix; ++bit) if (((candidate.bytes[bit / 8] ^ address.bytes[bit / 8]) & (128 >> (bit % 8))) != 0) return false;
            return true;
        } catch (const std::invalid_argument&) { return false; }
    }
};
struct PortRule { unsigned first, last; uint8_t protocol; };
class FilterRules {
public:
    std::vector<NetworkRule> networks;
    std::vector<PortRule> ports;
    std::vector<std::string> domains, protocols;
    std::vector<AppType> apps;
    void addIP(const std::string& value) {
        auto slash = value.find('/');
        auto address = parseAddress(value.substr(0, slash));
        networks.push_back({address, slash == std::string::npos ? address.bits : number(value.substr(slash + 1), address.bits)});
    }
    void addPort(std::string value) {
        uint8_t protocol = 0;
        auto colon = value.find(':');
        if (colon != std::string::npos) {
            auto name = lowerText(value.substr(0, colon));
            if (name != "tcp" && name != "udp") throw std::invalid_argument("Port protocol must be tcp or udp");
            protocol = name == "tcp" ? 6 : 17;
            value = value.substr(colon + 1);
        }
        auto dash = value.find('-');
        unsigned first = number(value.substr(0, dash), 65535);
        unsigned last = dash == std::string::npos ? first : number(value.substr(dash + 1), 65535);
        if (!first || last < first) throw std::invalid_argument("Invalid port range");
        ports.push_back({first, last, protocol});
    }
    void addDomain(std::string value) {
        value = normalizeDomain(value);
        if (!validDomain(value.compare(0, 2, "*.") == 0 ? value.substr(2) : value)) throw std::invalid_argument("Invalid domain rule");
        domains.push_back(value);
    }
    void addProtocol(std::string value) {
        value = lowerText(value);
        if (value != "tcp" && value != "udp" && value != "icmp" && value != "icmpv6" && value != "arp") throw std::invalid_argument("Unknown protocol: " + value);
        protocols.push_back(value);
    }
    void addApp(const std::string& value) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); ++i) {
            auto app = static_cast<AppType>(i);
            if (lowerText(appTypeToString(app)) == lowerText(value) || (app == AppType::TWITTER && lowerText(value) == "twitter")) { apps.push_back(app); return; }
        }
        throw std::invalid_argument("Unknown application: " + value);
    }
    bool matchDomain(const std::string& host) const {
        auto normalized = normalizeDomain(host);
        for (const auto& rule : domains) if (domainMatches(normalized, rule)) return true;
        return false;
    }
    bool matchApp(AppType app) const { return std::find(apps.begin(), apps.end(), app) != apps.end(); }
    std::string networkReason(const std::string& src, const std::string& dst, uint8_t protocol, bool arp, unsigned srcPort, unsigned dstPort, bool hasPorts) const {
        for (const auto& rule : networks) if (rule.matches(src) || rule.matches(dst)) return "IP/network";
        std::string name = arp ? "arp" : protocol == 6 ? "tcp" : protocol == 17 ? "udp" : protocol == 1 ? "icmp" : protocol == 58 ? "icmpv6" : "";
        if (!name.empty() && std::find(protocols.begin(), protocols.end(), name) != protocols.end()) return "Protocol";
        if (hasPorts) for (const auto& rule : ports) if ((!rule.protocol || rule.protocol == protocol) &&
            ((srcPort >= rule.first && srcPort <= rule.last) || (dstPort >= rule.first && dstPort <= rule.last))) return "Port";
        return {};
    }
};
}
#endif
