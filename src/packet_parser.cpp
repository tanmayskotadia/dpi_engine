#include "packet_parser.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace PacketAnalyzer {
namespace {

// Byte reads are alignment-safe and independent of the reader's host byte order.
uint16_t read16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}
uint32_t read32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) | data[3];
}
uint32_t read32le(const uint8_t* data) {
    return (static_cast<uint32_t>(data[3]) << 24) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) | data[0];
}
bool available(size_t end, size_t offset, size_t count) {
    return offset <= end && count <= end - offset;
}
bool fail(ParsedPacket& parsed, ParseStatus status, const std::string& message) {
    parsed.parse_status = status;
    parsed.parse_error = message;
    parsed.truncated = parsed.truncated || status == ParseStatus::Truncated;
    parsed.unsupported = status == ParseStatus::Unsupported;
    return false;
}
bool shortTransport(ParsedPacket& parsed, const char* protocol) {
    return fail(parsed, parsed.truncated ? ParseStatus::Truncated : ParseStatus::Malformed,
                std::string(protocol) + " header exceeds the available IP payload");
}
std::string ipv4String(const uint8_t* ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
           std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}
bool vlanType(uint16_t type) {
    return type == 0x8100 || type == 0x88a8 || type == 0x9100 || type == 0x9200;
}
bool parseVlans(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    while (vlanType(parsed.ether_type)) {
        if (!available(len, offset, 4)) return fail(parsed, ParseStatus::Truncated, "Truncated VLAN header");
        if (parsed.vlan_ids.size() == 32) return fail(parsed, ParseStatus::Unsupported, "VLAN stack exceeds the supported depth");
        parsed.vlan_ids.push_back(read16(data + offset) & 0x0fff);
        parsed.vlan_count = static_cast<uint8_t>(parsed.vlan_ids.size());
        parsed.ether_type = read16(data + offset + 2);
        offset += 4;
    }
    return true;
}
uint16_t familyEtherType(uint32_t family) {
    if (family == 2) return EtherType::IPv4;
    if (family == 24 || family == 28 || family == 30) return EtherType::IPv6;
    return 0;
}
bool parseArp(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    if (!available(len, offset, 8)) return fail(parsed, ParseStatus::Truncated, "Truncated ARP header");
    const uint8_t* arp = data + offset;
    const size_t hardwareLength = arp[4];
    const size_t protocolLength = arp[5];
    if (!hardwareLength || !protocolLength) return fail(parsed, ParseStatus::Malformed, "ARP address lengths must be nonzero");
    const size_t arpLength = 8 + 2 * (hardwareLength + protocolLength);
    if (!available(len, offset, arpLength)) return fail(parsed, ParseStatus::Truncated, "Truncated ARP addresses");
    parsed.has_arp = true;
    parsed.arp_operation = read16(arp + 6);
    if (read16(arp + 2) == EtherType::IPv4 && protocolLength == 4) {
        parsed.src_ip = ipv4String(arp + 8 + hardwareLength);
        parsed.dest_ip = ipv4String(arp + 8 + 2 * hardwareLength + protocolLength);
    }
    offset += arpLength;
    parsed.packet_end = offset; // Ignore Ethernet minimum-frame padding.
    return true;
}

} // namespace

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parsed = ParsedPacket{};
    parsed.timestamp_sec = raw.header.ts_sec;
    parsed.timestamp_usec = raw.header.ts_usec;
    parsed.link_type = raw.link_type;
    const uint8_t* data = raw.data.data();
    const size_t len = raw.data.size();
    parsed.packet_end = len;
    size_t offset = 0;
    if (raw.header.orig_len > len) {
        fail(parsed, ParseStatus::Truncated, "Capture contains fewer bytes than the original frame");
    }

    switch (raw.link_type) {
        case 1: // LINKTYPE_ETHERNET
            if (!parseEthernet(data, len, parsed, offset)) return false;
            break;
        case 113: // LINKTYPE_LINUX_SLL: libpcap/pcap/sll.h, 16-byte v1 header.
            if (!available(len, 0, 16)) return fail(parsed, ParseStatus::Truncated, "Truncated Linux SLL header");
            if (read16(data + 2) == 1 && read16(data + 4) == 6) parsed.src_mac = macToString(data + 6);
            parsed.ether_type = read16(data + 14);
            offset = 16;
            if (!parseVlans(data, len, parsed, offset)) return false;
            break;
        case 276: // LINKTYPE_LINUX_SLL2: 20-byte v2 header.
            if (!available(len, 0, 20)) return fail(parsed, ParseStatus::Truncated, "Truncated Linux SLL2 header");
            parsed.ether_type = read16(data);
            parsed.link_interface_index = read32(data + 4);
            if (read16(data + 8) == 1 && data[11] == 6) parsed.src_mac = macToString(data + 12);
            offset = 20;
            if (!parseVlans(data, len, parsed, offset)) return false;
            break;
        case 101: // LINKTYPE_RAW
            if (!len) return fail(parsed, ParseStatus::Truncated, "Empty raw IP packet");
            if ((data[0] >> 4) == 4) parsed.ether_type = EtherType::IPv4;
            else if ((data[0] >> 4) == 6) parsed.ether_type = EtherType::IPv6;
            else return fail(parsed, ParseStatus::Malformed, "Raw IP packet has an invalid IP version");
            break;
        case 228: // LINKTYPE_IPV4
            parsed.ether_type = EtherType::IPv4;
            break;
        case 229: // LINKTYPE_IPV6
            parsed.ether_type = EtherType::IPv6;
            break;
        case 0: // LINKTYPE_NULL: family is in the capturing host's byte order.
        case 108: // LINKTYPE_LOOP: family is always in network byte order.
            if (!available(len, 0, 4)) return fail(parsed, ParseStatus::Truncated, "Truncated loopback header");
            parsed.ether_type = familyEtherType(raw.link_type == 0 && raw.source_little_endian ? read32le(data) : read32(data));
            if (!parsed.ether_type) return fail(parsed, ParseStatus::Unsupported, "Unsupported loopback address family");
            offset = 4;
            break;
        default:
            return fail(parsed, ParseStatus::Unsupported, "Unsupported capture link type " + std::to_string(raw.link_type));
    }

    if (parsed.ether_type == EtherType::ARP) {
        if (!parseArp(data, len, parsed, offset)) return false;
    } else if (parsed.ether_type == EtherType::IPv4 || parsed.ether_type == EtherType::IPv6) {
        parsed.ip_offset = offset;
        if (parsed.ether_type == EtherType::IPv4) {
            if (!parseIPv4(data, len, parsed, offset)) return false;
        } else if (!parseIPv6(data, len, parsed, offset)) return false;
        parsed.transport_offset = offset;

        // A later fragment's bytes begin in the middle of the original payload.
        // In IPv6 they may even begin in the middle of an extension header.
        if (parsed.fragment_offset == 0) {
            if (parsed.protocol == Protocol::TCP) {
                if (!parseTCP(data, parsed.packet_end, parsed, offset)) return false;
            } else if (parsed.protocol == Protocol::UDP) {
                if (!parseUDP(data, parsed.packet_end, parsed, offset)) return false;
            } else if (parsed.protocol == Protocol::ICMP || parsed.protocol == Protocol::ICMPv6) {
                if (!available(parsed.packet_end, offset, 4)) {
                    if (!parsed.more_fragments || parsed.ip_version != 4) return shortTransport(parsed, "ICMP");
                } else {
                    parsed.has_icmp = true;
                    parsed.icmp_type = data[offset];
                    parsed.icmp_code = data[offset + 1];
                    offset += 4;
                }
            } else if (parsed.ip_version == 6 && parsed.protocol == 59) {
                // RFC 8200: ignore bytes following No Next Header.
                offset = parsed.packet_end;
            }
            // ESP, GRE, IGMP, SCTP and other IP protocols remain opaque payloads.
        }
    } else {
        return fail(parsed, ParseStatus::Unsupported, "Unsupported network EtherType " + std::to_string(parsed.ether_type));
    }

    parsed.payload_offset = offset;
    parsed.payload_length = offset <= parsed.packet_end ? parsed.packet_end - offset : 0;
    parsed.payload_data = parsed.payload_length ? data + offset : nullptr;
    return parsed.parse_status == ParseStatus::Ok;
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    if (!available(len, 0, 14)) return fail(parsed, ParseStatus::Truncated, "Truncated Ethernet header");
    parsed.dest_mac = macToString(data);
    parsed.src_mac = macToString(data + 6);
    parsed.ether_type = read16(data + 12);
    offset = 14;
    return parseVlans(data, len, parsed, offset);
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    if (!available(len, offset, 20)) return fail(parsed, ParseStatus::Truncated, "Truncated IPv4 header");
    const uint8_t* ip = data + offset;
    if ((ip[0] >> 4) != 4) return fail(parsed, ParseStatus::Malformed, "IPv4 EtherType does not contain an IPv4 header");
    const size_t headerLength = (ip[0] & 0x0f) * 4;
    const size_t totalLength = read16(ip + 2);
    if (headerLength < 20) return fail(parsed, ParseStatus::Malformed, "IPv4 header length is less than 20 bytes");
    if (totalLength < headerLength) return fail(parsed, ParseStatus::Malformed, "IPv4 total length is smaller than its header");
    parsed.has_ip = true;
    parsed.ip_version = 4;
    parsed.ttl = ip[8];
    parsed.protocol = ip[9];
    parsed.src_ip = ipv4String(ip + 12);
    parsed.dest_ip = ipv4String(ip + 16);
    parsed.fragment_id = read16(ip + 4);
    const uint16_t fragment = read16(ip + 6);
    parsed.fragment_offset = static_cast<uint32_t>(fragment & 0x1fff) * 8;
    parsed.more_fragments = (fragment & 0x2000) != 0;
    parsed.is_fragment = parsed.fragment_offset != 0 || parsed.more_fragments;
    if (!available(len, offset, headerLength)) return fail(parsed, ParseStatus::Truncated, "Truncated IPv4 options");
    if (!available(len, offset, totalLength)) fail(parsed, ParseStatus::Truncated, "Captured IPv4 packet is shorter than its total length");
    parsed.packet_end = offset + std::min(totalLength, len - offset);
    offset += headerLength;
    parsed.fragment_data_offset = offset;
    return true;
}

bool PacketParser::parseIPv6(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    if (!available(len, offset, 40)) return fail(parsed, ParseStatus::Truncated, "Truncated IPv6 header");
    const uint8_t* ip = data + offset;
    if ((ip[0] >> 4) != 6) return fail(parsed, ParseStatus::Malformed, "IPv6 EtherType does not contain an IPv6 header");
    const size_t payloadLength = read16(ip + 4);
    parsed.has_ip = true;
    parsed.ip_version = 6;
    parsed.protocol = ip[6];
    parsed.ttl = ip[7];
    parsed.src_ip = ipv6ToString(ip + 8);
    parsed.dest_ip = ipv6ToString(ip + 24);
    offset += 40;
    // Never mistake a jumbo option or Ethernet padding for ordinary IP payload.
    if (payloadLength == 0 && parsed.protocol == 0) return fail(parsed, ParseStatus::Unsupported, "IPv6 jumbograms are not supported");
    if (!available(len, offset, payloadLength)) fail(parsed, ParseStatus::Truncated, "Captured IPv6 packet is shorter than its payload length");
    parsed.packet_end = offset + std::min(payloadLength, len - offset);

    // RFC 8200 extensions and RFC 4302 AH. ESP cannot be traversed without keys.
    size_t extensionCount = 0;
    while (parsed.protocol == 0 || parsed.protocol == 43 || parsed.protocol == 44 ||
           parsed.protocol == 51 || parsed.protocol == 60 || parsed.protocol == 135 ||
           parsed.protocol == 139 || parsed.protocol == 140) {
        if (++extensionCount > 64) return fail(parsed, ParseStatus::Unsupported, "IPv6 extension chain exceeds the supported depth");
        if (!available(parsed.packet_end, offset, 2)) return shortTransport(parsed, "IPv6 extension");
        const uint8_t next = data[offset];
        size_t extensionLength = 0;
        if (parsed.protocol == 44) {
            if (parsed.has_fragment_header) return fail(parsed, ParseStatus::Malformed, "Duplicate IPv6 fragment header");
            if (!available(parsed.packet_end, offset, 8)) return shortTransport(parsed, "IPv6 fragment");
            parsed.has_fragment_header = true;
            const uint16_t fragment = read16(data + offset + 2);
            parsed.fragment_offset = fragment & 0xfff8;
            parsed.more_fragments = (fragment & 1) != 0;
            parsed.fragment_id = read32(data + offset + 4);
            parsed.is_fragment = parsed.fragment_offset != 0 || parsed.more_fragments;
            offset += 8;
            parsed.fragment_data_offset = offset;
            parsed.protocol = next;
            if (parsed.fragment_offset != 0) return true;
            continue;
        }
        if (parsed.protocol == 0 && offset != parsed.ip_offset + 40) return fail(parsed, ParseStatus::Malformed, "IPv6 hop-by-hop header is not first");
        if (parsed.protocol == 51) {
            extensionLength = (static_cast<size_t>(data[offset + 1]) + 2) * 4;
            if (extensionLength < 12) return fail(parsed, ParseStatus::Malformed, "Invalid IPv6 authentication header length");
        } else {
            extensionLength = (static_cast<size_t>(data[offset + 1]) + 1) * 8;
        }
        if (!available(parsed.packet_end, offset, extensionLength)) return shortTransport(parsed, "IPv6 extension");
        offset += extensionLength;
        parsed.protocol = next;
    }
    return true;
}

bool PacketParser::parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    if (!available(len, offset, 20)) {
        // IPv4 permits a first fragment shorter than the complete TCP header.
        if (parsed.more_fragments && parsed.ip_version == 4) return true;
        return shortTransport(parsed, "TCP");
    }
    const uint8_t* tcp = data + offset;
    const size_t headerLength = (tcp[12] >> 4) * 4;
    if (headerLength < 20) return fail(parsed, ParseStatus::Malformed, "TCP data offset is smaller than the fixed header");
    if (!available(len, offset, headerLength)) {
        if (parsed.more_fragments && parsed.ip_version == 4) return true;
        return shortTransport(parsed, "TCP options");
    }
    parsed.src_port = read16(tcp);
    parsed.dest_port = read16(tcp + 2);
    parsed.seq_number = read32(tcp + 4);
    parsed.ack_number = read32(tcp + 8);
    parsed.tcp_flags = tcp[13];
    parsed.has_tcp = true;
    offset += headerLength;
    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset) {
    if (!available(len, offset, 8)) {
        if (parsed.more_fragments && parsed.ip_version == 4) return true;
        return shortTransport(parsed, "UDP");
    }
    const uint8_t* udp = data + offset;
    const size_t length = read16(udp + 4);
    if (length < 8) return fail(parsed, ParseStatus::Malformed, "UDP length is smaller than its header");
    if (!available(len, offset, length) && !parsed.more_fragments) return shortTransport(parsed, "UDP datagram");
    parsed.src_port = read16(udp);
    parsed.dest_port = read16(udp + 2);
    parsed.has_udp = true;
    parsed.packet_end = offset + std::min(length, len - offset);
    offset += 8;
    return true;
}

std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream text;
    text << std::hex << std::setfill('0');
    for (size_t index = 0; index < 6; ++index) {
        if (index) text << ':';
        text << std::setw(2) << static_cast<unsigned>(mac[index]);
    }
    return text.str();
}

std::string PacketParser::ipToString(uint32_t ip) {
    // This API accepts an address stored in network byte order, as before.
    uint8_t bytes[4];
    std::memcpy(bytes, &ip, sizeof(bytes));
    return ipv4String(bytes);
}

std::string PacketParser::ipv6ToString(const uint8_t* ip) {
    // RFC 5952: lowercase, no leading zeroes, longest zero run, first on ties.
    if (std::all_of(ip, ip + 10, [](uint8_t byte) { return byte == 0; }) && ip[10] == 0xff && ip[11] == 0xff) {
        return "::ffff:" + ipv4String(ip + 12);
    }
    std::array<uint16_t, 8> words{};
    for (size_t index = 0; index < words.size(); ++index) words[index] = read16(ip + index * 2);
    size_t bestStart = words.size();
    size_t bestLength = 0;
    for (size_t index = 0; index < words.size();) {
        if (words[index] != 0) { ++index; continue; }
        size_t end = index;
        while (end < words.size() && words[end] == 0) ++end;
        if (end - index > bestLength && end - index >= 2) {
            bestStart = index;
            bestLength = end - index;
        }
        index = end;
    }
    std::ostringstream text;
    text << std::hex;
    for (size_t index = 0; index < words.size();) {
        if (index == bestStart) {
            text << "::";
            index += bestLength;
        } else {
            if (index && index != bestStart + bestLength) text << ':';
            text << words[index++];
        }
    }
    return text.str();
}

std::string PacketParser::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case Protocol::ICMP: return "ICMP";
        case Protocol::IGMP: return "IGMP";
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        case Protocol::ICMPv6: return "ICMPv6";
        case 4: return "IPv4-in-IP";
        case 41: return "IPv6-in-IP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 59: return "No next header";
        case 89: return "OSPF";
        case 132: return "SCTP";
        default: return "IP protocol " + std::to_string(protocol);
    }
}

std::string PacketParser::tcpFlagsToString(uint8_t flags) {
    std::string result;
    if (flags & TCPFlags::SYN) result += "SYN ";
    if (flags & TCPFlags::ACK) result += "ACK ";
    if (flags & TCPFlags::FIN) result += "FIN ";
    if (flags & TCPFlags::RST) result += "RST ";
    if (flags & TCPFlags::PSH) result += "PSH ";
    if (flags & TCPFlags::URG) result += "URG ";
    if (flags & 0x40) result += "ECE ";
    if (flags & 0x80) result += "CWR ";
    if (!result.empty()) result.pop_back();
    return result.empty() ? "none" : result;
}

} // namespace PacketAnalyzer
