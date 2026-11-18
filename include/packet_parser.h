#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <array>
#include <vector>
#include "pcap_reader.h"

namespace PacketAnalyzer {

// Ethernet Header (14 bytes)
// This is the first layer - the "envelope" for the packet
struct EthernetHeader {
    std::array<uint8_t, 6> dest_mac;    // Destination MAC address
    std::array<uint8_t, 6> src_mac;     // Source MAC address
    uint16_t ether_type;                 // Type of payload (0x0800 = IPv4)
};

// IPv4 Header (20-60 bytes, usually 20)
struct IPv4Header {
    uint8_t  version_ihl;      // Version (4 bits) + Header Length (4 bits)
    uint8_t  tos;              // Type of Service
    uint16_t total_length;     // Total packet length
    uint16_t identification;   // Fragment identification
    uint16_t flags_fragment;   // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;              // Time To Live
    uint8_t  protocol;         // Protocol (6=TCP, 17=UDP, 1=ICMP)
    uint16_t checksum;         // Header checksum
    uint32_t src_ip;           // Source IP address
    uint32_t dest_ip;          // Destination IP address
    // Options may follow if header length > 5
};

// TCP Header (20-60 bytes, usually 20)
struct TCPHeader {
    uint16_t src_port;         // Source port
    uint16_t dest_port;        // Destination port
    uint32_t seq_number;       // Sequence number
    uint32_t ack_number;       // Acknowledgment number
    uint8_t  data_offset;      // Data offset (4 bits) + Reserved (4 bits)
    uint8_t  flags;            // TCP flags (SYN, ACK, FIN, etc.)
    uint16_t window;           // Window size
    uint16_t checksum;         // Checksum
    uint16_t urgent_pointer;   // Urgent pointer
};

// UDP Header (8 bytes - always fixed size)
struct UDPHeader {
    uint16_t src_port;         // Source port
    uint16_t dest_port;        // Destination port
    uint16_t length;           // Length of UDP header + data
    uint16_t checksum;         // Checksum
};

enum class ParseStatus { Ok, Truncated, Malformed, Unsupported };

// Parsed views refer to the captured bytes, never to reassembled traffic.
struct ParsedPacket {
    // Timestamps
    uint32_t timestamp_sec = 0;
    uint32_t timestamp_usec = 0;

    ParseStatus parse_status = ParseStatus::Ok;
    std::string parse_error;
    bool truncated = false;
    bool unsupported = false;
    uint32_t link_type = 1;
    uint32_t link_interface_index = 0; // Interface index carried by Linux SLL2.
    
    // Ethernet layer
    std::string src_mac;
    std::string dest_mac;
    uint16_t ether_type = 0;
    uint8_t vlan_count = 0;
    std::vector<uint16_t> vlan_ids; // Outer to inner, excluding priority bits.
    bool has_arp = false;
    uint16_t arp_operation = 0;
    
    // IP layer (if present)
    bool has_ip = false;
    uint8_t ip_version = 0;
    std::string src_ip;
    std::string dest_ip;
    uint8_t protocol = 0;      // Final next-header value, after IPv6 extensions.
    uint8_t ttl = 0;
    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t packet_end = 0;     // Exclusive captured bound, excludes link padding.
    bool is_fragment = false;
    bool has_fragment_header = false;
    bool more_fragments = false;
    uint32_t fragment_offset = 0; // Byte offset, not the on-wire 8-byte units.
    uint32_t fragment_id = 0;
    size_t fragment_data_offset = 0; // Captured start of this fragment's IP payload.
    
    // Transport layer (if present)
    bool has_tcp = false;
    bool has_udp = false;
    bool has_icmp = false;
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    
    // TCP-specific
    uint8_t tcp_flags = 0;
    uint32_t seq_number = 0;
    uint32_t ack_number = 0;
    
    // Payload
    size_t payload_offset = 0;
    size_t payload_length = 0;
    const uint8_t* payload_data = nullptr;  // Points into original packet
};

// Class to parse raw packets
class PacketParser {
public:
    // False reports a malformed, truncated or unsupported frame. Discovered
    // endpoints and parse_error remain available; callers may preserve the frame.
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);
    
    // Helper functions to convert to human-readable strings
    static std::string macToString(const uint8_t* mac);
    static std::string ipToString(uint32_t ip);
    static std::string ipv6ToString(const uint8_t* ip);
    static std::string protocolToString(uint8_t protocol);
    static std::string tcpFlagsToString(uint8_t flags);
    
private:
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseIPv6(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
};

// TCP Flag constants
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

// Protocol numbers
namespace Protocol {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t IGMP = 2;
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
    constexpr uint8_t ICMPv6 = 58;
}

// EtherType values
namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t IPv6 = 0x86DD;
    constexpr uint16_t ARP  = 0x0806;
}

} // namespace PacketAnalyzer

#endif // PACKET_PARSER_H
