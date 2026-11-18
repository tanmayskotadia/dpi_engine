#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <memory>
#include <unordered_map>

namespace PacketAnalyzer {

// PCAP Global Header (24 bytes)
// This is at the very beginning of every .pcap file
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 (or swapped for big-endian)
    uint16_t version_major;  // Usually 2
    uint16_t version_minor;  // Usually 4
    int32_t  thiszone;       // GMT offset (usually 0)
    uint32_t sigfigs;        // Accuracy of timestamps (usually 0)
    uint32_t snaplen;        // Max length of captured packets
    uint32_t network;        // Data link type (1 = Ethernet)
};

// PCAP Packet Header (16 bytes)
// Each packet in the file starts with this header
struct PcapPacketHeader {
    uint32_t ts_sec;         // Timestamp seconds
    uint32_t ts_usec;        // Timestamp microseconds
    uint32_t incl_len;       // Number of bytes saved in file
    uint32_t orig_len;       // Actual length of packet
};

// Represents a single captured packet
struct RawPacket {
    PcapPacketHeader header{};
    std::vector<uint8_t> data;  // The actual packet bytes
    uint32_t link_type = 1;
    uint32_t interface_id = 0;
    uint64_t section_id = 0;
    uint32_t snaplen = 65535;
    // For PCAPNG, these fields are authoritative; header timestamps are a
    // microsecond compatibility view. For classic PCAP ts_usec retains the
    // source's microsecond/nanosecond units.
    uint64_t timestamp_raw = 0;
    uint8_t timestamp_resolution = 6;
    int64_t timestamp_offset = 0;
    bool timestamp_present = true;
    bool source_little_endian = true;
    uint32_t block_type = 6; // PCAPNG: EPB=6, obsolete PB=2, SPB=3.
    uint16_t drops_count = 0xffff;
    std::shared_ptr<const std::vector<uint8_t>> interface_options;
    std::shared_ptr<const std::vector<uint8_t>> section_options;
    std::vector<uint8_t> packet_options;
};

// Class to read PCAP files
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader();

    // Open a pcap file for reading
    bool open(const std::string& filename);
    
    // Close the file
    void close();
    
    // Read the next packet, returns false if no more packets
    bool readNextPacket(RawPacket& packet);
    
    // Get the global header info
    const PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    
    // Check if file is open
    bool isOpen() const { return file_.is_open(); }
    
    // Check if we need to swap byte order
    bool needsByteSwap() const { return needs_byte_swap_; }
    bool isPcapNg() const { return pcapng_; }
    bool isNanosecondPrecision() const { return nanoseconds_; }
    const char* outputExtension() const { return pcapng_ ? ".pcapng" : ".pcap"; }
    bool hasError() const { return !error_.empty(); }
    const std::string& errorMessage() const { return error_; }

    // Bound allocations from untrusted length fields, without imposing the
    // Ethernet 65535-byte limit on other valid link-layer capture formats.
    static constexpr uint32_t MAX_PACKET_BYTES = 16 * 1024 * 1024;
    static constexpr uint32_t MAX_BLOCK_BYTES = 32 * 1024 * 1024;
    static constexpr uint32_t MAX_INTERFACES = 65536;

private:
    friend class PcapWriter;
    struct Interface {
        uint32_t link_type = 1;
        uint32_t snaplen = 0;
        uint8_t resolution = 6;
        int64_t offset = 0;
        std::shared_ptr<const std::vector<uint8_t>> options;
    };
    std::ifstream file_;
    PcapGlobalHeader global_header_{};
    bool needs_byte_swap_ = false;
    bool little_endian_ = true;
    bool pcapng_ = false;
    bool nanoseconds_ = false;
    bool section_seen_ = false;
    uint64_t file_size_ = 0;
    uint64_t position_ = 0;
    uint64_t section_id_ = 0;
    uint64_t section_end_ = UINT64_MAX;
    size_t interface_options_bytes_ = 0;
    std::string error_;
    std::vector<Interface> interfaces_;
    std::shared_ptr<const std::vector<uint8_t>> section_options_;

    bool fail(const std::string& message);
    bool readBytes(uint8_t* destination, size_t count, const char* description);
    bool readBlock(uint32_t& type, std::vector<uint8_t>& body);
    bool readSection(const std::vector<uint8_t>& body);
    bool readInterface(const std::vector<uint8_t>& body);
    bool readNgPacket(uint32_t type, const std::vector<uint8_t>& body, RawPacket& packet);
    bool validateOptions(const std::vector<uint8_t>& body, size_t start, uint32_t type, Interface* interface = nullptr);
};

// Writes in the input capture format. Packet bytes, wire length, timestamp
// precision, per-interface link types and opaque packet options are preserved.
// Call close() and inspect its result to detect buffered write failures.
class PcapWriter {
public:
    ~PcapWriter();
    bool open(const std::string& filename, const PcapReader& reader);
    bool write(const RawPacket& packet);
    bool close();
    bool hasError() const { return !error_.empty(); }
    const std::string& errorMessage() const { return error_; }

private:
    struct OutputInterface {
        uint32_t id;
        uint32_t link_type;
        uint32_t snaplen;
        uint8_t resolution;
        int64_t offset;
    };
    std::ofstream file_;
    bool pcapng_ = false;
    bool little_endian_ = true;
    bool nanoseconds_ = false;
    uint64_t section_id_ = 0;
    PcapGlobalHeader global_header_{};
    std::unordered_map<uint32_t, OutputInterface> interfaces_;
    std::string error_;
    bool fail(const std::string& message);
    bool writeBytes(const uint8_t* bytes, size_t size);
    bool writeBlock(uint32_t type, const std::vector<uint8_t>& body);
    bool writeSection(bool littleEndian, uint64_t sectionId, const std::shared_ptr<const std::vector<uint8_t>>& options);
    bool writeInterface(const RawPacket& packet, uint32_t& id);
};

} // namespace PacketAnalyzer

#endif // PCAP_READER_H
