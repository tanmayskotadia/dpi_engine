#include "pcap_reader.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>

namespace PacketAnalyzer {
namespace {
constexpr uint32_t SHB = 0x0a0d0d0a;
constexpr uint32_t BYTE_ORDER_MAGIC = 0x1a2b3c4d;
constexpr uint32_t MICRO_MAGIC = 0xa1b2c3d4;
constexpr uint32_t NANO_MAGIC = 0xa1b23c4d;

uint16_t get16(const uint8_t* p, bool little) {
    return little ? uint16_t(p[0] | uint16_t(p[1]) << 8) : uint16_t(uint16_t(p[0]) << 8 | p[1]);
}
uint32_t get32(const uint8_t* p, bool little) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) value |= uint32_t(p[i]) << (8 * (little ? i : 3 - i));
    return value;
}
uint64_t get64(const uint8_t* p, bool little) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= uint64_t(p[i]) << (8 * (little ? i : 7 - i));
    return value;
}
int64_t signed64(uint64_t value) {
    int64_t result;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}
void put(std::vector<uint8_t>& bytes, uint64_t value, unsigned size, bool little) {
    for (unsigned i = 0; i < size; ++i) bytes.push_back(uint8_t(value >> (8 * (little ? i : size - 1 - i))));
}
size_t padded(size_t size) { return (size + 3) & ~size_t(3); }
bool hostLittleEndian() {
    const uint16_t one = 1;
    return *reinterpret_cast<const uint8_t*>(&one) == 1;
}
std::shared_ptr<const std::vector<uint8_t>> optionsFrom(const std::vector<uint8_t>& bytes, size_t start) {
    return std::make_shared<const std::vector<uint8_t>>(bytes.begin() + start, bytes.end());
}
void compatibilityTimestamp(RawPacket& packet) {
    if (!packet.timestamp_present) return;
    const unsigned exponent = packet.timestamp_resolution & 0x7f;
    const long double units = (packet.timestamp_resolution & 0x80)
        ? std::ldexp(1.0L, exponent) : std::pow(10.0L, exponent);
    const long double seconds = static_cast<long double>(packet.timestamp_raw) / units + packet.timestamp_offset;
    // The legacy view cannot represent negative or >32-bit seconds. The raw
    // value and its resolution/offset remain exact for lossless output.
    if (seconds < 0) return;
    if (seconds > std::numeric_limits<uint32_t>::max()) {
        packet.header.ts_sec = std::numeric_limits<uint32_t>::max();
        packet.header.ts_usec = 999999;
        return;
    }
    packet.header.ts_sec = static_cast<uint32_t>(seconds);
    packet.header.ts_usec = static_cast<uint32_t>(std::min(999999.0L, std::floor((seconds - std::floor(seconds)) * 1000000.0L)));
}
} // namespace

PcapReader::~PcapReader() { close(); }

bool PcapReader::fail(const std::string& message) {
    if (error_.empty()) error_ = "Capture read error at byte " + std::to_string(position_) + ": " + message;
    return false;
}

bool PcapReader::readBytes(uint8_t* destination, size_t count, const char* description) {
    if (count > file_size_ - position_) return fail(std::string("Truncated ") + description);
    if (!count) return true;
    file_.read(reinterpret_cast<char*>(destination), static_cast<std::streamsize>(count));
    if (!file_) return fail(std::string("Could not read ") + description);
    position_ += count;
    return true;
}

bool PcapReader::open(const std::string& filename) {
    close();
    error_.clear();
    global_header_ = {};
    pcapng_ = nanoseconds_ = section_seen_ = false;
    little_endian_ = true;
    section_id_ = position_ = file_size_ = 0;
    section_end_ = UINT64_MAX;
    file_.clear();
    file_.open(filename, std::ios::binary);
    if (!file_) return fail("Could not open input file");
    file_.seekg(0, std::ios::end);
    const auto size = file_.tellg();
    if (size < 0) return fail("Could not determine input size");
    file_size_ = static_cast<uint64_t>(size);
    file_.seekg(0);
    uint8_t header[24]{};
    if (!readBytes(header, 4, "capture signature")) return false;
    const uint32_t magic = get32(header, true);
    if (magic == SHB) {
        pcapng_ = true;
        position_ = 0;
        file_.seekg(0);
        uint32_t type;
        std::vector<uint8_t> body;
        return readBlock(type, body) && readSection(body);
    }
    switch (magic) {
        case MICRO_MAGIC: little_endian_ = true; break;
        case 0xd4c3b2a1: little_endian_ = false; break;
        case NANO_MAGIC: little_endian_ = true; nanoseconds_ = true; break;
        case 0x4d3cb2a1: little_endian_ = false; nanoseconds_ = true; break;
        default: return fail("Unsupported capture signature; expected classic PCAP or PCAPNG");
    }
    needs_byte_swap_ = little_endian_ != hostLittleEndian();
    if (!readBytes(header + 4, 20, "PCAP global header")) return false;
    global_header_.magic_number = nanoseconds_ ? NANO_MAGIC : MICRO_MAGIC;
    global_header_.version_major = get16(header + 4, little_endian_);
    global_header_.version_minor = get16(header + 6, little_endian_);
    const uint32_t zone = get32(header + 8, little_endian_);
    std::memcpy(&global_header_.thiszone, &zone, sizeof(zone));
    global_header_.sigfigs = get32(header + 12, little_endian_);
    global_header_.snaplen = get32(header + 16, little_endian_);
    global_header_.network = get32(header + 20, little_endian_);
    if (global_header_.version_major != 2 || global_header_.version_minor != 4) return fail("Unsupported PCAP version; expected 2.4");
    if (!global_header_.snaplen) return fail("PCAP snapshot length must not be zero");
    return true;
}

void PcapReader::close() {
    if (file_.is_open()) file_.close();
    interfaces_.clear();
    section_options_.reset();
    needs_byte_swap_ = false;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    if (hasError() || !file_.is_open()) return false;
    if (pcapng_) {
        uint32_t type;
        std::vector<uint8_t> body;
        while (readBlock(type, body)) {
            if (type == SHB) { if (!readSection(body)) return false; }
            else if (type == 1) { if (!readInterface(body)) return false; }
            else if (type == 2 || type == 3 || type == 6) return readNgPacket(type, body, packet);
            // Unknown nonstandard blocks and optional metadata blocks have
            // validated lengths/trailers and are safely skipped.
        }
        return false;
    }
    if (position_ == file_size_) return false;
    packet = RawPacket{};
    uint8_t header[16];
    if (!readBytes(header, sizeof(header), "PCAP packet header")) return false;
    packet.header.ts_sec = get32(header, little_endian_);
    packet.header.ts_usec = get32(header + 4, little_endian_);
    packet.header.incl_len = get32(header + 8, little_endian_);
    packet.header.orig_len = get32(header + 12, little_endian_);
    if (packet.header.incl_len > MAX_PACKET_BYTES) return fail("Captured packet exceeds the 16 MiB safety limit");
    if (packet.header.incl_len > global_header_.snaplen || packet.header.incl_len > packet.header.orig_len) return fail("PCAP captured length exceeds snapshot or original length");
    const uint32_t units = nanoseconds_ ? 1000000000 : 1000000;
    if (packet.header.ts_usec >= units) return fail("PCAP timestamp fraction is outside its precision range");
    packet.data.resize(packet.header.incl_len);
    if (!readBytes(packet.data.data(), packet.data.size(), "PCAP packet data")) return false;
    packet.link_type = global_header_.network & 0xffff;
    packet.snaplen = global_header_.snaplen;
    packet.timestamp_resolution = nanoseconds_ ? 9 : 6;
    packet.timestamp_raw = uint64_t(packet.header.ts_sec) * units + packet.header.ts_usec;
    packet.source_little_endian = little_endian_;
    return true;
}

bool PcapReader::readBlock(uint32_t& type, std::vector<uint8_t>& body) {
    body.clear();
    if (position_ == file_size_) {
        if (section_seen_ && section_end_ != UINT64_MAX && position_ != section_end_) return fail("PCAPNG section ended before its declared length");
        return false;
    }
    const uint64_t start = position_;
    uint8_t header[12];
    if (!readBytes(header, 8, "PCAPNG block header")) return false;
    const bool isSection = get32(header, true) == SHB;
    if (isSection) {
        if (section_seen_ && section_end_ != UINT64_MAX && start != section_end_) return fail("PCAPNG section header does not match declared section boundary");
        if (!readBytes(header + 8, 4, "PCAPNG byte-order magic")) return false;
        if (get32(header + 8, true) == BYTE_ORDER_MAGIC) little_endian_ = true;
        else if (get32(header + 8, false) == BYTE_ORDER_MAGIC) little_endian_ = false;
        else return fail("Invalid PCAPNG byte-order magic");
        needs_byte_swap_ = little_endian_ != hostLittleEndian();
    } else if (!section_seen_) return fail("PCAPNG must start with a section header");
    type = get32(header, little_endian_);
    const uint32_t length = get32(header + 4, little_endian_);
    if (length < (isSection ? 28u : 12u) || length % 4) return fail("Invalid PCAPNG block length or alignment");
    if (length > MAX_BLOCK_BYTES) return fail("PCAPNG block exceeds the 32 MiB safety limit");
    if (length > file_size_ - start) return fail("Truncated PCAPNG block");
    if (!isSection && section_end_ != UINT64_MAX && (start >= section_end_ || length > section_end_ - start)) return fail("PCAPNG block exceeds its declared section boundary");
    const size_t bodySize = length - 12;
    const bool understood = isSection || type == 1 || type == 2 || type == 3 || type == 6;
    if (understood) {
        body.resize(bodySize);
        const size_t alreadyRead = isSection ? 4 : 0;
        if (alreadyRead) std::copy(header + 8, header + 12, body.begin());
        if (bodySize > alreadyRead && !readBytes(body.data() + alreadyRead, bodySize - alreadyRead, "PCAPNG block body")) return false;
    } else {
        file_.seekg(static_cast<std::streamoff>(bodySize), std::ios::cur);
        if (!file_) return fail("Could not skip PCAPNG metadata block");
        position_ += bodySize;
    }
    uint8_t trailer[4];
    if (!readBytes(trailer, sizeof(trailer), "PCAPNG block trailer")) return false;
    if (get32(trailer, little_endian_) != length) return fail("PCAPNG block length does not match its trailer");
    return true;
}

bool PcapReader::validateOptions(const std::vector<uint8_t>& body, size_t start, uint32_t type, Interface* interface) {
    bool resolutionSeen = false, offsetSeen = false;
    while (start < body.size()) {
        if (body.size() - start < 4) return fail("Truncated PCAPNG option header");
        const uint16_t code = get16(body.data() + start, little_endian_);
        const uint16_t length = get16(body.data() + start + 2, little_endian_);
        start += 4;
        if (!code) {
            if (length) return fail("PCAPNG end-of-options length must be zero");
            if (std::any_of(body.begin() + start, body.end(), [](uint8_t byte) { return byte != 0; })) return fail("Unexpected data after PCAPNG end-of-options");
            return true;
        }
        if (padded(length) > body.size() - start) return fail("PCAPNG option exceeds its block");
        if (type == 1) {
            int expected = -1;
            switch (code) {
                case 4: case 7: case 8: case 14: case 16: case 17: expected = 8; break;
                case 5: expected = 17; break;
                case 6: expected = 6; break;
                case 9: case 13: expected = 1; break;
                case 10: expected = 4; break;
                default: break;
            }
            if ((expected >= 0 && length != expected) || (code == 11 && length < 1)) return fail("Invalid PCAPNG interface option length");
            if (code == 9) {
                if (resolutionSeen) return fail("Duplicate PCAPNG timestamp resolution option");
                resolutionSeen = true;
                interface->resolution = body[start];
            } else if (code == 14) {
                if (offsetSeen) return fail("Duplicate PCAPNG timestamp offset option");
                offsetSeen = true;
                interface->offset = signed64(get64(body.data() + start, little_endian_));
            }
        } else if (type == 2 || type == 6) {
            if ((code == 2 && length != 4) || (code == 3 && length < 1) ||
                (type == 6 && ((code == 4 && length != 8) || (code == 5 && length != 8) || (code == 6 && length != 4) || (code == 7 && length < 1)))) return fail("Invalid PCAPNG packet option length");
        }
        start += padded(length);
    }
    return true;
}

bool PcapReader::readSection(const std::vector<uint8_t>& body) {
    if (body.size() < 16) return fail("Truncated PCAPNG section header");
    if (get16(body.data() + 4, little_endian_) != 1 || get16(body.data() + 6, little_endian_) != 0) return fail("Unsupported PCAPNG section version; expected 1.0");
    const uint64_t length = get64(body.data() + 8, little_endian_);
    if (length != UINT64_MAX && (length > INT64_MAX || length % 4 || length > file_size_ - position_)) return fail("Invalid or truncated PCAPNG section length");
    if (!validateOptions(body, 16, SHB)) return false;
    section_end_ = length == UINT64_MAX ? UINT64_MAX : position_ + length;
    if (section_seen_) ++section_id_;
    section_seen_ = true;
    interfaces_.clear();
    interface_options_bytes_ = 0;
    section_options_ = optionsFrom(body, 16);
    return true;
}

bool PcapReader::readInterface(const std::vector<uint8_t>& body) {
    if (body.size() < 8) return fail("Truncated PCAPNG interface description");
    if (interfaces_.size() >= MAX_INTERFACES) return fail("PCAPNG section exceeds the interface safety limit");
    if (body.size() - 8 > MAX_PACKET_BYTES - interface_options_bytes_) return fail("PCAPNG interface options exceed the 16 MiB section metadata limit");
    Interface interface;
    interface.link_type = get16(body.data(), little_endian_);
    interface.snaplen = get32(body.data() + 4, little_endian_);
    if (!validateOptions(body, 8, 1, &interface)) return false;
    interface.options = optionsFrom(body, 8);
    interface_options_bytes_ += body.size() - 8;
    interfaces_.push_back(std::move(interface));
    if (interfaces_.size() == 1) {
        global_header_.network = interfaces_[0].link_type;
        global_header_.snaplen = interfaces_[0].snaplen;
    }
    return true;
}

bool PcapReader::readNgPacket(uint32_t type, const std::vector<uint8_t>& body, RawPacket& packet) {
    packet = RawPacket{};
    const size_t dataOffset = type == 3 ? 4 : 20;
    if (body.size() < dataOffset) return fail("Truncated PCAPNG packet block");
    const uint32_t interfaceId = type == 3 ? 0 : type == 2 ? get16(body.data(), little_endian_) : get32(body.data(), little_endian_);
    if (interfaceId >= interfaces_.size()) return fail("PCAPNG packet references an undefined interface");
    const auto& interface = interfaces_[interfaceId];
    packet.interface_id = interfaceId;
    packet.section_id = section_id_;
    packet.link_type = interface.link_type;
    packet.snaplen = interface.snaplen;
    packet.timestamp_resolution = interface.resolution;
    packet.timestamp_offset = interface.offset;
    packet.timestamp_present = type != 3;
    packet.source_little_endian = little_endian_;
    packet.block_type = type;
    packet.interface_options = interface.options;
    packet.section_options = section_options_;
    if (type == 3) {
        packet.header.orig_len = get32(body.data(), little_endian_);
        packet.header.incl_len = interface.snaplen ? std::min(interface.snaplen, packet.header.orig_len) : packet.header.orig_len;
    } else {
        packet.header.incl_len = get32(body.data() + 12, little_endian_);
        packet.header.orig_len = get32(body.data() + 16, little_endian_);
        packet.timestamp_raw = uint64_t(get32(body.data() + 4, little_endian_)) << 32 | get32(body.data() + 8, little_endian_);
        if (type == 2) packet.drops_count = get16(body.data() + 2, little_endian_);
    }
    if (packet.header.incl_len > MAX_PACKET_BYTES) return fail("Captured packet exceeds the 16 MiB safety limit");
    if (packet.header.incl_len > packet.header.orig_len || (interface.snaplen && packet.header.incl_len > interface.snaplen)) return fail("PCAPNG captured length exceeds snapshot or original length");
    const size_t dataSize = padded(packet.header.incl_len);
    if (dataSize > body.size() - dataOffset) return fail("PCAPNG packet data exceeds its block");
    const size_t optionsOffset = dataOffset + dataSize;
    if (type == 3) {
        if (optionsOffset != body.size()) return fail("PCAPNG simple packet length does not match its interface snapshot length");
    } else {
        if (!validateOptions(body, optionsOffset, type)) return false;
        packet.packet_options.assign(body.begin() + optionsOffset, body.end());
    }
    packet.data.assign(body.begin() + dataOffset, body.begin() + dataOffset + packet.header.incl_len);
    compatibilityTimestamp(packet);
    return true;
}

PcapWriter::~PcapWriter() { close(); }

bool PcapWriter::fail(const std::string& message) {
    if (error_.empty()) error_ = "Capture write error: " + message;
    return false;
}

bool PcapWriter::writeBytes(const uint8_t* bytes, size_t size) {
    if (hasError()) return false;
    if (size) file_.write(reinterpret_cast<const char*>(bytes), static_cast<std::streamsize>(size));
    return file_ ? true : fail("Could not write output data");
}

bool PcapWriter::open(const std::string& filename, const PcapReader& reader) {
    close();
    error_.clear();
    interfaces_.clear();
    if (!reader.isOpen() || reader.hasError()) return fail("Input capture is not open or has a read error");
    pcapng_ = reader.pcapng_;
    little_endian_ = reader.little_endian_;
    nanoseconds_ = reader.nanoseconds_;
    global_header_ = reader.global_header_;
    file_.clear();
    file_.open(filename, std::ios::binary | std::ios::trunc);
    if (!file_) return fail("Could not open output file");
    if (pcapng_) return writeSection(little_endian_, reader.section_id_, reader.section_options_);
    std::vector<uint8_t> header;
    put(header, nanoseconds_ ? NANO_MAGIC : MICRO_MAGIC, 4, little_endian_);
    put(header, global_header_.version_major, 2, little_endian_);
    put(header, global_header_.version_minor, 2, little_endian_);
    put(header, static_cast<uint32_t>(global_header_.thiszone), 4, little_endian_);
    put(header, global_header_.sigfigs, 4, little_endian_);
    put(header, global_header_.snaplen, 4, little_endian_);
    put(header, global_header_.network, 4, little_endian_);
    return writeBytes(header.data(), header.size());
}

bool PcapWriter::writeBlock(uint32_t type, const std::vector<uint8_t>& body) {
    if (body.size() % 4 || body.size() > PcapReader::MAX_BLOCK_BYTES - 12) return fail("Invalid or oversized PCAPNG output block");
    const uint32_t length = static_cast<uint32_t>(body.size() + 12);
    std::vector<uint8_t> header;
    put(header, type, 4, little_endian_);
    put(header, length, 4, little_endian_);
    return writeBytes(header.data(), header.size()) && writeBytes(body.data(), body.size()) && writeBytes(header.data() + 4, 4);
}

bool PcapWriter::writeSection(bool littleEndian, uint64_t sectionId, const std::shared_ptr<const std::vector<uint8_t>>& options) {
    little_endian_ = littleEndian;
    section_id_ = sectionId;
    interfaces_.clear();
    std::vector<uint8_t> body;
    put(body, BYTE_ORDER_MAGIC, 4, little_endian_);
    put(body, 1, 2, little_endian_);
    put(body, 0, 2, little_endian_);
    put(body, UINT64_MAX, 8, little_endian_);
    if (options) body.insert(body.end(), options->begin(), options->end());
    return writeBlock(SHB, body);
}

bool PcapWriter::writeInterface(const RawPacket& packet, uint32_t& id) {
    const auto found = interfaces_.find(packet.interface_id);
    if (found != interfaces_.end()) {
        const auto& interface = found->second;
        if (interface.link_type != packet.link_type || interface.snaplen != packet.snaplen || interface.resolution != packet.timestamp_resolution || interface.offset != packet.timestamp_offset) return fail("Interface metadata changed within a PCAPNG section");
        id = interface.id;
        return true;
    }
    if (interfaces_.size() >= PcapReader::MAX_INTERFACES) return fail("Output section exceeds the interface safety limit");
    if (packet.link_type > UINT16_MAX) return fail("Link type cannot be represented in PCAPNG");
    id = static_cast<uint32_t>(interfaces_.size());
    std::vector<uint8_t> body;
    put(body, packet.link_type, 2, little_endian_);
    put(body, 0, 2, little_endian_);
    put(body, packet.snaplen, 4, little_endian_);
    if (packet.interface_options) body.insert(body.end(), packet.interface_options->begin(), packet.interface_options->end());
    else {
        put(body, 9, 2, little_endian_); put(body, 1, 2, little_endian_);
        body.push_back(packet.timestamp_resolution); body.resize(padded(body.size()), 0);
        put(body, 14, 2, little_endian_); put(body, 8, 2, little_endian_);
        put(body, static_cast<uint64_t>(packet.timestamp_offset), 8, little_endian_);
        put(body, 0, 4, little_endian_);
    }
    if (!writeBlock(1, body)) return false;
    interfaces_.emplace(packet.interface_id, OutputInterface{id, packet.link_type, packet.snaplen, packet.timestamp_resolution, packet.timestamp_offset});
    return true;
}

bool PcapWriter::write(const RawPacket& packet) {
    if (hasError()) return false;
    if (!file_.is_open()) return fail("Output file is not open");
    if (packet.data.size() != packet.header.incl_len || packet.data.size() > PcapReader::MAX_PACKET_BYTES || packet.header.incl_len > packet.header.orig_len) return fail("Invalid captured or original packet length");
    if (!pcapng_) {
        if (packet.link_type != (global_header_.network & 0xffff) || packet.timestamp_resolution != (nanoseconds_ ? 9 : 6) || !packet.timestamp_present || packet.header.incl_len > global_header_.snaplen) return fail("Packet metadata is incompatible with the classic PCAP header");
        if (packet.header.ts_usec >= (nanoseconds_ ? 1000000000u : 1000000u)) return fail("Invalid PCAP timestamp fraction");
        std::vector<uint8_t> header;
        put(header, packet.header.ts_sec, 4, little_endian_);
        put(header, packet.header.ts_usec, 4, little_endian_);
        put(header, packet.header.incl_len, 4, little_endian_);
        put(header, packet.header.orig_len, 4, little_endian_);
        return writeBytes(header.data(), header.size()) && writeBytes(packet.data.data(), packet.data.size());
    }
    if (packet.snaplen && packet.header.incl_len > packet.snaplen) return fail("Packet exceeds its interface snapshot length");
    if (packet.block_type != 2 && packet.block_type != 3 && packet.block_type != 6) return fail("Unsupported PCAPNG packet block type");
    if ((packet.block_type == 3) == packet.timestamp_present) return fail("PCAPNG packet timestamp presence does not match its block type");
    if (section_id_ != packet.section_id || little_endian_ != packet.source_little_endian) {
        if (!writeSection(packet.source_little_endian, packet.section_id, packet.section_options)) return false;
    }
    // SPBs always belong to output interface 0. If filtering removed earlier
    // packets, start a new section rather than assigning a false timestamp or
    // accidentally binding an SPB to another surviving interface.
    auto existing = interfaces_.find(packet.interface_id);
    if (packet.block_type == 3 && !interfaces_.empty() && (existing == interfaces_.end() || existing->second.id != 0)) {
        if (!writeSection(packet.source_little_endian, packet.section_id, packet.section_options)) return false;
    }
    uint32_t interfaceId;
    if (!writeInterface(packet, interfaceId)) return false;
    std::vector<uint8_t> body;
    if (packet.block_type == 3) {
        const uint32_t expected = packet.snaplen ? std::min(packet.snaplen, packet.header.orig_len) : packet.header.orig_len;
        if (packet.header.incl_len != expected) return fail("Simple packet length does not match its interface snapshot length");
        put(body, packet.header.orig_len, 4, little_endian_);
    } else {
        if (packet.block_type == 2) {
            if (interfaceId > UINT16_MAX) return fail("Obsolete packet block cannot address this interface");
            put(body, interfaceId, 2, little_endian_);
            put(body, packet.drops_count, 2, little_endian_);
        } else put(body, interfaceId, 4, little_endian_);
        put(body, packet.timestamp_raw >> 32, 4, little_endian_);
        put(body, packet.timestamp_raw & 0xffffffff, 4, little_endian_);
        put(body, packet.header.incl_len, 4, little_endian_);
        put(body, packet.header.orig_len, 4, little_endian_);
    }
    body.insert(body.end(), packet.data.begin(), packet.data.end());
    body.resize(padded(body.size()), 0);
    if (packet.block_type != 3) body.insert(body.end(), packet.packet_options.begin(), packet.packet_options.end());
    return writeBlock(packet.block_type, body);
}

bool PcapWriter::close() {
    if (file_.is_open()) {
        file_.flush();
        if (!file_) fail("Could not flush output data");
        file_.close();
        if (file_.fail()) fail("Could not close output file");
    }
    return !hasError();
}
} // namespace PacketAnalyzer
