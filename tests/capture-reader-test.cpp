#include "pcap_reader.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <stdexcept>

using namespace PacketAnalyzer;
using Bytes = std::vector<uint8_t>;
namespace fs = std::filesystem;

namespace {
unsigned assertions = 0;
void check(bool condition, const std::string& message) {
    ++assertions;
    if (!condition) throw std::runtime_error(message);
}

struct TemporaryDirectory {
    fs::path path;
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        for (unsigned attempt = 0; attempt < 100; ++attempt) {
            path = fs::temp_directory_path() / ("dpi-capture-reader-tests-" + std::to_string(stamp) + "-" + std::to_string(attempt));
            if (fs::create_directory(path)) return;
        }
        throw std::runtime_error("Cannot create isolated capture test directory");
    }
    ~TemporaryDirectory() { std::error_code ignored; fs::remove_all(path, ignored); }
};

void number(Bytes& out, uint64_t value, unsigned size, bool little) {
    for (unsigned i = 0; i < size; ++i) out.push_back(static_cast<uint8_t>(value >> (8 * (little ? i : size - 1 - i))));
}
void append(Bytes& into, const Bytes& bytes) { into.insert(into.end(), bytes.begin(), bytes.end()); }
void pad(Bytes& bytes) { while (bytes.size() % 4) bytes.push_back(0); }
void set32(Bytes& bytes, size_t offset, uint32_t value, bool little = true) {
    Bytes replacement;
    number(replacement, value, 4, little);
    std::copy(replacement.begin(), replacement.end(), bytes.begin() + offset);
}
Bytes option(uint16_t code, const Bytes& value, bool little) {
    Bytes bytes;
    number(bytes, code, 2, little); number(bytes, value.size(), 2, little);
    append(bytes, value); pad(bytes);
    return bytes;
}
Bytes block(uint32_t type, Bytes body, bool little) {
    pad(body);
    Bytes bytes;
    number(bytes, type, 4, little); number(bytes, body.size() + 12, 4, little);
    append(bytes, body); number(bytes, body.size() + 12, 4, little);
    return bytes;
}
Bytes section(bool little, uint64_t length = UINT64_MAX, const Bytes& options = {}) {
    Bytes body;
    number(body, 0x1a2b3c4d, 4, little);
    number(body, 1, 2, little); number(body, 0, 2, little);
    number(body, length, 8, little); append(body, options);
    return block(0x0a0d0d0a, body, little);
}
Bytes interfaceBlock(bool little, uint16_t link, uint32_t snaplen, const Bytes& options = {}) {
    Bytes body;
    number(body, link, 2, little); number(body, 0, 2, little);
    number(body, snaplen, 4, little); append(body, options);
    return block(1, body, little);
}
Bytes timestampOptions(bool little, uint8_t resolution, int64_t offset) {
    Bytes bytes = option(9, {resolution}, little);
    Bytes seconds;
    number(seconds, static_cast<uint64_t>(offset), 8, little);
    append(bytes, option(14, seconds, little));
    append(bytes, option(2, {'t', 'e', 's', 't'}, little));
    append(bytes, option(0, {}, little));
    return bytes;
}
Bytes packetBlock(bool little, uint32_t interfaceId, uint64_t timestamp, const Bytes& data,
                  uint32_t originalLength, uint32_t type = 6, const Bytes& options = {}) {
    Bytes body;
    if (type == 3) number(body, originalLength, 4, little);
    else {
        if (type == 2) { number(body, interfaceId, 2, little); number(body, 11, 2, little); }
        else number(body, interfaceId, 4, little);
        number(body, timestamp >> 32, 4, little); number(body, timestamp & 0xffffffff, 4, little);
        number(body, data.size(), 4, little); number(body, originalLength, 4, little);
    }
    append(body, data); pad(body); append(body, options);
    return block(type, body, little);
}
Bytes classicHeader(bool little, bool nano, uint32_t link = 147, uint32_t snaplen = 65535) {
    Bytes bytes;
    number(bytes, nano ? 0xa1b23c4d : 0xa1b2c3d4, 4, little);
    number(bytes, 2, 2, little); number(bytes, 4, 2, little);
    number(bytes, 0, 4, little); number(bytes, 0, 4, little);
    number(bytes, snaplen, 4, little); number(bytes, link, 4, little);
    return bytes;
}
void classicPacket(Bytes& bytes, bool little, bool nano, const Bytes& data, uint32_t originalLength) {
    number(bytes, 1700000000, 4, little);
    number(bytes, nano ? 987654321 : 654321, 4, little);
    number(bytes, data.size(), 4, little); number(bytes, originalLength, 4, little);
    append(bytes, data);
}
void save(const fs::path& path, const Bytes& bytes) {
    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    check(bool(file), "Could not write test fixture");
}
Bytes load(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(file), {});
}
std::vector<RawPacket> readPackets(const fs::path& path) {
    PcapReader reader;
    check(reader.open(path.string()), "Valid fixture failed to open: " + reader.errorMessage());
    std::vector<RawPacket> packets;
    RawPacket packet;
    while (reader.readNextPacket(packet)) packets.push_back(packet);
    check(!reader.hasError(), "Valid capture read failed: " + reader.errorMessage());
    return packets;
}
void rejected(const fs::path& path, const Bytes& bytes, const std::string& description) {
    save(path, bytes);
    PcapReader reader;
    RawPacket packet;
    if (reader.open(path.string())) while (reader.readNextPacket(packet)) {}
    check(reader.hasError(), "Malformed fixture was accepted: " + description);
    check(!reader.errorMessage().empty(), "Malformed fixture must provide a diagnostic");
    check(!reader.readNextPacket(packet), "Reading must stop after a parse error");
}
void samePacket(const RawPacket& expected, const RawPacket& actual) {
    check(actual.data == expected.data, "Packet bytes changed");
    check(actual.header.incl_len == expected.header.incl_len, "Captured length changed");
    check(actual.header.orig_len == expected.header.orig_len, "Original wire length changed");
    check(actual.link_type == expected.link_type, "Link type changed");
    check(actual.snaplen == expected.snaplen, "Snapshot length changed");
    check(actual.timestamp_raw == expected.timestamp_raw, "Raw timestamp lost precision");
    check(actual.timestamp_resolution == expected.timestamp_resolution, "Timestamp resolution changed");
    check(actual.timestamp_offset == expected.timestamp_offset, "Timestamp offset changed");
    check(actual.timestamp_present == expected.timestamp_present, "Missing timestamp was fabricated");
    check(actual.block_type == expected.block_type, "Packet block type changed");
    check(actual.source_little_endian == expected.source_little_endian, "Section byte order changed");
    check(actual.drops_count == expected.drops_count, "Obsolete packet drop count changed");
    check(actual.packet_options == expected.packet_options, "Packet options changed");
    check(bool(actual.interface_options) == bool(expected.interface_options), "Interface options were lost");
    if (expected.interface_options) check(*actual.interface_options == *expected.interface_options, "Interface options changed");
    if (expected.section_options) check(actual.section_options && *actual.section_options == *expected.section_options, "Section options changed");
}
void roundTrip(const fs::path& input, const fs::path& output, const std::function<bool(size_t)>& keep = [](size_t) { return true; }) {
    PcapReader reader;
    PcapWriter writer;
    check(reader.open(input.string()), "Cannot open round-trip input: " + reader.errorMessage());
    check(writer.open(output.string(), reader), "Cannot open round-trip writer: " + writer.errorMessage());
    std::vector<RawPacket> expected;
    RawPacket packet;
    size_t index = 0;
    while (reader.readNextPacket(packet)) {
        if (keep(index)) {
            expected.push_back(packet);
            check(writer.write(packet), "Writer rejected a valid packet: " + writer.errorMessage());
        }
        ++index;
    }
    check(!reader.hasError(), "Round-trip input became invalid: " + reader.errorMessage());
    check(writer.close(), "Writer could not flush: " + writer.errorMessage());
    const auto actual = readPackets(output);
    check(actual.size() == expected.size(), "Packet count changed during filtering/round trip");
    for (size_t i = 0; i < actual.size(); ++i) samePacket(expected[i], actual[i]);
}
} // namespace

int main() {
    try {
        TemporaryDirectory fixtures;
        const auto input = fixtures.path / "input.capture";
        const auto output = fixtures.path / "output.capture";
        const Bytes unknownFrame{0, 0xff, 0x7e, 3, 9};

        // Classic microsecond/nanosecond captures in either byte order round trip
        // byte-for-byte, including reserved/FCS bits and truncated wire lengths.
        for (bool little : {false, true}) for (bool nano : {false, true}) {
            Bytes bytes = classicHeader(little, nano, 0x04000093, 1024);
            classicPacket(bytes, little, nano, unknownFrame, 512);
            classicPacket(bytes, little, nano, {}, 0);
            save(input, bytes);
            PcapReader reader;
            check(reader.open(input.string()), "Classic capture did not open");
            check(!reader.isPcapNg() && reader.isNanosecondPrecision() == nano, "Classic format detection failed");
            check(std::string(reader.outputExtension()) == ".pcap", "Classic extension mismatch");
            RawPacket packet;
            check(reader.readNextPacket(packet), "Classic packet missing");
            check(packet.link_type == 147 && packet.header.orig_len == 512, "Classic packet metadata mismatch");
            check(packet.header.ts_usec == (nano ? 987654321u : 654321u), "Classic timestamp fraction changed");
            reader.close();
            roundTrip(input, output);
            check(load(output) == bytes, "Classic round trip was not byte-for-byte exact");
        }

        Bytes large = classicHeader(true, true, 101, 100000);
        classicPacket(large, true, true, Bytes(70003, 0xab), 90000);
        save(input, large);
        roundTrip(input, output);
        check(readPackets(output)[0].data.size() == 70003, "Valid non-Ethernet packet was limited to 65535 bytes");

        Bytes classic = classicHeader(true, false);
        classicPacket(classic, true, false, unknownFrame, 20);
        for (size_t length = 0; length < classic.size(); ++length) {
            if (length == 24) continue; // A global header alone is a valid empty capture.
            rejected(input, Bytes(classic.begin(), classic.begin() + length), "truncated classic capture");
        }
        Bytes bad = classic; bad[0] = 0; rejected(input, bad, "bad classic magic");
        bad = classic; set32(bad, 16, 0); rejected(input, bad, "zero snapshot length");
        bad = classic; bad[4] = 3; rejected(input, bad, "unsupported classic version");
        bad = classic; set32(bad, 32, 21); rejected(input, bad, "captured length exceeds original");
        bad = classic; set32(bad, 16, 4); rejected(input, bad, "captured length exceeds snapshot");
        bad = classic; set32(bad, 32, PcapReader::MAX_PACKET_BYTES + 1); rejected(input, bad, "oversized classic packet");
        bad = classic; set32(bad, 28, 1000000); rejected(input, bad, "invalid microsecond fraction");

        // The first surviving packet is interface 1; the later SPB must still
        // refer to interface 0 after filtering and output interface remapping.
        const Bytes comment = option(1, {'c', 'a', 'p', 't', 'u', 'r', 'e'}, true);
        Bytes ng = section(true, UINT64_MAX, comment);
        append(ng, interfaceBlock(true, 1, 4, timestampOptions(true, 9, -3)));
        append(ng, interfaceBlock(true, 147, 0, timestampOptions(true, 0x8a, 2)));
        append(ng, block(0x12345678, {1, 2, 3, 4}, true)); // Unknown metadata is safely skipped.
        append(ng, packetBlock(true, 1, 123456789012345ull, unknownFrame, 200, 6, option(1, {'p'}, true)));
        append(ng, packetBlock(true, 0, 0, {1, 2, 3, 4}, 9, 3));
        append(ng, packetBlock(true, 0, 987654321123456789ull, {5, 6, 7}, 12));
        append(ng, packetBlock(true, 1, 1025, {9, 8}, 10, 2, option(2, {0, 0, 0, 0}, true)));
        append(ng, section(false));
        append(ng, interfaceBlock(false, 276, 65535, timestampOptions(false, 9, -10)));
        append(ng, packetBlock(false, 0, UINT64_MAX, {0, 1, 0, 2, 0, 3}, 100));
        save(input, ng);
        PcapReader ngReader;
        check(ngReader.open(input.string()) && ngReader.isPcapNg(), "PCAPNG detection failed");
        check(std::string(ngReader.outputExtension()) == ".pcapng", "PCAPNG extension mismatch");
        ngReader.close();
        const auto packets = readPackets(input);
        check(packets.size() == 5, "PCAPNG packet blocks were lost");
        check(packets[0].interface_id == 1 && packets[0].link_type == 147, "Mixed interface metadata missing");
        check(packets[0].timestamp_resolution == 0x8a && packets[0].timestamp_offset == 2, "Binary timestamp metadata mismatch");
        check(!packets[1].timestamp_present && packets[1].header.incl_len == 4 && packets[1].header.orig_len == 9, "SPB capture truncation not preserved");
        check(packets[3].block_type == 2 && packets[3].drops_count == 11, "Obsolete Packet Block not supported");
        check(packets[4].section_id == 1 && !packets[4].source_little_endian && packets[4].interface_id == 0, "Section-local interface IDs/endianness did not reset");
        roundTrip(input, output);
        roundTrip(input, output, [](size_t index) { return index != 2; });
        const auto reopened = readPackets(input);
        for (size_t i = 0; i < packets.size(); ++i) {
            check(reopened[i].section_id == packets[i].section_id && reopened[i].interface_id == packets[i].interface_id, "Reopened capture IDs are not stable");
        }

        for (uint8_t resolution : {uint8_t(0), uint8_t(6), uint8_t(9), uint8_t(19), uint8_t(127), uint8_t(0x80), uint8_t(0xbf), uint8_t(0xff)}) {
            Bytes bytes = section(false);
            append(bytes, interfaceBlock(false, 999, 0, timestampOptions(false, resolution, INT64_MIN)));
            append(bytes, packetBlock(false, 0, UINT64_MAX, unknownFrame, 50));
            save(input, bytes);
            roundTrip(input, output);
        }

        Bytes simpleNg = section(true);
        append(simpleNg, interfaceBlock(true, 1, 65535));
        const size_t packetStart = simpleNg.size();
        append(simpleNg, packetBlock(true, 0, 1, unknownFrame, 20));
        for (size_t length = 0; length < simpleNg.size(); ++length) {
            if (length == 28 || length == packetStart) continue; // Valid empty section/capture.
            rejected(input, Bytes(simpleNg.begin(), simpleNg.begin() + length), "truncated PCAPNG capture");
        }
        bad = simpleNg; bad[8] = 0; rejected(input, bad, "bad section byte-order magic");
        bad = simpleNg; bad[12] = 2; rejected(input, bad, "unsupported section version");
        bad = simpleNg; set32(bad, 4, 27); rejected(input, bad, "unaligned section block");
        bad = simpleNg; set32(bad, packetStart + 4, 8); rejected(input, bad, "block below minimum length");
        bad = simpleNg; set32(bad, packetStart + 4, PcapReader::MAX_BLOCK_BYTES + 4); rejected(input, bad, "oversized block");
        bad = simpleNg; set32(bad, packetStart + 8, 5); rejected(input, bad, "undefined interface");
        bad = simpleNg; set32(bad, packetStart + 20, 100); rejected(input, bad, "packet data exceeds its block");
        bad = simpleNg; set32(bad, bad.size() - 4, 12); rejected(input, bad, "mismatched trailing length");

        for (const Bytes& options : {option(9, {6, 0}, true), option(14, {1}, true), option(9, {}, true)}) {
            bad = section(true); append(bad, interfaceBlock(true, 1, 65535, options));
            rejected(input, bad, "invalid interface timestamp option length");
        }
        Bytes duplicate = option(9, {6}, true); append(duplicate, option(9, {9}, true));
        bad = section(true); append(bad, interfaceBlock(true, 1, 65535, duplicate));
        rejected(input, bad, "duplicate timestamp resolution option");
        bad = section(true); append(bad, interfaceBlock(true, 1, 4));
        append(bad, packetBlock(true, 0, 0, {1, 2, 3, 4, 5}, 9, 3));
        rejected(input, bad, "SPB payload inconsistent with snapshot length");
        bad = section(true); append(bad, interfaceBlock(true, 1, 65535));
        append(bad, packetBlock(true, 0, 0, unknownFrame, 9, 6, {1, 0, 100, 0}));
        rejected(input, bad, "packet option extending beyond block");

        Bytes contents = interfaceBlock(true, 147, 65535);
        append(contents, packetBlock(true, 0, 42, unknownFrame, 99));
        Bytes bounded = section(true, contents.size()); append(bounded, contents);
        append(bounded, section(false, 0));
        save(input, bounded); roundTrip(input, output);
        bad = section(true, contents.size() - 4); append(bad, contents);
        rejected(input, bad, "block crossing declared section boundary");
        bad = section(true, contents.size() + 4); append(bad, contents);
        rejected(input, bad, "declared section longer than file");
        bad = section(true, 8); append(bad, section(true));
        rejected(input, bad, "unexpected section before declared boundary");

        // Reuse after a malformed capture must clear the old error and metadata.
        PcapReader reused;
        save(input, {0, 1, 2});
        check(!reused.open(input.string()) && reused.hasError(), "Short capture was accepted");
        save(input, classic);
        check(reused.open(input.string()) && !reused.hasError(), "Reader cannot recover on a new valid file");
        PcapWriter writer;
        check(writer.open(output.string(), reused), "Writer did not open");
        RawPacket packet;
        check(reused.readNextPacket(packet), "Reader did not recover its packet");
        ++packet.header.orig_len; // A larger wire length is legitimate truncation metadata.
        check(writer.write(packet), "Writer rejected a valid original length");
        ++packet.header.incl_len;
        check(!writer.write(packet) && writer.hasError(), "Writer accepted a captured/data length mismatch");
        check(!writer.close(), "Writer lost its error on close");
        check(!writer.open((fixtures.path / "missing" / "output.pcap").string(), reused), "Writer accepted an invalid output path");

        std::cout << "Capture reader/writer tests passed (" << assertions << " assertions)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Capture reader/writer test failed: " << error.what() << '\n';
        return 1;
    }
}
