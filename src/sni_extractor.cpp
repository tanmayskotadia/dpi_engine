#include "sni_extractor.h"
#include "filter_rules.h"
#include <cstring>
#include <algorithm>

namespace DPI {
uint16_t SNIExtractor::readUint16BE(const uint8_t* p) { return (uint16_t(p[0]) << 8) | p[1]; }
uint32_t SNIExtractor::readUint24BE(const uint8_t* p) { return (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | p[2]; }
bool SNIExtractor::isTLSClientHello(const uint8_t* p, size_t length) {
    return p && length >= 9 && p[0] == 22 && p[1] == 3 && p[2] <= 4 &&
        readUint16BE(p + 3) >= 4 && size_t(readUint16BE(p + 3)) + 5 <= length && p[5] == 1;
}
std::optional<std::string> SNIExtractor::extract(const uint8_t* p, size_t length) {
    if (!isTLSClientHello(p, length)) return std::nullopt;
    const size_t recordEnd = 5 + readUint16BE(p + 3);
    const size_t end = 9 + readUint24BE(p + 6);
    if (end > recordEnd || end < 44) return std::nullopt;
    size_t offset = 43;
    offset += 1 + p[offset];
    if (offset + 2 > end) return std::nullopt;
    const size_t ciphers = readUint16BE(p + offset);
    if (ciphers < 2 || ciphers % 2) return std::nullopt;
    offset += 2 + ciphers;
    if (offset >= end) return std::nullopt;
    const size_t compression = p[offset];
    if (!compression) return std::nullopt;
    offset += 1 + compression;
    if (offset + 2 > end) return std::nullopt;
    const size_t extensionsEnd = offset + 2 + readUint16BE(p + offset);
    offset += 2;
    if (extensionsEnd != end) return std::nullopt;
    while (offset + 4 <= end) {
        const auto type = readUint16BE(p + offset);
        const size_t size = readUint16BE(p + offset + 2);
        offset += 4;
        if (offset + size > end) return std::nullopt;
        if (type == 0) {
            if (size < 5 || size_t(readUint16BE(p + offset)) + 2 != size) return std::nullopt;
            size_t item = offset + 2;
            while (item + 3 <= offset + size) {
                const auto nameType = p[item];
                const size_t nameLength = readUint16BE(p + item + 1);
                item += 3;
                if (item + nameLength > offset + size) return std::nullopt;
                if (nameType == 0) {
                    auto host = normalizeDomain(std::string(reinterpret_cast<const char*>(p + item), nameLength));
                    return validDomain(host) ? std::optional<std::string>(host) : std::nullopt;
                }
                item += nameLength;
            }
        }
        offset += size;
    }
    return std::nullopt;
}
std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(const uint8_t*, size_t) { return {}; }

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* p, size_t n) {
    if (!p) return false;
    for (const char* method : {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "CONNECT ", "TRACE "}) {
        const size_t size = std::strlen(method);
        if (n >= size && !std::memcmp(p, method, size)) return true;
    }
    return false;
}
std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* p, size_t n) {
    if (!isHTTPRequest(p, n)) return std::nullopt;
    std::string text(reinterpret_cast<const char*>(p), n);
    const auto headerEnd = text.find("\r\n\r\n");
    if (headerEnd == std::string::npos) return std::nullopt;
    size_t offset = text.find("\r\n");
    if (offset == std::string::npos) return std::nullopt;
    offset += 2;
    while (offset < headerEnd) {
        auto end = text.find("\r\n", offset);
        if (end == std::string::npos || end > headerEnd) return std::nullopt;
        auto colon = text.find(':', offset);
        if (colon < end && lowerText(text.substr(offset, colon - offset)) == "host") {
            auto host = text.substr(colon + 1, end - colon - 1);
            auto first = host.find_first_not_of(" \t");
            if (first == std::string::npos) return std::nullopt;
            host = host.substr(first, host.find_last_not_of(" \t") - first + 1);
            auto port = host.find(':');
            if (port != std::string::npos) host.resize(port);
            host = normalizeDomain(host);
            return validDomain(host) ? std::optional<std::string>(host) : std::nullopt;
        }
        offset = end + 2;
    }
    return std::nullopt;
}

bool DNSExtractor::isDNSQuery(const uint8_t* p, size_t n) {
    return p && n >= 12 && !(p[2] & 0x78) && (p[4] || p[5]);
}
std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* p, size_t n) {
    // Responses carry the same question; inspect both directions.
    if (!isDNSQuery(p, n)) return std::nullopt;
    size_t offset = 12, questionEnd = 0;
    std::string host;
    for (unsigned jumps = 0; jumps < 128 && offset < n; ++jumps) {
        const uint8_t size = p[offset++];
        if (!size) {
            if (!questionEnd) questionEnd = offset;
            if (questionEnd + 4 > n) return std::nullopt;
            host = normalizeDomain(host);
            return validDomain(host) ? std::optional<std::string>(host) : std::nullopt;
        }
        if ((size & 0xc0) == 0xc0) {
            if (offset >= n) return std::nullopt;
            if (!questionEnd) questionEnd = offset + 1;
            auto target = size_t((size & 0x3f) << 8) | p[offset];
            if (target >= offset - 1) return std::nullopt;
            offset = target;
            continue;
        }
        if (size > 63 || offset + size > n || host.size() + size + 1 > 254) return std::nullopt;
        if (!host.empty()) host += '.';
        host.append(reinterpret_cast<const char*>(p + offset), size);
        offset += size;
    }
    return std::nullopt;
}
bool QUICSNIExtractor::isQUICInitial(const uint8_t* p, size_t n) {
    return p && n >= 7 && (p[0] & 0xc0) == 0xc0 && (p[1] || p[2] || p[3] || p[4]);
}
std::optional<std::string> QUICSNIExtractor::extract(const uint8_t*, size_t) {
    // QUIC ciphertext must be decrypted; scanning it cannot reliably recover SNI.
    return std::nullopt;
}
}
