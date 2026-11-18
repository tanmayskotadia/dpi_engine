# DPI Engine - Deep Packet Inspection System

A local packet-analysis workspace with capture upload, live capture, flow-aware filtering, reports, and optional Windows firewall enforcement.

[Run locally](#run-locally) · [Engine walkthrough](#engine-walkthrough) · [Use the workspace](#use-the-workspace) · [Capture formats](#capture-formats-and-protocols) · [Configuration](#configuration)

## Run locally

Requires Node.js supported by the bundled Vite version, npm, and a C++17 compiler (g++ or CMake with a configured compiler).

```sh
npm install
npm --prefix frontend install
npm run build:engine
npm run build:frontend
npm start
```

Open [localhost:3000](http://localhost:3000). For frontend development, run `npm run dev` in another terminal and use [localhost:5173](http://localhost:5173).

Live capture needs [Wireshark's dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html) and a working capture driver. On Windows, install Wireshark with Npcap. The app detects the standard Wireshark installation, or uses `DUMPCAP_PATH`. It does not install a driver or change its permissions.

Live enforcement uses Windows Defender Firewall on the computer running the server. Run the server from an Administrator terminal when you intend to apply or remove native rules. The interface reports whether native status and privileges are available.

## Engine walkthrough

This document provides a comprehensive overview of the project, covering the networking concepts, system architecture, packet processing pipeline, and implementation details to help readers understand how the DPI engine works.

The walkthrough follows the original engine, from reading a packet through producing a sample report. The [current architecture](#architecture) uses two passes to apply flow decisions in capture order. See [Filtering behavior](#filtering-behavior) for the rules used by the current release.

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [Packet Processing Pipeline (Simple Version)](#5-packet-processing-pipeline-simple-version)
6. [Packet Processing Pipeline (Multi-threaded Version)](#6-packet-processing-pipeline-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS                │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)    │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)        │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network) │
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI:** Even though HTTPS encrypts application data, the destination domain is typically exposed through the TLS Server Name Indication (SNI), allowing it to be identified before encryption of the application payload.

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `src/main_working.cpp` | Learning, small captures |
| Multi-threaded | `src/dpi_mt.cpp` | Production, large captures |

---

## 4. File Structure

```
packet_analyzer/
├── include/                    # Header files (declarations)
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Network protocol parsing
│   ├── sni_extractor.h        # TLS/HTTP inspection
│   ├── types.h                # Data structures (FiveTuple, AppType, etc.)
│   ├── rule_manager.h         # Blocking rules (multi-threaded version)
│   ├── connection_tracker.h   # Flow tracking (multi-threaded version)
│   ├── load_balancer.h        # LB thread (multi-threaded version)
│   ├── fast_path.h            # FP thread (multi-threaded version)
│   ├── thread_safe_queue.h    # Thread-safe queue
│   └── dpi_engine.h           # Main orchestrator
│
├── src/                        # Implementation files
│   ├── pcap_reader.cpp        # PCAP file handling
│   ├── packet_parser.cpp      # Protocol parsing
│   ├── sni_extractor.cpp      # SNI/Host extraction
│   ├── types.cpp              # Helper functions
│   ├── main_working.cpp       # ★ SIMPLE VERSION ★
│   ├── dpi_mt.cpp             # ★ MULTI-THREADED VERSION ★
│   └── [other files]          # Supporting code
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
└── README.md                  # This file!
```

---

## 5. Packet Processing Pipeline (Simple Version)

Let's trace a single packet through `main_working.cpp`:

### Step 1: Read PCAP File

```cpp
PcapReader reader;
reader.open("capture.pcap");
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```cpp
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return false when no more packets

### Step 3: Parse Protocol Headers

```cpp
PacketParser::parse(raw, parsed);
```

**What happens (in packet_parser.cpp):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.src_port = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.has_tcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```cpp
FiveTuple tuple;
tuple.src_ip = parseIP(parsed.src_ip);
tuple.dst_ip = parseIP(parsed.dest_ip);
tuple.src_port = parsed.src_port;
tuple.dst_port = parsed.dest_port;
tuple.protocol = parsed.protocol;

Flow& flow = flows[tuple];  // Get or create
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```cpp
// For HTTPS traffic (port 443)
if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
    auto sni = SNIExtractor::extract(payload, payload_length);
    if (sni) {
        flow.sni = *sni;                    // "www.youtube.com"
        flow.app_type = sniToAppType(*sni); // AppType::YOUTUBE
    }
}
```

**What happens (in sni_extractor.cpp):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```cpp
   // In types.cpp
   if (sni.find("youtube") != std::string::npos) {
       return AppType::YOUTUBE;
   }
   ```

### Step 6: Check Blocking Rules

```cpp
if (rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni)) {
    flow.blocked = true;
}
```

**What happens:**
```cpp
// Check IP blacklist
if (blocked_ips.count(src_ip)) return true;

// Check app blacklist
if (blocked_apps.count(app)) return true;

// Check domain blacklist (substring match)
for (const auto& dom : blocked_domains) {
    if (sni.find(dom) != std::string::npos) return true;
}

return false;
```

### Step 7: Forward or Drop

```cpp
if (flow.blocked) {
    dropped++;
    // Don't write to output
} else {
    forwarded++;
    // Write packet to output file
    output.write(packet_header);
    output.write(packet_data);
}
```

### Step 8: Generate Report

After processing all packets:
```cpp
// Count apps
for (const auto& [tuple, flow] : flows) {
    app_stats[flow.app_type]++;
}

// Print report
"YouTube: 150 packets (15%)"
"Facebook: 80 packets (8%)"
...
```

---

## 6. Packet Processing Pipeline (Multi-threaded Version)

The multi-threaded version (`dpi_mt.cpp`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)|│(Fast Path)│  │(Fast Path)││(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread

```cpp
// Main thread reads PCAP
while (reader.readNextPacket(raw)) {
    Packet pkt = createPacket(raw);

    // Hash to select Load Balancer
    size_t lb_idx = hash(pkt.tuple) % num_lbs;

    // Push to LB's queue
    lbs_[lb_idx]->queue().push(pkt);
}
```

#### Step 2: Load Balancer Thread

```cpp
void LoadBalancer::run() {
    while (running_) {
        // Pop from my input queue
        auto pkt = input_queue_.pop();

        // Hash to select Fast Path
        size_t fp_idx = hash(pkt.tuple) % num_fps_;

        // Push to FP's queue
        fps_[fp_idx]->queue().push(pkt);
    }
}
```

#### Step 3: Fast Path Thread

```cpp
void FastPath::run() {
    while (running_) {
        // Pop from my input queue
        auto pkt = input_queue_.pop();

        // Look up flow (each FP has its own flow table)
        Flow& flow = flows_[pkt.tuple];

        // Classify (SNI extraction)
        classifyFlow(pkt, flow);

        // Check rules
        if (rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni)) {
            stats_->dropped++;
        } else {
            // Forward: push to output queue
            output_queue_->push(pkt);
        }
    }
}
```

#### Step 4: Output Writer Thread

```cpp
void outputThread() {
    while (running_ || output_queue_.size() > 0) {
        auto pkt = output_queue_.pop();

        // Write to output file
        output_file.write(packet_header);
        output_file.write(pkt.data);
    }
}
```

### Thread-Safe Queue

The magic that makes multi-threading work:

```cpp
template<typename T>
class TSQueue {
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;

    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(item);
        not_empty_.notify_one();  // Wake up waiting consumer
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [&]{ return !queue_.empty(); });
        T item = queue_.front();
        queue_.pop();
        return item;
    }
};
```

**How it works:**
- `push()`: Producer adds item, signals waiting consumers
- `pop()`: Consumer waits until item available, then takes it
- `mutex`: Only one thread can access at a time
- `condition_variable`: Efficient waiting (no busy-loop)

---

## 7. Deep Dive: Each Component

### pcap_reader.h / pcap_reader.cpp

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```cpp
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 identifies PCAP
    uint16_t version_major;  // Usually 2
    uint16_t version_minor;  // Usually 4
    uint32_t snaplen;        // Max packet size captured
    uint32_t network;        // 1 = Ethernet
};

struct PcapPacketHeader {
    uint32_t ts_sec;         // Timestamp (seconds)
    uint32_t ts_usec;        // Timestamp (microseconds)
    uint32_t incl_len;       // Bytes saved in file
    uint32_t orig_len;       // Original packet size
};
```

**Key functions:**
- `open(filename)`: Open PCAP, validate header
- `readNextPacket(raw)`: Read next packet into buffer
- `close()`: Clean up

### packet_parser.h / packet_parser.cpp

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```cpp
bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parseEthernet(...);  // Extract MACs, EtherType
    parseIPv4(...);      // Extract IPs, protocol, TTL
    parseTCP(...);       // Extract ports, flags, seq numbers
    // OR
    parseUDP(...);       // Extract ports
}
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). Your computer might use little-endian. We use `ntohs()` and `ntohl()` to convert:
```cpp
// ntohs = Network TO Host Short (16-bit)
uint16_t port = ntohs(*(uint16_t*)(data + offset));

// ntohl = Network TO Host Long (32-bit)
uint32_t seq = ntohl(*(uint32_t*)(data + offset));
```

### sni_extractor.h / sni_extractor.cpp

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload,
    size_t length
) {
    // 1. Verify TLS record header
    // 2. Verify Client Hello handshake
    // 3. Skip to extensions
    // 4. Find SNI extension (type 0x0000)
    // 5. Extract hostname string
}
```

**For HTTP:**
```cpp
std::optional<std::string> HTTPHostExtractor::extract(
    const uint8_t* payload,
    size_t length
) {
    // 1. Verify HTTP request (GET, POST, etc.)
    // 2. Search for "Host: " header
    // 3. Extract value until newline
}
```

### types.h / types.cpp

**Purpose:** Define data structures used throughout

**FiveTuple:**
```cpp
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    bool operator==(const FiveTuple& other) const;
};
```

**AppType:**
```cpp
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    // ... more apps
};
```

**sniToAppType function:**
```cpp
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube") != std::string::npos)
        return AppType::YOUTUBE;
    if (sni.find("facebook") != std::string::npos)
        return AppType::FACEBOOK;
    // ... more patterns
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload, size_t length
) {
    // Check TLS record header
    if (payload[0] != 0x16) return std::nullopt;  // Not handshake
    if (payload[5] != 0x01) return std::nullopt;  // Not Client Hello

    size_t offset = 43;  // Skip to session ID

    // Skip Session ID
    uint8_t session_len = payload[offset];
    offset += 1 + session_len;

    // Skip Cipher Suites
    uint16_t cipher_len = readUint16BE(payload + offset);
    offset += 2 + cipher_len;

    // Skip Compression Methods
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;

    // Read Extensions Length
    uint16_t ext_len = readUint16BE(payload + offset);
    offset += 2;

    // Search for SNI extension
    size_t ext_end = offset + ext_len;
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = readUint16BE(payload + offset);
        uint16_t ext_data_len = readUint16BE(payload + offset + 2);
        offset += 4;

        if (ext_type == 0x0000) {  // SNI!
            // Parse SNI structure
            uint16_t sni_len = readUint16BE(payload + offset + 3);
            return std::string(
                (char*)(payload + offset + 5),
                sni_len
            );
        }

        offset += ext_data_len;
    }

    return std::nullopt;  // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

These commands and the report in chapter 11 accompany the [original engine source](https://github.com/tanmayskotadia/dpi_engine/tree/eee69d8f41cb4231030d3af5eb5fe812cb7e9998). For the current executable, see [Run locally](#run-locally) and [Command line](#command-line).

### Windows (MSYS2 MinGW64)

#### Prerequisites

- **Windows 10/11**
- **MSYS2**
- **MinGW-w64 GCC**
- **Python 3.x (optional, only for generating sample PCAP files)**

#### MSYS2 Setup

**Step 1: Install MSYS2**

Download and install MSYS2:

https://www.msys2.org/

**Step 2: Install MinGW64 Compiler**

Open **MSYS2 MINGW64** and run:

```powershell
pacman -Syu
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
```

**Step 3: Add MinGW64 to PATH**

Add the following directory to your Windows PATH:

```text
C:\msys64\mingw64\bin
```

Verify:

```powershell
where.exe g++
```

Expected:

```text
C:\msys64\mingw64\bin\g++.exe
```

**Step 4: (If using Anaconda)**

Disable automatic activation:

```powershell
conda config --set auto_activate_base false
```

Restart PowerShell.

Verify that the correct runtime library is found:

```powershell
where.exe libstdc++-6.dll
```

Expected:

```text
C:\msys64\mingw64\bin\libstdc++-6.dll
```

> If Anaconda's DLL appears before the MSYS2 DLL, the executable may fail with **0xC0000139 (Entry Point Not Found)**.

#### Build Commands

**Simple Version:**

```powershell
g++ -std=c++17 -O2 -I include -o dpi_simple.exe `
    src/main_working.cpp `
    src/pcap_reader.cpp `
    src/packet_parser.cpp `
    src/sni_extractor.cpp `
    src/types.cpp
```

**Multi-threaded Version:**

```powershell
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine.exe `
    src/dpi_mt.cpp `
    src/pcap_reader.cpp `
    src/packet_parser.cpp `
    src/sni_extractor.cpp `
    src/types.cpp
```


#### Creating Test Data (Optional)

```powershell
py generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

#### Running

**Basic usage:**

```powershell
.\dpi_engine.exe test_dpi.pcap output.pcap
```

**With blocking:**

```powershell
.\dpi_engine.exe test_dpi.pcap blocked_output.pcap `
    --block-app YouTube `
    --block-app TikTok `
    --block-ip 192.168.1.50 `
    --block-domain facebook
```

**Configure threads (multi-threaded only):**

```powershell
.\dpi_engine.exe test_dpi.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB threads × 4 FP threads = 16 processing threads
```

#### Verify Results

Open the generated PCAP files in **Wireshark** and compare:

- `test_dpi.pcap`
- `output.pcap` (basic execution)
- `blocked_output.pcap` (blocking example)

Verify:

- Packet count
- Blocked packets
- Application detection

#### Clean Generated Files

```powershell
Remove-Item -LiteralPath dpi_simple.exe, dpi_engine.exe, test_dpi.pcap, output.pcap, blocked_output.pcap
```

---

## 11. Understanding the Output

### Sample Output

```text
┌──────────────────────────────────────────────────────────────┐
│              DPI ENGINE v2.0 (Multi-threaded)                │
├──────────────────────────────────────────────────────────────┤
│ Load Balancers : 2                                           │
│ FPs per LB     : 2                                           │
│ Total FPs      : 4                                           │
└──────────────────────────────────────────────────────────────┘

[Rules]
  ✓ Blocked IP      : 192.168.1.50
  ✓ Blocked App     : YouTube
  ✓ Blocked App     : TikTok
  ✓ Blocked Domain  : facebook

[PCAP]
  Opened file       : test_dpi.pcap
  Version           : 2.4
  Snaplen           : 65535 bytes
  Link Type         : Ethernet

[Reader]
  Processing packets...
  Done reading 77 packets

┌──────────────────────────────────────────────────────────────┐
│                    PROCESSING REPORT                         │
├──────────────────────────────────────────────────────────────┤
│ Total Packets : 77                                           │
│ Total Bytes   : 5738                                         │
│ TCP Packets   : 73                                           │
│ UDP Packets   : 4                                            │
├──────────────────────────────────────────────────────────────┤
│ Forwarded     : 69                                           │
│ Dropped       : 8                                            │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                   THREAD STATISTICS                          │
├──────────────────────────────────────────────────────────────┤
│ LB0 dispatched : 33                                          │
│ LB1 dispatched : 44                                          │
│ FP0 processed  : 33                                          │
│ FP1 processed  : 0                                           │
│ FP2 processed  : 0                                           │
│ FP3 processed  : 44                                          │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                 APPLICATION BREAKDOWN                        │
├──────────────────────────────────────────────────────────────┤
│ HTTPS         │ 39 │ 50.6% │ ##########                      │
│ Unknown       │ 16 │ 20.8% │ ####                            │
│ DNS           │  4 │  5.2% │ #                               │
│ Twitter/X     │  3 │  3.9% │                                 │
│ HTTP          │  2 │  2.6% │                                 │
│ TikTok        │  1 │  1.3% │                                 │
│ ...                                                          │
└──────────────────────────────────────────────────────────────┘

[Detected Domains / SNIs]

  • httpbin.org          → HTTPS
  • www.youtube.com      → YouTube
  • www.facebook.com     → Facebook
  • www.microsoft.com    → Twitter/X
  • github.com           → GitHub
  • www.instagram.com    → Instagram
  • ...
```

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Inspecting protocol metadata and unencrypted handshake information without decrypting application payloads.
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

A key insight is that, in most HTTPS connections today, the destination domain is exposed through the TLS Server Name Indication (SNI), enabling Deep Packet Inspection systems to classify and filter traffic without decrypting the application payload.

---

## Use the workspace

1. Open **Captures**. Upload a PCAP/PCAPNG file, select a saved capture, or use **Live capture** to record an adapter.
2. Add IP/network, application, domain, port, or protocol rules.
3. Run the analysis. The rules are snapshotted at the start; edits apply to the next run.
4. Open **Results** for packet counts, inspection limitations, blocking reasons, domain search, JSON export, and the filtered capture.
5. Use **Console** to follow, pause, copy, or download engine output.

Analysis filters a saved file. It does **not** block the computer's live connections. Use **Live Windows firewall** for that separate action.

### Live capture

Select a discovered local adapter, duration, and packet limit. No protocol filter is applied by default: all frames delivered by that adapter are recorded. An optional BPF capture filter can narrow the recording.

Recording stops at the first duration, packet-count, or 100 MiB limit. The allowed duration is 1–300 seconds and the packet limit is 1–1,000,000. A completed recording is saved as PCAPNG and selected for analysis. Stop finalizes complete blocks before publishing the file.

Adapter availability and the traffic visible to it depend on the operating system, capture driver, network topology, and permissions. This does not promise visibility into every packet on an entire network, or decode every link-layer format.

### Live Windows firewall

1. Save the desired rules.
2. Select inbound, outbound, or both directions.
3. Choose **Review native policy** and inspect the exact native matches and exclusions.
4. Choose **Apply reviewed policy** to replace DPI Engine's managed rules.
5. Use **Remove managed rules** to remove only those rules.

The preview expires after five minutes. Application classifications, domain patterns, and ARP rules are explicitly excluded from native enforcement. They remain available for capture filtering.

| Saved rule | Live Windows match |
| --- | --- |
| IPv4/IPv6 address or CIDR | Remote address, selected direction |
| Port/range | Local port inbound; remote port outbound |
| TCP, UDP, ICMP, ICMPv6 | Native protocol, selected direction |
| Domain, application, ARP | Capture filtering only |

Native rules act independently: multiple rules are combined as alternatives, not an AND expression. They apply to all firewall profiles. Disabled profiles or organizational policy can affect enforcement; the interface reports native status. Rules persist after the server exits.

Replacement stages new disabled rules, enables the replacement, then removes previous managed rules. Failures attempt to restore the previous policy and report rollback failures. Only the fixed `DPIEngine.ManagedBlocking.v1` group with the generated name prefix is managed. Other firewall rules are untouched.

The capture/firewall API rejects remote clients, foreign browser origins, DNS-rebinding hostnames, and form-style mutation requests. These controls are intended for a local workstation, not a public multi-user firewall service.

Native semantics are documented by Microsoft: [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule) and [Remove-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/remove-netfirewallrule).

## Capture formats and protocols

| Area | Support |
| --- | --- |
| Classic PCAP | Little/big endian; microsecond/nanosecond timestamps |
| PCAPNG | Multiple interfaces and sections; EPB, SPB, obsolete packet blocks; timestamp resolutions and offsets |
| Common link layers | Ethernet, VLAN/QinQ, Linux SLL/SLL2, raw IP, NULL/LOOP, explicit IPv4/IPv6 |
| Network/transport | IPv4, IPv6 extension headers, TCP, UDP, ARP, ICMP/ICMPv6, other IP protocols |
| Hostnames | Visible TLS ClientHello SNI, HTTP Host, DNS questions in queries/responses |
| Other frames | Counted and preserved byte-for-byte unless a known rule matches |

Output retains the input format, frame order, packet bytes, original wire lengths, timestamp precision, and per-interface link types. PCAPNG interface/packet options are preserved. Unrelated metadata blocks such as name-resolution/statistics/secrets blocks are not copied.

A malformed capture-file record is an error, not a successful truncated result. Malformed/truncated/unsupported packet contents are separately counted and preserved when no applicable rule matches. The report distinguishes these from packets dropped by rules.

## Filtering behavior

- **IP/CIDR:** matches either packet endpoint, IPv4 or IPv6; IPv4 ARP sender/target addresses are inspected too.
- **Ports:** `443`, `8000-8080`, `tcp:443`, `udp:5000-5100`; matches either endpoint for the selected transport.
- **Protocols:** `tcp`, `udp`, `icmp`, `icmpv6`, `arp`.
- **Domains:** case-insensitive DNS-label boundaries. `example.com` matches the apex and real subdomains; `*.example.com` matches only subdomains. It does not match `notexample.com`.
- **Applications:** deterministic hostname mappings and transport fallbacks, with visible classification in reports. Domain substrings inside unrelated hostnames are not treated as identities.
- **Bidirectional TCP flows:** classified before output, so a detected blocked hostname removes earlier handshake packets and reverse-direction traffic in that flow. New observed SYN sequences distinguish reuse of a tuple.
- **DNS:** hostname decisions are per question-bearing packet; one blocked lookup does not poison unrelated lookups on the same UDP socket.
- **Fragments:** IP/protocol rules apply to known headers. Port decisions can follow the first fragment's flow; payload reassembly is not performed.

### Inspection limits

This is a bounded analyzer, not a universal decryption or evasion-resistant IDS. It cannot recover hidden ECH names, decrypt application traffic, or extract hostnames from encrypted QUIC payloads. UDP/443 is a QUIC transport heuristic, not proof of the application.

TCP hostname inspection handles contiguous segments, retransmission overlap, and bounded out-of-order segments when the sequence origin is known. It inspects up to 64 KiB per stream with at most 32 queued gaps and bounded active inspection buffers. ClientHello messages split across TLS records, IP-fragmented application payloads, midstream gaps, and complex HTTP reuse may remain unclassified. Resource-limited inspection is reported. Unsupported traffic is not silently discarded.

Capture records are bounded to 16 MiB per packet, 32 MiB per PCAPNG block, and 65,536 interfaces per section. Flow/fragment tracking is bounded; captures that exceed the tracking limit fail explicitly and can be split into smaller captures.

## Command line

```sh
./build/packet_analyzer input.pcap output.pcap --block-ip 192.0.2.0/24 --block-port tcp:443
./build/packet_analyzer input.pcapng output.pcapng --block-ip 2001:db8::/32 --block-protocol icmpv6
./build/packet_analyzer input.pcap output.pcap --block-domain "*.example.com" --block-app YouTube
```

On Windows, use `build\packet_analyzer.exe`. Input and output must differ; an existing output is never intentionally overwritten. `--lbs 1..16` sets dispatch groups and `--fps 1..16` sets analysis workers per group.

## Architecture

```text
Capture file
  → validated record reader
  → bounded queues / flow analysis workers
  → completed flow decisions
  → second sequential read
  → ordered filtering and atomic output publication
  → report / history / downloads
```

Both capture passes stream records. Queues close and drain explicitly; worker shutdown never relies on a timed sleep. Packet totals include every record, with forwarded + dropped equal to the total on a successful run.

The active executable is built from `src/dpi_mt.cpp`, `pcap_reader.cpp`, `packet_parser.cpp`, `sni_extractor.cpp`, and `types.cpp`. Other historical entry points in `src/` are not the production executable.

## Configuration

| Variable | Purpose |
| --- | --- |
| `PORT` | Backend port, default 3000 |
| `DPI_BIND_HOST` | Defaults to 127.0.0.1. Set to 0.0.0.0 for a hosted offline workspace. |
| `DPI_ENGINE_PATH` | Override the compiled engine |
| `DUMPCAP_PATH` | Override dumpcap |
| `PCAP_STORAGE_PATH` / `PCAP_OUTPUT_PATH` | Capture directories |
| `HISTORY_PATH` / `RULES_PATH` | Persisted reports and policy |
| `PCAP_MAX_FILE_SIZE_MB` | Upload limit, default 500 MiB |
| `VITE_API_URL` | Frontend API base; shared by requests and SSE |
| `CORS_ORIGIN` | Origin for ordinary analysis API access |

Live controls are available when the server listens on loopback. A network-facing listener serves offline analysis only. The Windows firewall adapter is unavailable inside the Linux Docker image. Live capture in a container also needs separately provisioned tooling and adapter access; the supplied Docker image supports offline analysis.

## Validation

```sh
npm test
npm run build:frontend
```

Tests rebuild the engine, compile native reader/parser suites, run deterministic synthetic captures through the real CLI, and verify API validation, local-control isolation, capture lifecycle, and firewall planning/rollback with mocked native operations. They do not apply host firewall rules or record real network traffic.
