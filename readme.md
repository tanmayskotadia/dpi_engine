# DPI Engine

A local packet-analysis workspace with capture upload, live capture, flow-aware filtering, reports, and optional Windows firewall enforcement.

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

The [original engine walkthrough](docs/original-engine-guide.md) covers packet anatomy, the sample captures, and the earlier pipeline.

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
