# Wirehound — Network Traffic Sniffer Design Spec

## Overview

Wirehound is a standalone macOS desktop application for real-time network traffic monitoring. It provides a live dashboard combining a Wireshark-style packet list with live charts showing bandwidth and protocol breakdown.

## Tech Stack

| Layer | Technology |
|---|---|
| App framework | Tauri v2 |
| Backend | Rust |
| Frontend | Svelte |
| Packet capture | `pcap` crate (libpcap bindings) |
| Packet parsing | `pnet` crate |
| Async runtime | `tokio` |
| Charts | Chart.js via `svelte-chartjs` |
| Virtual scrolling | `svelte-virtual-list` or custom |

## Architecture

Monolithic Tauri app — single process, single binary.

```
┌─────────────────────────────────────────────┐
│                 Tauri App                    │
│                                             │
│  ┌─────────────┐    IPC Events    ┌───────┐ │
│  │ Rust Backend │ ──────────────► │Svelte │ │
│  │              │                 │  UI   │ │
│  │ • Capture    │ ◄────────────── │       │ │
│  │ • Parse      │   IPC Commands  │       │ │
│  │ • Filter     │                 │       │ │
│  │ • Stats      │                 │       │ │
│  └─────────────┘                  └───────┘ │
└─────────────────────────────────────────────┘
```

### Rust Backend — Three Internal Layers

Connected by `tokio` channels:

1. **Capture thread** — uses `pcap` crate to read raw packets from a network interface in promiscuous mode. Pushes raw bytes into a bounded channel.
2. **Parser** — reads from the capture channel, decodes Ethernet -> IP -> TCP/UDP/ICMP -> application-layer (DNS, HTTP). Produces structured `Packet` records.
3. **Stats aggregator** — maintains rolling counters (bandwidth, top talkers, protocol breakdown). Emits periodic `Stats` summaries every ~1 second.

### IPC Events (Backend -> Frontend)

- `packet` — individual parsed packets for the scrolling list
- `stats` — aggregated metrics every ~1 second for charts

### IPC Commands (Frontend -> Backend)

- `list_interfaces` — get available network interfaces
- `start_capture(interface, filter)` — begin capturing on an interface with optional BPF filter
- `stop_capture` — stop the current capture
- `clear_packets` — clear the packet list

## Data Model

### Packet

```rust
struct Packet {
    id: u64,
    timestamp: chrono::DateTime<Utc>,
    src_ip: String,
    dst_ip: String,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Protocol,       // TCP, UDP, ICMP, DNS, HTTP, etc.
    length: u32,
    raw_bytes: Vec<u8>,
    parsed_layers: Vec<Layer>, // Ethernet -> IP -> TCP -> HTTP, etc.
    summary: String,           // One-line human-readable summary
}
```

### Layer

```rust
struct Layer {
    name: String,              // "Ethernet", "IPv4", "TCP", "HTTP"
    fields: Vec<(String, String)>, // Key-value pairs for detail view
}
```

### Stats

```rust
struct Stats {
    bytes_per_sec: u64,
    packets_per_sec: u64,
    protocol_breakdown: HashMap<Protocol, u64>,
    top_talkers: Vec<(String, u64)>,  // IP -> byte count
}
```

### Protocol Enum

```rust
enum Protocol {
    TCP,
    UDP,
    ICMP,
    DNS,
    HTTP,
    HTTPS,
    ARP,
    Other(String),
}
```

## Frontend Layout

```
┌──────────────────────────────────────────────┐
│  Toolbar                                     │
│  [Interface v] [Filter: ________] [> Start]  │
├──────────────────────────┬───────────────────┤
│                          │                   │
│  Packet List (left)      │  Charts (right)   │
│                          │                   │
│  #  Time  Src  Dst  Proto│  ┌─ Bandwidth ─┐  │
│  1  0.00  ...  ...  TCP  │  │  ~~~/\~~~    │  │
│  2  0.01  ...  ...  DNS  │  └─────────────┘  │
│  3  0.02  ...  ...  UDP  │  ┌─ Protocols ──┐ │
│  ...                     │  │  TCP 60%     │  │
│                          │  │  UDP 25%     │  │
│                          │  │  DNS 15%     │  │
│                          │  └─────────────┘  │
├──────────────────────────┴───────────────────┤
│  Packet Detail (bottom)                      │
│  > Ethernet: src=AA:BB:CC dst=DD:EE:FF       │
│  > IPv4: 192.168.1.5 -> 142.250.80.46       │
│  > TCP: 52341 -> 443 [SYN] Seq=0            │
│  > Raw Hex: 0000  45 00 00 3c ...            │
└──────────────────────────────────────────────┘
```

### Components

- **Toolbar** — interface selector dropdown, BPF filter text input, start/stop/clear buttons, live packet counter
- **PacketList** — virtualized scrolling table (only renders visible rows). Columns: #, Time, Source, Destination, Protocol, Length, Summary. Click a row to see details.
- **PacketDetail** — expandable tree of protocol layers for selected packet, plus hex dump view of raw bytes
- **BandwidthChart** — rolling line chart of bytes/sec over the last 60 seconds
- **ProtocolChart** — donut chart of protocol distribution, updated every second
- **Resizable panes** — drag handles to resize panels

### Chart Library

Chart.js via `svelte-chartjs`. Handles real-time updates well, simple API, well-documented.

### Virtual Scrolling

`svelte-virtual-list` or custom implementation to keep the packet list performant at 10k+ rows.

## Filtering

Two levels:

1. **Capture filter (BPF)** — applied at the pcap level before packets enter the app. Standard BPF syntax (e.g., `tcp port 80`, `host 192.168.1.1`). High performance, reduces noise at the source.
2. **Display filter (frontend)** — text search/filter on the visible packet list. Filters by IP, protocol, port, or summary text. Does not affect what's captured, only what's shown.

## Permissions & Platform

### macOS BPF Access (Primary Platform)

Packet capture requires access to `/dev/bpf*` devices. Rather than requiring `sudo` for the entire app:

1. First-run screen checks if the user has BPF access
2. If not, displays setup instructions to add the user to the `access_bpf` group
3. Includes a "Check Again" button to re-test after setup
4. Once configured, captures work without elevated privileges

### Platform Notes

- macOS-first — ships libpcap by default
- Architecture is cross-platform (pcap works on Linux/Windows) but not a v1 goal
- Tauri produces a `.dmg` for macOS distribution

## Error Handling

- **No permissions** — first-run screen detects missing BPF access, shows setup instructions with "Check Again" button
- **Interface goes down** — stop capture cleanly, notify user via toast/banner (no crash)
- **High packet volume** — bounded channel between capture and parser. If parser falls behind, oldest unprocessed packets are dropped. "X packets dropped" counter shown in toolbar
- **No interfaces found** — clear message suggesting permission check
- **Invalid BPF filter** — validate filter syntax before applying, show inline error on filter input

## Out of Scope for v1

- Windows/Linux builds
- PCAP file save/load
- Deep packet inspection beyond basic protocol headers
- Plugin/extension system
- Network map / topology visualization
- Packet modification / injection
