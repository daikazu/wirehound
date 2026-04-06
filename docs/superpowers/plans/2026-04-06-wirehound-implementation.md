# Wirehound Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone macOS desktop app for real-time network traffic sniffing with a live packet list, protocol detail panes, and live charts.

**Architecture:** Monolithic Tauri v2 app with a Rust backend handling packet capture (pcap), parsing (pnet), and stats aggregation via tokio channels. Svelte 5 frontend renders a virtualized packet list, expandable detail pane, and Chart.js-powered live charts. Communication via Tauri IPC events (backend→frontend) and invoke commands (frontend→backend).

**Tech Stack:** Rust, Tauri v2, Svelte 5, pcap crate, pnet crate, tokio, chrono, serde, Chart.js

---

## File Structure

```
wirehound/
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── capabilities/
│   │   └── default.json
│   ├── src/
│   │   ├── main.rs          -- Tauri entry point
│   │   ├── lib.rs           -- Module declarations + Tauri setup
│   │   ├── models.rs        -- Protocol, Layer, Packet, Stats, NetworkInterface
│   │   ├── capture.rs       -- pcap capture thread management
│   │   ├── parser.rs        -- Raw packet → structured Packet parsing
│   │   ├── stats.rs         -- Rolling stats aggregation
│   │   └── commands.rs      -- Tauri IPC command handlers
│   └── build.rs
├── src/
│   ├── App.svelte           -- Root layout with all panels
│   ├── main.js              -- Svelte mount point
│   ├── app.css              -- Global styles
│   └── lib/
│       ├── components/
│       │   ├── Toolbar.svelte        -- Interface picker, filter, controls
│       │   ├── PacketList.svelte     -- Virtualized scrolling packet table
│       │   ├── PacketDetail.svelte   -- Layer tree + hex dump
│       │   ├── BandwidthChart.svelte -- Rolling line chart
│       │   ├── ProtocolChart.svelte  -- Donut chart
│       │   └── PermissionCheck.svelte-- BPF access check + setup guide
│       └── stores/
│           ├── packets.ts            -- Packet list store
│           ├── stats.ts              -- Stats store
│           └── capture.ts            -- Capture state store
├── package.json
├── vite.config.js
└── svelte.config.js
```

---

## Task 1: Scaffold Tauri v2 + Svelte Project

**Files:**
- Create: entire project scaffold via `create-tauri-app`
- Modify: `package.json` (add dependencies)
- Modify: `src-tauri/Cargo.toml` (add Rust dependencies)

- [ ] **Step 1: Install Tauri CLI globally**

```bash
npm install -g @tauri-apps/cli@latest
```

- [ ] **Step 2: Create Tauri + Svelte project**

Run from the parent directory (`/Users/mikewall/Code/`). Since the `wirehound` directory already exists with our docs, we'll scaffold into a temp directory and move files:

```bash
cd /tmp
npm create tauri-app@latest wirehound-scaffold -- --template svelte --manager npm
```

Then copy the scaffold files into the existing wirehound directory (preserving our docs/):

```bash
cp -r /tmp/wirehound-scaffold/src /Users/mikewall/Code/wirehound/
cp -r /tmp/wirehound-scaffold/src-tauri /Users/mikewall/Code/wirehound/
cp /tmp/wirehound-scaffold/package.json /Users/mikewall/Code/wirehound/
cp /tmp/wirehound-scaffold/vite.config.js /Users/mikewall/Code/wirehound/
cp /tmp/wirehound-scaffold/svelte.config.js /Users/mikewall/Code/wirehound/
cp /tmp/wirehound-scaffold/index.html /Users/mikewall/Code/wirehound/
rm -rf /tmp/wirehound-scaffold
```

- [ ] **Step 3: Add Rust dependencies to `src-tauri/Cargo.toml`**

Add these to `[dependencies]`:

```toml
pcap = "2"
pnet = "0.35"
tokio = { version = "1", features = ["full"] }
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 4: Add frontend dependencies**

```bash
npm install
npm install chart.js
```

- [ ] **Step 5: Verify the project builds and launches**

```bash
npm run tauri dev
```

Expected: A blank Tauri window opens with the default Svelte template. Close it.

- [ ] **Step 6: Add `.gitignore`**

Create `.gitignore`:

```
node_modules/
src-tauri/target/
dist/
.DS_Store
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: scaffold Tauri v2 + Svelte project with dependencies"
```

---

## Task 2: Rust Data Model

**Files:**
- Create: `src-tauri/src/models.rs`
- Modify: `src-tauri/src/lib.rs` (add module declaration)

- [ ] **Step 1: Create `src-tauri/src/models.rs`**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    DNS,
    HTTP,
    HTTPS,
    ARP,
    Other(String),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Other(name) => write!(f, "{}", name),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub length: u32,
    pub raw_bytes: Vec<u8>,
    pub parsed_layers: Vec<Layer>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub bytes_per_sec: u64,
    pub packets_per_sec: u64,
    pub protocol_breakdown: HashMap<String, u64>,
    pub top_talkers: Vec<(String, u64)>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            bytes_per_sec: 0,
            packets_per_sec: 0,
            protocol_breakdown: HashMap::new(),
            top_talkers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub is_loopback: bool,
}
```

- [ ] **Step 2: Add module declaration to `src-tauri/src/lib.rs`**

Add at the top of `lib.rs`:

```rust
pub mod models;
```

- [ ] **Step 3: Verify it compiles**

```bash
cd src-tauri && cargo check
```

Expected: Compiles without errors.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/models.rs src-tauri/src/lib.rs
git commit -m "feat: add Rust data model — Protocol, Layer, Packet, Stats, NetworkInterface"
```

---

## Task 3: Packet Parser

**Files:**
- Create: `src-tauri/src/parser.rs`
- Modify: `src-tauri/src/lib.rs` (add module)

- [ ] **Step 1: Create `src-tauri/src/parser.rs`**

```rust
use crate::models::{Layer, Packet, Protocol};
use chrono::Utc;
use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EtherTypes, EthernetPacket},
    icmp::IcmpPacket,
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet as PnetPacket,
};
use std::sync::atomic::{AtomicU64, Ordering};

static PACKET_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn reset_counter() {
    PACKET_COUNTER.store(0, Ordering::Relaxed);
}

pub fn parse_packet(raw: &[u8]) -> Option<Packet> {
    let ethernet = EthernetPacket::new(raw)?;
    let mut layers = Vec::new();
    let mut src_ip = String::new();
    let mut dst_ip = String::new();
    let mut src_port: Option<u16> = None;
    let mut dst_port: Option<u16> = None;
    let mut protocol = Protocol::Other("Ethernet".to_string());
    let mut summary = String::new();

    // Ethernet layer
    layers.push(Layer {
        name: "Ethernet".to_string(),
        fields: vec![
            ("Source MAC".to_string(), ethernet.get_source().to_string()),
            ("Dest MAC".to_string(), ethernet.get_destination().to_string()),
            ("EtherType".to_string(), format!("{:?}", ethernet.get_ethertype())),
        ],
    });

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                src_ip = ipv4.get_source().to_string();
                dst_ip = ipv4.get_destination().to_string();

                layers.push(Layer {
                    name: "IPv4".to_string(),
                    fields: vec![
                        ("Source".to_string(), src_ip.clone()),
                        ("Destination".to_string(), dst_ip.clone()),
                        ("TTL".to_string(), ipv4.get_ttl().to_string()),
                        ("Protocol".to_string(), format!("{:?}", ipv4.get_next_level_protocol())),
                    ],
                });

                parse_transport(
                    ipv4.get_next_level_protocol(),
                    ipv4.payload(),
                    &src_ip,
                    &dst_ip,
                    &mut layers,
                    &mut src_port,
                    &mut dst_port,
                    &mut protocol,
                    &mut summary,
                );
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                src_ip = ipv6.get_source().to_string();
                dst_ip = ipv6.get_destination().to_string();

                layers.push(Layer {
                    name: "IPv6".to_string(),
                    fields: vec![
                        ("Source".to_string(), src_ip.clone()),
                        ("Destination".to_string(), dst_ip.clone()),
                        ("Hop Limit".to_string(), ipv6.get_hop_limit().to_string()),
                        ("Next Header".to_string(), format!("{:?}", ipv6.get_next_header())),
                    ],
                });

                parse_transport(
                    ipv6.get_next_header(),
                    ipv6.payload(),
                    &src_ip,
                    &dst_ip,
                    &mut layers,
                    &mut src_port,
                    &mut dst_port,
                    &mut protocol,
                    &mut summary,
                );
            }
        }
        EtherTypes::Arp => {
            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                protocol = Protocol::ARP;
                src_ip = format!("{}.{}.{}.{}", arp.get_sender_proto_addr()[0], arp.get_sender_proto_addr()[1], arp.get_sender_proto_addr()[2], arp.get_sender_proto_addr()[3]);
                dst_ip = format!("{}.{}.{}.{}", arp.get_target_proto_addr()[0], arp.get_target_proto_addr()[1], arp.get_target_proto_addr()[2], arp.get_target_proto_addr()[3]);

                layers.push(Layer {
                    name: "ARP".to_string(),
                    fields: vec![
                        ("Operation".to_string(), format!("{:?}", arp.get_operation())),
                        ("Sender MAC".to_string(), arp.get_sender_hw_addr().to_string()),
                        ("Sender IP".to_string(), src_ip.clone()),
                        ("Target MAC".to_string(), arp.get_target_hw_addr().to_string()),
                        ("Target IP".to_string(), dst_ip.clone()),
                    ],
                });
                summary = format!("ARP {} -> {}", src_ip, dst_ip);
            }
        }
        _ => {
            summary = format!("Unknown EtherType: {:?}", ethernet.get_ethertype());
        }
    }

    if summary.is_empty() {
        summary = format!("{} {} -> {}", protocol, src_ip, dst_ip);
    }

    let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);

    Some(Packet {
        id,
        timestamp: Utc::now(),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        length: raw.len() as u32,
        raw_bytes: raw.to_vec(),
        parsed_layers: layers,
        summary,
    })
}

fn parse_transport(
    next_proto: pnet::packet::ip::IpNextHeaderProtocol,
    payload: &[u8],
    src_ip: &str,
    dst_ip: &str,
    layers: &mut Vec<Layer>,
    src_port: &mut Option<u16>,
    dst_port: &mut Option<u16>,
    protocol: &mut Protocol,
    summary: &mut String,
) {
    match next_proto {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(payload) {
                *src_port = Some(tcp.get_source());
                *dst_port = Some(tcp.get_destination());

                let flags = format_tcp_flags(&tcp);

                // Detect HTTP/HTTPS by port
                *protocol = match (tcp.get_source(), tcp.get_destination()) {
                    (80, _) | (_, 80) | (8080, _) | (_, 8080) => Protocol::HTTP,
                    (443, _) | (_, 443) => Protocol::HTTPS,
                    _ => Protocol::TCP,
                };

                layers.push(Layer {
                    name: "TCP".to_string(),
                    fields: vec![
                        ("Source Port".to_string(), tcp.get_source().to_string()),
                        ("Dest Port".to_string(), tcp.get_destination().to_string()),
                        ("Flags".to_string(), flags.clone()),
                        ("Seq".to_string(), tcp.get_sequence().to_string()),
                        ("Ack".to_string(), tcp.get_acknowledgement().to_string()),
                        ("Window".to_string(), tcp.get_window().to_string()),
                    ],
                });

                *summary = format!(
                    "{} {}:{} -> {}:{} [{}]",
                    protocol, src_ip, tcp.get_source(), dst_ip, tcp.get_destination(), flags
                );

                // Parse DNS over TCP port 53
                if tcp.get_source() == 53 || tcp.get_destination() == 53 {
                    *protocol = Protocol::DNS;
                    *summary = format!("DNS (TCP) {}:{} -> {}:{}", src_ip, tcp.get_source(), dst_ip, tcp.get_destination());
                }
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(payload) {
                *src_port = Some(udp.get_source());
                *dst_port = Some(udp.get_destination());

                *protocol = if udp.get_source() == 53 || udp.get_destination() == 53 {
                    Protocol::DNS
                } else {
                    Protocol::UDP
                };

                layers.push(Layer {
                    name: "UDP".to_string(),
                    fields: vec![
                        ("Source Port".to_string(), udp.get_source().to_string()),
                        ("Dest Port".to_string(), udp.get_destination().to_string()),
                        ("Length".to_string(), udp.get_length().to_string()),
                    ],
                });

                *summary = format!(
                    "{} {}:{} -> {}:{}",
                    protocol, src_ip, udp.get_source(), dst_ip, udp.get_destination()
                );
            }
        }
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp) = IcmpPacket::new(payload) {
                *protocol = Protocol::ICMP;

                layers.push(Layer {
                    name: "ICMP".to_string(),
                    fields: vec![
                        ("Type".to_string(), format!("{:?}", icmp.get_icmp_type())),
                        ("Code".to_string(), format!("{:?}", icmp.get_icmp_code())),
                    ],
                });

                *summary = format!("ICMP {} -> {} type={:?}", src_ip, dst_ip, icmp.get_icmp_type());
            }
        }
        _ => {
            *protocol = Protocol::Other(format!("{:?}", next_proto));
            *summary = format!("{:?} {} -> {}", next_proto, src_ip, dst_ip);
        }
    }
}

fn format_tcp_flags(tcp: &TcpPacket) -> String {
    let mut flags = Vec::new();
    let f = tcp.get_flags();
    if f & 0x02 != 0 { flags.push("SYN"); }
    if f & 0x10 != 0 { flags.push("ACK"); }
    if f & 0x01 != 0 { flags.push("FIN"); }
    if f & 0x04 != 0 { flags.push("RST"); }
    if f & 0x08 != 0 { flags.push("PSH"); }
    if f & 0x20 != 0 { flags.push("URG"); }
    flags.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tcp_packet() -> Vec<u8> {
        // Minimal Ethernet + IPv4 + TCP packet
        let mut pkt = vec![0u8; 54];
        // Ethernet: dst MAC (6), src MAC (6), EtherType 0x0800 (IPv4)
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        // IPv4: version=4, IHL=5, total_length=40, protocol=6 (TCP)
        pkt[14] = 0x45; // version + IHL
        pkt[16] = 0x00; pkt[17] = 0x28; // total length = 40
        pkt[22] = 64; // TTL
        pkt[23] = 6; // protocol = TCP
        // src IP: 192.168.1.1
        pkt[26] = 192; pkt[27] = 168; pkt[28] = 1; pkt[29] = 1;
        // dst IP: 10.0.0.1
        pkt[30] = 10; pkt[31] = 0; pkt[32] = 0; pkt[33] = 1;
        // TCP: src port 12345 (0x3039), dst port 80 (0x0050)
        pkt[34] = 0x30; pkt[35] = 0x39; // src port
        pkt[36] = 0x00; pkt[37] = 0x50; // dst port
        // TCP data offset (5 = 20 bytes header) at byte 46, upper 4 bits
        pkt[46] = 0x50;
        // TCP flags at byte 47: SYN = 0x02
        pkt[47] = 0x02;
        pkt
    }

    #[test]
    fn test_parse_tcp_packet() {
        let raw = build_tcp_packet();
        let packet = parse_packet(&raw).unwrap();
        assert_eq!(packet.src_ip, "192.168.1.1");
        assert_eq!(packet.dst_ip, "10.0.0.1");
        assert_eq!(packet.src_port, Some(12345));
        assert_eq!(packet.dst_port, Some(80));
        assert_eq!(packet.protocol, Protocol::HTTP); // port 80
        assert_eq!(packet.length, 54);
        assert!(packet.parsed_layers.len() >= 3); // Ethernet, IPv4, TCP
    }

    #[test]
    fn test_parse_returns_none_for_empty() {
        assert!(parse_packet(&[]).is_none());
    }

    #[test]
    fn test_parse_returns_none_for_too_short() {
        assert!(parse_packet(&[0x00; 10]).is_none());
    }

    fn build_udp_dns_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 42];
        // Ethernet
        pkt[12] = 0x08; pkt[13] = 0x00;
        // IPv4
        pkt[14] = 0x45;
        pkt[16] = 0x00; pkt[17] = 0x1c; // total length = 28
        pkt[22] = 64; // TTL
        pkt[23] = 17; // protocol = UDP
        // src/dst IP
        pkt[26] = 192; pkt[27] = 168; pkt[28] = 1; pkt[29] = 100;
        pkt[30] = 8; pkt[31] = 8; pkt[32] = 8; pkt[33] = 8;
        // UDP: src port 54321, dst port 53 (DNS)
        pkt[34] = 0xd4; pkt[35] = 0x31; // 54321
        pkt[36] = 0x00; pkt[37] = 0x35; // 53
        pkt[38] = 0x00; pkt[39] = 0x08; // length
        pkt
    }

    #[test]
    fn test_parse_udp_dns_packet() {
        let raw = build_udp_dns_packet();
        let packet = parse_packet(&raw).unwrap();
        assert_eq!(packet.protocol, Protocol::DNS);
        assert_eq!(packet.dst_ip, "8.8.8.8");
        assert_eq!(packet.dst_port, Some(53));
    }

    fn build_arp_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 42];
        // Ethernet: EtherType 0x0806 (ARP)
        pkt[12] = 0x08; pkt[13] = 0x06;
        // ARP: hardware type 1, protocol type 0x0800, hw size 6, proto size 4
        pkt[14] = 0x00; pkt[15] = 0x01; // hw type
        pkt[16] = 0x08; pkt[17] = 0x00; // proto type
        pkt[18] = 6; // hw size
        pkt[19] = 4; // proto size
        pkt[20] = 0x00; pkt[21] = 0x01; // operation: request
        // Sender IP at offset 28-31
        pkt[28] = 192; pkt[29] = 168; pkt[30] = 1; pkt[31] = 1;
        // Target IP at offset 38-41
        pkt[38] = 192; pkt[39] = 168; pkt[40] = 1; pkt[41] = 2;
        pkt
    }

    #[test]
    fn test_parse_arp_packet() {
        let raw = build_arp_packet();
        let packet = parse_packet(&raw).unwrap();
        assert_eq!(packet.protocol, Protocol::ARP);
        assert_eq!(packet.src_ip, "192.168.1.1");
        assert_eq!(packet.dst_ip, "192.168.1.2");
    }
}
```

- [ ] **Step 2: Add module to `src-tauri/src/lib.rs`**

Add to the module declarations:

```rust
pub mod parser;
```

- [ ] **Step 3: Run the tests**

```bash
cd src-tauri && cargo test
```

Expected: All 4 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/parser.rs src-tauri/src/lib.rs
git commit -m "feat: add packet parser with Ethernet/IPv4/IPv6/TCP/UDP/ICMP/ARP/DNS support"
```

---

## Task 4: Stats Aggregator

**Files:**
- Create: `src-tauri/src/stats.rs`
- Modify: `src-tauri/src/lib.rs` (add module)

- [ ] **Step 1: Create `src-tauri/src/stats.rs`**

```rust
use crate::models::{Packet, Stats};
use std::collections::HashMap;

pub struct StatsAggregator {
    bytes_window: Vec<u64>,
    packets_window: Vec<u64>,
    protocol_counts: HashMap<String, u64>,
    ip_bytes: HashMap<String, u64>,
    current_bytes: u64,
    current_packets: u64,
}

impl StatsAggregator {
    pub fn new() -> Self {
        Self {
            bytes_window: Vec::new(),
            packets_window: Vec::new(),
            protocol_counts: HashMap::new(),
            ip_bytes: HashMap::new(),
            current_bytes: 0,
            current_packets: 0,
        }
    }

    pub fn record_packet(&mut self, packet: &Packet) {
        self.current_bytes += packet.length as u64;
        self.current_packets += 1;

        let proto_name = packet.protocol.to_string();
        *self.protocol_counts.entry(proto_name).or_insert(0) += 1;

        if !packet.src_ip.is_empty() {
            *self.ip_bytes.entry(packet.src_ip.clone()).or_insert(0) += packet.length as u64;
        }
        if !packet.dst_ip.is_empty() {
            *self.ip_bytes.entry(packet.dst_ip.clone()).or_insert(0) += packet.length as u64;
        }
    }

    /// Call once per second to produce a Stats snapshot and roll the window.
    pub fn tick(&mut self) -> Stats {
        self.bytes_window.push(self.current_bytes);
        self.packets_window.push(self.current_packets);

        // Keep last 60 seconds
        if self.bytes_window.len() > 60 {
            self.bytes_window.remove(0);
        }
        if self.packets_window.len() > 60 {
            self.packets_window.remove(0);
        }

        let bytes_per_sec = self.current_bytes;
        let packets_per_sec = self.current_packets;

        // Top talkers: sort by bytes, take top 10
        let mut top_talkers: Vec<(String, u64)> = self.ip_bytes.iter()
            .map(|(ip, bytes)| (ip.clone(), *bytes))
            .collect();
        top_talkers.sort_by(|a, b| b.1.cmp(&a.1));
        top_talkers.truncate(10);

        let stats = Stats {
            bytes_per_sec,
            packets_per_sec,
            protocol_breakdown: self.protocol_counts.clone(),
            top_talkers,
        };

        // Reset per-second counters
        self.current_bytes = 0;
        self.current_packets = 0;

        stats
    }

    pub fn reset(&mut self) {
        self.bytes_window.clear();
        self.packets_window.clear();
        self.protocol_counts.clear();
        self.ip_bytes.clear();
        self.current_bytes = 0;
        self.current_packets = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;
    use chrono::Utc;

    fn make_packet(src_ip: &str, dst_ip: &str, protocol: Protocol, length: u32) -> Packet {
        Packet {
            id: 0,
            timestamp: Utc::now(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port: None,
            dst_port: None,
            protocol,
            length,
            raw_bytes: vec![],
            parsed_layers: vec![],
            summary: String::new(),
        }
    }

    #[test]
    fn test_record_and_tick() {
        let mut agg = StatsAggregator::new();
        agg.record_packet(&make_packet("1.1.1.1", "2.2.2.2", Protocol::TCP, 100));
        agg.record_packet(&make_packet("1.1.1.1", "3.3.3.3", Protocol::UDP, 200));

        let stats = agg.tick();
        assert_eq!(stats.bytes_per_sec, 300);
        assert_eq!(stats.packets_per_sec, 2);
        assert_eq!(stats.protocol_breakdown.get("TCP"), Some(&1));
        assert_eq!(stats.protocol_breakdown.get("UDP"), Some(&1));
    }

    #[test]
    fn test_tick_resets_per_second_counters() {
        let mut agg = StatsAggregator::new();
        agg.record_packet(&make_packet("1.1.1.1", "2.2.2.2", Protocol::TCP, 100));
        agg.tick();

        let stats = agg.tick();
        assert_eq!(stats.bytes_per_sec, 0);
        assert_eq!(stats.packets_per_sec, 0);
    }

    #[test]
    fn test_top_talkers_sorted() {
        let mut agg = StatsAggregator::new();
        agg.record_packet(&make_packet("1.1.1.1", "2.2.2.2", Protocol::TCP, 100));
        agg.record_packet(&make_packet("3.3.3.3", "2.2.2.2", Protocol::TCP, 500));

        let stats = agg.tick();
        // 2.2.2.2 has 600 bytes (dst of both), 3.3.3.3 has 500, 1.1.1.1 has 100
        assert_eq!(stats.top_talkers[0].0, "2.2.2.2");
    }

    #[test]
    fn test_reset_clears_everything() {
        let mut agg = StatsAggregator::new();
        agg.record_packet(&make_packet("1.1.1.1", "2.2.2.2", Protocol::TCP, 100));
        agg.reset();

        let stats = agg.tick();
        assert_eq!(stats.bytes_per_sec, 0);
        assert!(stats.top_talkers.is_empty());
    }
}
```

- [ ] **Step 2: Add module to `src-tauri/src/lib.rs`**

```rust
pub mod stats;
```

- [ ] **Step 3: Run tests**

```bash
cd src-tauri && cargo test
```

Expected: All tests pass (parser + stats).

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/stats.rs src-tauri/src/lib.rs
git commit -m "feat: add stats aggregator with rolling bandwidth, protocol breakdown, top talkers"
```

---

## Task 5: Capture Module

**Files:**
- Create: `src-tauri/src/capture.rs`
- Modify: `src-tauri/src/lib.rs` (add module)

- [ ] **Step 1: Create `src-tauri/src/capture.rs`**

```rust
use crate::models::NetworkInterface;
use crate::parser;
use crate::stats::StatsAggregator;
use pcap::{Capture, Device};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use tauri::{AppHandle, Emitter};
use tokio::time::{interval, Duration};

pub struct CaptureState {
    pub is_capturing: AtomicBool,
    pub packets_dropped: AtomicU64,
    pub stats_aggregator: Mutex<StatsAggregator>,
}

impl CaptureState {
    pub fn new() -> Self {
        Self {
            is_capturing: AtomicBool::new(false),
            packets_dropped: AtomicU64::new(0),
            stats_aggregator: Mutex::new(StatsAggregator::new()),
        }
    }
}

pub fn list_interfaces() -> Vec<NetworkInterface> {
    Device::list()
        .unwrap_or_default()
        .into_iter()
        .map(|d| NetworkInterface {
            name: d.name.clone(),
            description: d.desc.unwrap_or_else(|| d.name.clone()),
            is_loopback: d.flags.is_loopback(),
        })
        .collect()
}

pub fn check_permissions() -> bool {
    // Try to open any device briefly to check BPF access
    if let Some(device) = Device::list().ok().and_then(|d| d.into_iter().next()) {
        Capture::from_device(device)
            .and_then(|c| c.open())
            .is_ok()
    } else {
        false
    }
}

pub fn start_capture(
    app: AppHandle,
    state: Arc<CaptureState>,
    interface_name: String,
    bpf_filter: Option<String>,
) -> Result<(), String> {
    if state.is_capturing.load(Ordering::Relaxed) {
        return Err("Capture already running".to_string());
    }

    let device = Device::list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| format!("Interface '{}' not found", interface_name))?;

    let mut cap = Capture::from_device(device)
        .map_err(|e| e.to_string())?
        .promisc(true)
        .snaplen(65535)
        .timeout(100) // 100ms read timeout so we can check stop flag
        .open()
        .map_err(|e| e.to_string())?;

    if let Some(filter) = bpf_filter {
        if !filter.trim().is_empty() {
            cap.filter(&filter, true).map_err(|e| e.to_string())?;
        }
    }

    state.is_capturing.store(true, Ordering::Relaxed);
    state.packets_dropped.store(0, Ordering::Relaxed);
    parser::reset_counter();

    if let Ok(mut agg) = state.stats_aggregator.lock() {
        agg.reset();
    }

    let capture_state = Arc::clone(&state);
    let app_clone = app.clone();

    // Capture thread
    std::thread::spawn(move || {
        while capture_state.is_capturing.load(Ordering::Relaxed) {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(parsed) = parser::parse_packet(packet.data) {
                        // Record in stats
                        if let Ok(mut agg) = capture_state.stats_aggregator.lock() {
                            agg.record_packet(&parsed);
                        }
                        // Emit to frontend
                        let _ = app_clone.emit("packet", &parsed);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal — just loop and check stop flag
                    continue;
                }
                Err(_) => {
                    // Interface error — stop capture
                    capture_state.is_capturing.store(false, Ordering::Relaxed);
                    let _ = app_clone.emit("capture-error", "Interface error — capture stopped");
                    break;
                }
            }
        }
    });

    // Stats emission thread (every 1 second)
    let stats_state = Arc::clone(&state);
    let stats_app = app.clone();
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(1));
        while stats_state.is_capturing.load(Ordering::Relaxed) {
            tick.tick().await;
            if let Ok(mut agg) = stats_state.stats_aggregator.lock() {
                let stats = agg.tick();
                let _ = stats_app.emit("stats", &stats);
            }
        }
    });

    Ok(())
}

pub fn stop_capture(state: &CaptureState) {
    state.is_capturing.store(false, Ordering::Relaxed);
}
```

- [ ] **Step 2: Add module to `src-tauri/src/lib.rs`**

```rust
pub mod capture;
```

- [ ] **Step 3: Verify it compiles**

```bash
cd src-tauri && cargo check
```

Expected: Compiles without errors.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/capture.rs src-tauri/src/lib.rs
git commit -m "feat: add capture module with pcap interface, BPF filtering, stats emission"
```

---

## Task 6: Tauri Commands & App Setup

**Files:**
- Create: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/lib.rs` (wire up commands and state)
- Modify: `src-tauri/src/main.rs` (if needed)

- [ ] **Step 1: Create `src-tauri/src/commands.rs`**

```rust
use crate::capture::{self, CaptureState};
use crate::models::NetworkInterface;
use std::sync::Arc;
use tauri::{AppHandle, State};

#[tauri::command]
pub fn list_interfaces() -> Vec<NetworkInterface> {
    capture::list_interfaces()
}

#[tauri::command]
pub fn check_permissions() -> bool {
    capture::check_permissions()
}

#[tauri::command]
pub fn start_capture(
    app: AppHandle,
    state: State<'_, Arc<CaptureState>>,
    interface_name: String,
    bpf_filter: Option<String>,
) -> Result<(), String> {
    capture::start_capture(app, Arc::clone(&state), interface_name, bpf_filter)
}

#[tauri::command]
pub fn stop_capture(state: State<'_, Arc<CaptureState>>) -> Result<(), String> {
    capture::stop_capture(&state);
    Ok(())
}

#[tauri::command]
pub fn is_capturing(state: State<'_, Arc<CaptureState>>) -> bool {
    state.is_capturing.load(std::sync::atomic::Ordering::Relaxed)
}
```

- [ ] **Step 2: Update `src-tauri/src/lib.rs` with full app setup**

Replace the contents of `lib.rs` with:

```rust
pub mod capture;
pub mod commands;
pub mod models;
pub mod parser;
pub mod stats;

use capture::CaptureState;
use std::sync::Arc;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Arc::new(CaptureState::new()))
        .invoke_handler(tauri::generate_handler![
            commands::list_interfaces,
            commands::check_permissions,
            commands::start_capture,
            commands::stop_capture,
            commands::is_capturing,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Step 3: Ensure `src-tauri/src/main.rs` calls `run()`**

The file should contain:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    wirehound_lib::run();
}
```

Note: The library name depends on what `create-tauri-app` generated in `Cargo.toml` under `[lib] name = "..."`. Check this value and use it. It may be `wirehound_lib` or `app_lib` — adjust accordingly.

- [ ] **Step 4: Verify compilation**

```bash
cd src-tauri && cargo check
```

Expected: Compiles without errors.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/commands.rs src-tauri/src/lib.rs src-tauri/src/main.rs
git commit -m "feat: add Tauri IPC commands and wire up app state"
```

---

## Task 7: Svelte Stores

**Files:**
- Create: `src/lib/stores/packets.ts`
- Create: `src/lib/stores/stats.ts`
- Create: `src/lib/stores/capture.ts`

- [ ] **Step 1: Create `src/lib/stores/packets.ts`**

```typescript
import { writable } from 'svelte/store';

export interface Layer {
  name: string;
  fields: [string, string][];
}

export interface Packet {
  id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | { Other: string };
  length: number;
  raw_bytes: number[];
  parsed_layers: Layer[];
  summary: string;
}

const MAX_PACKETS = 10000;

function createPacketStore() {
  const { subscribe, update, set } = writable<Packet[]>([]);

  return {
    subscribe,
    add(packet: Packet) {
      update(packets => {
        const next = [...packets, packet];
        if (next.length > MAX_PACKETS) {
          return next.slice(next.length - MAX_PACKETS);
        }
        return next;
      });
    },
    clear() {
      set([]);
    },
  };
}

export const packets = createPacketStore();
export const selectedPacket = writable<Packet | null>(null);
```

- [ ] **Step 2: Create `src/lib/stores/stats.ts`**

```typescript
import { writable } from 'svelte/store';

export interface Stats {
  bytes_per_sec: number;
  packets_per_sec: number;
  protocol_breakdown: Record<string, number>;
  top_talkers: [string, number][];
}

export const stats = writable<Stats>({
  bytes_per_sec: 0,
  packets_per_sec: 0,
  protocol_breakdown: {},
  top_talkers: [],
});

// Rolling history for the bandwidth chart (last 60 seconds)
function createBandwidthHistory() {
  const { subscribe, update } = writable<number[]>([]);

  return {
    subscribe,
    push(bytesPerSec: number) {
      update(history => {
        const next = [...history, bytesPerSec];
        if (next.length > 60) {
          return next.slice(next.length - 60);
        }
        return next;
      });
    },
    reset() {
      // Use update to clear
      update(() => []);
    },
  };
}

export const bandwidthHistory = createBandwidthHistory();
```

- [ ] **Step 3: Create `src/lib/stores/capture.ts`**

```typescript
import { writable } from 'svelte/store';

export interface NetworkInterface {
  name: string;
  description: string;
  is_loopback: boolean;
}

export const interfaces = writable<NetworkInterface[]>([]);
export const selectedInterface = writable<string>('');
export const bpfFilter = writable<string>('');
export const isCapturing = writable<boolean>(false);
export const hasPermission = writable<boolean | null>(null); // null = not checked yet
export const displayFilter = writable<string>('');
```

- [ ] **Step 4: Create store directories**

```bash
mkdir -p src/lib/stores src/lib/components
```

- [ ] **Step 5: Commit**

```bash
git add src/lib/stores/
git commit -m "feat: add Svelte stores for packets, stats, and capture state"
```

---

## Task 8: Permission Check Component

**Files:**
- Create: `src/lib/components/PermissionCheck.svelte`

- [ ] **Step 1: Create `src/lib/components/PermissionCheck.svelte`**

```svelte
<script>
  import { invoke } from '@tauri-apps/api/core';
  import { hasPermission } from '../stores/capture.ts';

  let checking = $state(false);

  async function checkAccess() {
    checking = true;
    try {
      const result = await invoke('check_permissions');
      hasPermission.set(result);
    } catch (e) {
      hasPermission.set(false);
    }
    checking = false;
  }

  // Check on mount
  checkAccess();
</script>

<div class="permission-screen">
  <div class="permission-card">
    <h1>Wirehound</h1>
    <h2>Network Access Required</h2>
    <p>Wirehound needs access to your network interfaces to capture packets.</p>

    <div class="instructions">
      <h3>Setup Instructions (one-time)</h3>
      <ol>
        <li>Open Terminal</li>
        <li>Run: <code>sudo chmod o+r /dev/bpf*</code></li>
        <li>
          For permanent access, create a startup script or use:
          <code>sudo dscl . -create /Groups/access_bpf</code><br />
          <code>sudo dscl . -append /Groups/access_bpf GroupMembership $(whoami)</code>
        </li>
      </ol>
      <p class="note">You may need to restart the app after granting access.</p>
    </div>

    <button onclick={checkAccess} disabled={checking}>
      {checking ? 'Checking...' : 'Check Again'}
    </button>
  </div>
</div>

<style>
  .permission-screen {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
    background: #0a0a0f;
    color: #e0e0e0;
    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
  }

  .permission-card {
    max-width: 500px;
    padding: 2rem;
    background: #1a1a2e;
    border-radius: 12px;
    border: 1px solid #2a2a4a;
  }

  h1 {
    margin: 0 0 0.5rem;
    font-size: 1.5rem;
    color: #00d4ff;
  }

  h2 {
    margin: 0 0 1rem;
    font-size: 1.1rem;
    font-weight: normal;
    color: #ff6b6b;
  }

  .instructions {
    background: #0d0d1a;
    padding: 1rem;
    border-radius: 8px;
    margin: 1rem 0;
  }

  h3 {
    margin: 0 0 0.5rem;
    font-size: 0.9rem;
    color: #aaa;
  }

  ol {
    margin: 0;
    padding-left: 1.5rem;
  }

  li {
    margin-bottom: 0.5rem;
    line-height: 1.5;
  }

  code {
    background: #2a2a4a;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.85rem;
    color: #00d4ff;
  }

  .note {
    font-size: 0.85rem;
    color: #888;
    margin-top: 0.5rem;
  }

  button {
    width: 100%;
    padding: 0.75rem;
    background: #00d4ff;
    color: #0a0a0f;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
  }

  button:hover {
    background: #00b8e6;
  }

  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/PermissionCheck.svelte
git commit -m "feat: add permission check screen with BPF setup instructions"
```

---

## Task 9: Toolbar Component

**Files:**
- Create: `src/lib/components/Toolbar.svelte`

- [ ] **Step 1: Create `src/lib/components/Toolbar.svelte`**

```svelte
<script>
  import { invoke } from '@tauri-apps/api/core';
  import {
    interfaces,
    selectedInterface,
    bpfFilter,
    isCapturing,
    displayFilter,
  } from '../stores/capture.ts';
  import { packets } from '../stores/packets.ts';

  let packetCount = $state(0);
  let filterError = $state('');

  packets.subscribe(p => packetCount = p.length);

  async function loadInterfaces() {
    try {
      const result = await invoke('list_interfaces');
      interfaces.set(result);
      if (result.length > 0) {
        // Default to first non-loopback interface
        const nonLoopback = result.find(i => !i.is_loopback);
        selectedInterface.set(nonLoopback ? nonLoopback.name : result[0].name);
      }
    } catch (e) {
      console.error('Failed to list interfaces:', e);
    }
  }

  async function toggleCapture() {
    let capturing;
    isCapturing.subscribe(v => capturing = v)();

    if (capturing) {
      await invoke('stop_capture');
      isCapturing.set(false);
    } else {
      filterError = '';
      let iface, filter;
      selectedInterface.subscribe(v => iface = v)();
      bpfFilter.subscribe(v => filter = v)();

      try {
        await invoke('start_capture', {
          interfaceName: iface,
          bpfFilter: filter || null,
        });
        isCapturing.set(true);
      } catch (e) {
        filterError = String(e);
      }
    }
  }

  function clearPackets() {
    packets.clear();
  }

  // Load interfaces on mount
  loadInterfaces();
</script>

<div class="toolbar">
  <div class="toolbar-left">
    <select
      onchange={(e) => selectedInterface.set(e.target.value)}
      disabled={$isCapturing}
    >
      {#each $interfaces as iface}
        <option value={iface.name} selected={iface.name === $selectedInterface}>
          {iface.description || iface.name}
          {iface.is_loopback ? ' (loopback)' : ''}
        </option>
      {/each}
    </select>

    <input
      type="text"
      placeholder="BPF filter (e.g. tcp port 80)"
      bind:value={$bpfFilter}
      disabled={$isCapturing}
      class:error={filterError}
    />

    {#if filterError}
      <span class="filter-error">{filterError}</span>
    {/if}
  </div>

  <div class="toolbar-center">
    <input
      type="text"
      placeholder="Display filter..."
      bind:value={$displayFilter}
    />
  </div>

  <div class="toolbar-right">
    <span class="packet-count">{packetCount.toLocaleString()} packets</span>

    <button class="btn-capture" class:capturing={$isCapturing} onclick={toggleCapture}>
      {$isCapturing ? 'Stop' : 'Start'}
    </button>

    <button class="btn-clear" onclick={clearPackets} disabled={$isCapturing}>
      Clear
    </button>
  </div>
</div>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    background: #1a1a2e;
    border-bottom: 1px solid #2a2a4a;
  }

  .toolbar-left {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-shrink: 0;
  }

  .toolbar-center {
    flex: 1;
  }

  .toolbar-center input {
    width: 100%;
  }

  .toolbar-right {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-shrink: 0;
  }

  select, input {
    background: #0d0d1a;
    border: 1px solid #2a2a4a;
    color: #e0e0e0;
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
    font-size: 0.85rem;
  }

  select {
    min-width: 160px;
  }

  input.error {
    border-color: #ff6b6b;
  }

  .filter-error {
    color: #ff6b6b;
    font-size: 0.75rem;
  }

  .packet-count {
    font-size: 0.85rem;
    color: #888;
    white-space: nowrap;
  }

  button {
    padding: 0.4rem 1rem;
    border: none;
    border-radius: 4px;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
  }

  .btn-capture {
    background: #00d4ff;
    color: #0a0a0f;
  }

  .btn-capture.capturing {
    background: #ff6b6b;
    color: #fff;
  }

  .btn-clear {
    background: #2a2a4a;
    color: #e0e0e0;
  }

  .btn-clear:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/Toolbar.svelte
git commit -m "feat: add toolbar with interface selector, BPF filter, display filter, controls"
```

---

## Task 10: Packet List Component (Virtualized)

**Files:**
- Create: `src/lib/components/PacketList.svelte`

- [ ] **Step 1: Create `src/lib/components/PacketList.svelte`**

```svelte
<script>
  import { packets, selectedPacket } from '../stores/packets.ts';
  import { displayFilter } from '../stores/capture.ts';

  let container = $state(null);
  let scrollTop = $state(0);
  let containerHeight = $state(600);
  const ROW_HEIGHT = 28;

  let filteredPackets = $derived.by(() => {
    const filter = $displayFilter.toLowerCase().trim();
    if (!filter) return $packets;
    return $packets.filter(p =>
      p.src_ip.toLowerCase().includes(filter) ||
      p.dst_ip.toLowerCase().includes(filter) ||
      p.summary.toLowerCase().includes(filter) ||
      formatProtocol(p.protocol).toLowerCase().includes(filter)
    );
  });

  let totalHeight = $derived(filteredPackets.length * ROW_HEIGHT);
  let startIndex = $derived(Math.floor(scrollTop / ROW_HEIGHT));
  let visibleCount = $derived(Math.ceil(containerHeight / ROW_HEIGHT) + 2);
  let visiblePackets = $derived(filteredPackets.slice(startIndex, startIndex + visibleCount));
  let offsetY = $derived(startIndex * ROW_HEIGHT);

  function formatProtocol(proto) {
    if (typeof proto === 'string') return proto;
    if (proto?.Other) return proto.Other;
    return 'Unknown';
  }

  function formatTime(timestamp) {
    const d = new Date(timestamp);
    return d.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      fractionalSecondDigits: 3,
    });
  }

  function selectPacket(packet) {
    selectedPacket.set(packet);
  }

  function handleScroll(e) {
    scrollTop = e.target.scrollTop;
  }

  function handleResize() {
    if (container) {
      containerHeight = container.clientHeight;
    }
  }

  $effect(() => {
    if (container) {
      containerHeight = container.clientHeight;
      const observer = new ResizeObserver(handleResize);
      observer.observe(container);
      return () => observer.disconnect();
    }
  });

  // Protocol color coding
  function protoColor(proto) {
    const name = formatProtocol(proto);
    const colors = {
      TCP: '#4fc3f7',
      UDP: '#81c784',
      DNS: '#ffb74d',
      HTTP: '#e57373',
      HTTPS: '#ba68c8',
      ICMP: '#fff176',
      ARP: '#90a4ae',
    };
    return colors[name] || '#e0e0e0';
  }
</script>

<div class="packet-list">
  <div class="header-row">
    <span class="col-id">#</span>
    <span class="col-time">Time</span>
    <span class="col-src">Source</span>
    <span class="col-dst">Destination</span>
    <span class="col-proto">Protocol</span>
    <span class="col-len">Length</span>
    <span class="col-summary">Info</span>
  </div>
  <div
    class="scroll-container"
    bind:this={container}
    onscroll={handleScroll}
  >
    <div class="scroll-spacer" style="height: {totalHeight}px">
      <div class="visible-rows" style="transform: translateY({offsetY}px)">
        {#each visiblePackets as packet (packet.id)}
          <div
            class="packet-row"
            class:selected={$selectedPacket?.id === packet.id}
            onclick={() => selectPacket(packet)}
          >
            <span class="col-id">{packet.id}</span>
            <span class="col-time">{formatTime(packet.timestamp)}</span>
            <span class="col-src">{packet.src_ip}{packet.src_port ? ':' + packet.src_port : ''}</span>
            <span class="col-dst">{packet.dst_ip}{packet.dst_port ? ':' + packet.dst_port : ''}</span>
            <span class="col-proto" style="color: {protoColor(packet.protocol)}">
              {formatProtocol(packet.protocol)}
            </span>
            <span class="col-len">{packet.length}</span>
            <span class="col-summary">{packet.summary}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
</div>

<style>
  .packet-list {
    display: flex;
    flex-direction: column;
    height: 100%;
    font-family: 'SF Mono', 'Menlo', monospace;
    font-size: 0.8rem;
  }

  .header-row {
    display: flex;
    padding: 0.3rem 0.5rem;
    background: #1a1a2e;
    border-bottom: 1px solid #2a2a4a;
    color: #888;
    font-weight: 600;
    flex-shrink: 0;
  }

  .scroll-container {
    flex: 1;
    overflow-y: auto;
  }

  .scroll-spacer {
    position: relative;
  }

  .visible-rows {
    position: absolute;
    width: 100%;
  }

  .packet-row {
    display: flex;
    padding: 0.2rem 0.5rem;
    height: 28px;
    align-items: center;
    cursor: pointer;
    border-bottom: 1px solid #1a1a2e;
  }

  .packet-row:hover {
    background: #1a1a2e;
  }

  .packet-row.selected {
    background: #2a2a4a;
  }

  .col-id { width: 60px; flex-shrink: 0; color: #666; }
  .col-time { width: 100px; flex-shrink: 0; }
  .col-src { width: 180px; flex-shrink: 0; }
  .col-dst { width: 180px; flex-shrink: 0; }
  .col-proto { width: 80px; flex-shrink: 0; font-weight: 600; }
  .col-len { width: 60px; flex-shrink: 0; color: #888; }
  .col-summary { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #aaa; }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/PacketList.svelte
git commit -m "feat: add virtualized packet list with display filtering and protocol color coding"
```

---

## Task 11: Packet Detail Component

**Files:**
- Create: `src/lib/components/PacketDetail.svelte`

- [ ] **Step 1: Create `src/lib/components/PacketDetail.svelte`**

```svelte
<script>
  import { selectedPacket } from '../stores/packets.ts';

  let expandedLayers = $state(new Set());

  function toggleLayer(name) {
    const next = new Set(expandedLayers);
    if (next.has(name)) {
      next.delete(name);
    } else {
      next.add(name);
    }
    expandedLayers = next;
  }

  function formatHex(bytes) {
    if (!bytes || bytes.length === 0) return '';
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const offset = i.toString(16).padStart(4, '0');
      const chunk = bytes.slice(i, i + 16);

      const hex = chunk
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');

      const ascii = chunk
        .map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.')
        .join('');

      lines.push(`${offset}  ${hex.padEnd(48)}  ${ascii}`);
    }
    return lines.join('\n');
  }

  // Expand all layers when a new packet is selected
  $effect(() => {
    if ($selectedPacket) {
      expandedLayers = new Set($selectedPacket.parsed_layers.map(l => l.name));
    }
  });
</script>

<div class="packet-detail">
  {#if $selectedPacket}
    <div class="layers">
      {#each $selectedPacket.parsed_layers as layer}
        <div class="layer">
          <div class="layer-header" onclick={() => toggleLayer(layer.name)}>
            <span class="toggle">{expandedLayers.has(layer.name) ? '\u25BE' : '\u25B8'}</span>
            <span class="layer-name">{layer.name}</span>
          </div>
          {#if expandedLayers.has(layer.name)}
            <div class="layer-fields">
              {#each layer.fields as [key, value]}
                <div class="field">
                  <span class="field-key">{key}:</span>
                  <span class="field-value">{value}</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>

    <div class="hex-dump">
      <div class="hex-header">Raw Data ({$selectedPacket.raw_bytes.length} bytes)</div>
      <pre>{formatHex($selectedPacket.raw_bytes)}</pre>
    </div>
  {:else}
    <div class="empty">Select a packet to view details</div>
  {/if}
</div>

<style>
  .packet-detail {
    display: flex;
    height: 100%;
    overflow: hidden;
    font-family: 'SF Mono', 'Menlo', monospace;
    font-size: 0.8rem;
  }

  .layers {
    flex: 1;
    overflow-y: auto;
    padding: 0.5rem;
    border-right: 1px solid #2a2a4a;
  }

  .layer {
    margin-bottom: 2px;
  }

  .layer-header {
    padding: 0.3rem 0.5rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    border-radius: 4px;
  }

  .layer-header:hover {
    background: #1a1a2e;
  }

  .toggle {
    color: #888;
    width: 12px;
  }

  .layer-name {
    font-weight: 600;
    color: #00d4ff;
  }

  .layer-fields {
    padding-left: 2rem;
  }

  .field {
    padding: 0.15rem 0;
    display: flex;
    gap: 0.5rem;
  }

  .field-key {
    color: #888;
    flex-shrink: 0;
  }

  .field-value {
    color: #e0e0e0;
  }

  .hex-dump {
    flex: 1;
    overflow-y: auto;
    padding: 0.5rem;
  }

  .hex-header {
    color: #888;
    margin-bottom: 0.5rem;
    font-weight: 600;
  }

  pre {
    margin: 0;
    color: #aaa;
    line-height: 1.4;
  }

  .empty {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    color: #555;
  }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add src/lib/components/PacketDetail.svelte
git commit -m "feat: add packet detail pane with expandable layers and hex dump"
```

---

## Task 12: Chart Components

**Files:**
- Create: `src/lib/components/BandwidthChart.svelte`
- Create: `src/lib/components/ProtocolChart.svelte`

- [ ] **Step 1: Create `src/lib/components/BandwidthChart.svelte`**

```svelte
<script>
  import { Chart, registerables } from 'chart.js';
  import { bandwidthHistory } from '../stores/stats.ts';

  Chart.register(...registerables);

  let canvas = $state(null);
  let chart = $state(null);

  $effect(() => {
    if (canvas && !chart) {
      chart = new Chart(canvas, {
        type: 'line',
        data: {
          labels: Array(60).fill(''),
          datasets: [{
            label: 'Bytes/sec',
            data: [],
            borderColor: '#00d4ff',
            backgroundColor: 'rgba(0, 212, 255, 0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 0,
            borderWidth: 2,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 0 },
          scales: {
            x: { display: false },
            y: {
              beginAtZero: true,
              ticks: { color: '#666', callback: (v) => formatBytes(v) },
              grid: { color: '#1a1a2e' },
            },
          },
          plugins: {
            legend: { display: false },
          },
        },
      });
    }
  });

  $effect(() => {
    if (chart) {
      const data = $bandwidthHistory;
      chart.data.labels = Array(Math.max(data.length, 60)).fill('');
      chart.data.datasets[0].data = data;
      chart.update();
    }
  });

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }
</script>

<div class="chart-container">
  <div class="chart-title">Bandwidth</div>
  <div class="chart-wrapper">
    <canvas bind:this={canvas}></canvas>
  </div>
</div>

<style>
  .chart-container {
    padding: 0.5rem;
  }

  .chart-title {
    font-size: 0.75rem;
    color: #888;
    font-weight: 600;
    margin-bottom: 0.25rem;
  }

  .chart-wrapper {
    height: 150px;
  }
</style>
```

- [ ] **Step 2: Create `src/lib/components/ProtocolChart.svelte`**

```svelte
<script>
  import { Chart, registerables } from 'chart.js';
  import { stats } from '../stores/stats.ts';

  Chart.register(...registerables);

  let canvas = $state(null);
  let chart = $state(null);

  const PROTOCOL_COLORS = {
    TCP: '#4fc3f7',
    UDP: '#81c784',
    DNS: '#ffb74d',
    HTTP: '#e57373',
    HTTPS: '#ba68c8',
    ICMP: '#fff176',
    ARP: '#90a4ae',
  };

  function getColor(proto) {
    return PROTOCOL_COLORS[proto] || '#e0e0e0';
  }

  $effect(() => {
    if (canvas && !chart) {
      chart = new Chart(canvas, {
        type: 'doughnut',
        data: {
          labels: [],
          datasets: [{
            data: [],
            backgroundColor: [],
            borderWidth: 0,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 0 },
          plugins: {
            legend: {
              position: 'right',
              labels: {
                color: '#888',
                font: { size: 11 },
                padding: 8,
              },
            },
          },
        },
      });
    }
  });

  $effect(() => {
    if (chart) {
      const breakdown = $stats.protocol_breakdown;
      const labels = Object.keys(breakdown);
      const data = Object.values(breakdown);
      const colors = labels.map(l => getColor(l));

      chart.data.labels = labels;
      chart.data.datasets[0].data = data;
      chart.data.datasets[0].backgroundColor = colors;
      chart.update();
    }
  });
</script>

<div class="chart-container">
  <div class="chart-title">Protocols</div>
  <div class="chart-wrapper">
    <canvas bind:this={canvas}></canvas>
  </div>
</div>

<style>
  .chart-container {
    padding: 0.5rem;
  }

  .chart-title {
    font-size: 0.75rem;
    color: #888;
    font-weight: 600;
    margin-bottom: 0.25rem;
  }

  .chart-wrapper {
    height: 180px;
  }
</style>
```

- [ ] **Step 3: Commit**

```bash
git add src/lib/components/BandwidthChart.svelte src/lib/components/ProtocolChart.svelte
git commit -m "feat: add bandwidth line chart and protocol donut chart"
```

---

## Task 13: Root App Component — Wire Everything Together

**Files:**
- Modify: `src/App.svelte`
- Modify: `src/app.css` (global styles)

- [ ] **Step 1: Replace `src/app.css` with global styles**

```css
:root {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  color: #e0e0e0;
  background-color: #0a0a0f;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  height: 100%;
  overflow: hidden;
}

#app {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: #0a0a0f;
}

::-webkit-scrollbar-thumb {
  background: #2a2a4a;
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: #3a3a5a;
}
```

- [ ] **Step 2: Replace `src/App.svelte`**

```svelte
<script>
  import { listen } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import { hasPermission } from './lib/stores/capture.ts';
  import { packets } from './lib/stores/packets.ts';
  import { stats, bandwidthHistory } from './lib/stores/stats.ts';
  import Toolbar from './lib/components/Toolbar.svelte';
  import PacketList from './lib/components/PacketList.svelte';
  import PacketDetail from './lib/components/PacketDetail.svelte';
  import BandwidthChart from './lib/components/BandwidthChart.svelte';
  import ProtocolChart from './lib/components/ProtocolChart.svelte';
  import PermissionCheck from './lib/components/PermissionCheck.svelte';
  import './app.css';

  let detailHeight = $state(250);
  let chartsWidth = $state(300);
  let resizingDetail = $state(false);
  let resizingCharts = $state(false);

  onMount(() => {
    // Listen for packet events from Rust backend
    const unlistenPacket = listen('packet', (event) => {
      packets.add(event.payload);
    });

    // Listen for stats events
    const unlistenStats = listen('stats', (event) => {
      stats.set(event.payload);
      bandwidthHistory.push(event.payload.bytes_per_sec);
    });

    // Listen for capture errors
    const unlistenError = listen('capture-error', (event) => {
      console.error('Capture error:', event.payload);
    });

    return () => {
      unlistenPacket.then(fn => fn());
      unlistenStats.then(fn => fn());
      unlistenError.then(fn => fn());
    };
  });

  function startResizeDetail(e) {
    resizingDetail = true;
    const startY = e.clientY;
    const startHeight = detailHeight;

    function onMove(e) {
      detailHeight = Math.max(100, Math.min(500, startHeight - (e.clientY - startY)));
    }
    function onUp() {
      resizingDetail = false;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }

  function startResizeCharts(e) {
    resizingCharts = true;
    const startX = e.clientX;
    const startWidth = chartsWidth;

    function onMove(e) {
      chartsWidth = Math.max(200, Math.min(600, startWidth - (e.clientX - startX)));
    }
    function onUp() {
      resizingCharts = false;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }
</script>

{#if $hasPermission === false}
  <PermissionCheck />
{:else}
  <div class="app-layout">
    <Toolbar />

    <div class="main-area">
      <div class="content-area">
        <div class="packet-list-area">
          <PacketList />
        </div>
        <!-- Vertical resize handle -->
        <div class="resize-handle-v" onmousedown={startResizeCharts}></div>
        <div class="charts-area" style="width: {chartsWidth}px">
          <BandwidthChart />
          <ProtocolChart />
        </div>
      </div>

      <!-- Horizontal resize handle -->
      <div class="resize-handle-h" onmousedown={startResizeDetail}></div>

      <div class="detail-area" style="height: {detailHeight}px">
        <PacketDetail />
      </div>
    </div>
  </div>
{/if}

<style>
  .app-layout {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: #0a0a0f;
  }

  .main-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .content-area {
    flex: 1;
    display: flex;
    overflow: hidden;
  }

  .packet-list-area {
    flex: 1;
    overflow: hidden;
  }

  .charts-area {
    flex-shrink: 0;
    border-left: 1px solid #2a2a4a;
    overflow-y: auto;
    background: #0d0d1a;
  }

  .detail-area {
    flex-shrink: 0;
    border-top: 1px solid #2a2a4a;
    overflow: hidden;
    background: #0d0d1a;
  }

  .resize-handle-h {
    height: 4px;
    background: #2a2a4a;
    cursor: row-resize;
    flex-shrink: 0;
  }

  .resize-handle-h:hover {
    background: #00d4ff;
  }

  .resize-handle-v {
    width: 4px;
    background: #2a2a4a;
    cursor: col-resize;
    flex-shrink: 0;
  }

  .resize-handle-v:hover {
    background: #00d4ff;
  }
</style>
```

- [ ] **Step 3: Verify the full app builds**

```bash
npm run tauri dev
```

Expected: The app opens with the Wirehound UI — toolbar, empty packet list, charts, and detail pane. If BPF permissions aren't configured, the permission check screen appears.

- [ ] **Step 4: Commit**

```bash
git add src/App.svelte src/app.css
git commit -m "feat: wire up root App layout with all panels, event listeners, and resizable panes"
```

---

## Task 14: Tauri Configuration & Window Settings

**Files:**
- Modify: `src-tauri/tauri.conf.json`

- [ ] **Step 1: Update `tauri.conf.json` window settings**

Ensure the window configuration includes:

```json
{
  "app": {
    "windows": [
      {
        "title": "Wirehound",
        "width": 1200,
        "height": 800,
        "minWidth": 800,
        "minHeight": 600,
        "resizable": true,
        "fullscreen": false
      }
    ]
  }
}
```

Also ensure the `identifier` is set to something unique like `com.wirehound.app`.

- [ ] **Step 2: Verify the app launches with correct window settings**

```bash
npm run tauri dev
```

Expected: Window opens at 1200x800 with "Wirehound" in the title bar.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/tauri.conf.json
git commit -m "feat: configure Tauri window — title, size, and app identifier"
```

---

## Task 15: Integration Testing & Smoke Test

**Files:**
- No new files — run existing tests and do manual verification

- [ ] **Step 1: Run all Rust tests**

```bash
cd src-tauri && cargo test
```

Expected: All parser and stats tests pass.

- [ ] **Step 2: Build a release binary**

```bash
npm run tauri build
```

Expected: Produces a `.dmg` in `src-tauri/target/release/bundle/dmg/`.

- [ ] **Step 3: Manual smoke test**

1. Launch the app
2. If permission screen shows, follow setup instructions and click "Check Again"
3. Select a network interface from the dropdown
4. Click "Start" — packets should appear in the list
5. Click a packet — detail pane should show layers and hex dump
6. Charts should update with bandwidth and protocol data
7. Type in the display filter — packet list should filter
8. Click "Stop" — capture stops
9. Click "Clear" — packet list clears

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: integration testing and smoke test complete"
```
