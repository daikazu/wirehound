# Wirehound

A network traffic sniffer desktop app built with Tauri, Rust, and Svelte. This is an experimental/learning project for exploring Rust and low-level packet capture — it's not intended for release or production use.

## What it does

- Live packet capture using libpcap in promiscuous mode
- Real-time scrolling packet list with protocol-level detail (Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS)
- Expandable packet detail pane with protocol layer tree and hex dump
- Live bandwidth chart and protocol breakdown donut chart
- BPF capture filters and display filters
- Optional reverse DNS resolution for IP addresses
- Resizable panels

## Tech Stack

- **Rust** — packet capture (pcap crate), parsing (pnet), stats aggregation
- **Tauri v2** — desktop app framework
- **Svelte 5** — frontend UI
- **Chart.js** — live charts

## Running

Requires Rust, Node.js, and libpcap (ships with macOS).

```bash
npm install
npm run tauri dev
```

Packet capture requires BPF access on macOS. The app will show setup instructions on first run, or you can run:

```bash
sudo chmod o+r /dev/bpf*
```

## Building

```bash
npm run tauri build
```

Produces a `.app` bundle and `.dmg` installer in `src-tauri/target/release/bundle/`.

## Status

Experimental. Built as a learning exercise for Rust and systems programming. Not planned for release.
