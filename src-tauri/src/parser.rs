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
                src_ip = arp.get_sender_proto_addr().to_string();
                dst_ip = arp.get_target_proto_addr().to_string();

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
        let mut pkt = vec![0u8; 54];
        pkt[12] = 0x08; pkt[13] = 0x00;
        pkt[14] = 0x45;
        pkt[16] = 0x00; pkt[17] = 0x28;
        pkt[22] = 64;
        pkt[23] = 6;
        pkt[26] = 192; pkt[27] = 168; pkt[28] = 1; pkt[29] = 1;
        pkt[30] = 10; pkt[31] = 0; pkt[32] = 0; pkt[33] = 1;
        pkt[34] = 0x30; pkt[35] = 0x39;
        pkt[36] = 0x00; pkt[37] = 0x50;
        pkt[46] = 0x50;
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
        assert_eq!(packet.protocol, Protocol::HTTP);
        assert_eq!(packet.length, 54);
        assert!(packet.parsed_layers.len() >= 3);
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
        pkt[12] = 0x08; pkt[13] = 0x00;
        pkt[14] = 0x45;
        pkt[16] = 0x00; pkt[17] = 0x1c;
        pkt[22] = 64;
        pkt[23] = 17;
        pkt[26] = 192; pkt[27] = 168; pkt[28] = 1; pkt[29] = 100;
        pkt[30] = 8; pkt[31] = 8; pkt[32] = 8; pkt[33] = 8;
        pkt[34] = 0xd4; pkt[35] = 0x31;
        pkt[36] = 0x00; pkt[37] = 0x35;
        pkt[38] = 0x00; pkt[39] = 0x08;
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
        pkt[12] = 0x08; pkt[13] = 0x06;
        pkt[14] = 0x00; pkt[15] = 0x01;
        pkt[16] = 0x08; pkt[17] = 0x00;
        pkt[18] = 6;
        pkt[19] = 4;
        pkt[20] = 0x00; pkt[21] = 0x01;
        pkt[28] = 192; pkt[29] = 168; pkt[30] = 1; pkt[31] = 1;
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
