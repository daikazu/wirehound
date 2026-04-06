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

        if self.bytes_window.len() > 60 {
            self.bytes_window.remove(0);
        }
        if self.packets_window.len() > 60 {
            self.packets_window.remove(0);
        }

        let bytes_per_sec = self.current_bytes;
        let packets_per_sec = self.current_packets;

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
