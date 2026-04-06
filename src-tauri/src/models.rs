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
