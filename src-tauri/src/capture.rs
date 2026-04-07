use crate::models::NetworkInterface;
use crate::parser;
use crate::stats::StatsAggregator;
use pcap::{Capture, Device};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use tauri::{AppHandle, Emitter};

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
        .timeout(100)
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
                        if let Ok(mut agg) = capture_state.stats_aggregator.lock() {
                            agg.record_packet(&parsed);
                        }
                        let _ = app_clone.emit("packet", &parsed);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    continue;
                }
                Err(_) => {
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
    std::thread::spawn(move || {
        while stats_state.is_capturing.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(1));
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
