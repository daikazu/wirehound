use crate::capture::{self, CaptureState};
use crate::models::NetworkInterface;
use crate::resolver;
use std::sync::atomic::Ordering;
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
    state.is_capturing.load(Ordering::Relaxed)
}

#[tauri::command]
pub fn set_resolve_dns(
    app: AppHandle,
    state: State<'_, Arc<CaptureState>>,
    enabled: bool,
) -> Result<(), String> {
    state.resolver.enabled.store(enabled, Ordering::Relaxed);
    if enabled {
        // Start resolver thread (idempotent — it loops forever once started,
        // but only does work when enabled is true)
        resolver::start_resolver_thread(app, Arc::clone(&state.resolver));
    }
    Ok(())
}
