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
