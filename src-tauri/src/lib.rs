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
        .plugin(tauri_plugin_opener::init())
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
