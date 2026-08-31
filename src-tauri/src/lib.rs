mod commands;
pub mod scanner;

pub use scanner::policy::{is_allowed_extension, is_allowed_filename};

// Tauri application setup.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(scanner::manager::ScanManager::default())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::scan_directory,
            commands::start_scan,
            commands::cancel_scan,
            commands::get_scan_result,
            commands::dismiss_scan_result
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
