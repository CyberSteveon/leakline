use tauri::{AppHandle, Emitter, State};

use crate::dependencies::{get_status, install, DependencyStatus};
use crate::scanner::manager::{ScanManager, ScanObserver};
use crate::scanner::models::{
    CancelAcknowledged, ScanCommandError, ScanCompleted, ScanProgress, ScanRequest, ScanResult,
    ScanStarted,
};

#[tauri::command]
pub fn app_info() -> String {
    let app_name = "leakline";
    let version = "0.1.0";

    format!("{}\nVersion: {}", app_name, version)
}

#[tauri::command]
pub fn get_dependency_status(app: AppHandle) -> Result<DependencyStatus, String> {
    get_status(&app)
}

#[tauri::command]
pub fn install_dependency(app: AppHandle) -> Result<(), String> {
    install(&app)
}

#[tauri::command]
pub fn uninstall_dependency(app: AppHandle, dep_id: String) -> Result<(), String> {
    crate::dependencies::uninstall(&app, &dep_id)
}

#[tauri::command]
pub fn start_scan(
    manager: State<'_, ScanManager>,
    app: AppHandle,
    request: ScanRequest,
) -> Result<ScanStarted, ScanCommandError> {
    let manager = manager.inner().clone();
    let handle = manager.start(request)?;
    let started = handle.started.clone();
    let observer = TauriScanObserver { app: app.clone() };

    tauri::async_runtime::spawn_blocking(move || {
        manager.run(handle, &observer, app);
    });

    Ok(started)
}

#[tauri::command]
pub fn cancel_scan(
    manager: State<'_, ScanManager>,
    scan_id: u64,
) -> Result<CancelAcknowledged, ScanCommandError> {
    manager.cancel(scan_id)
}

#[tauri::command]
pub fn get_scan_result(
    manager: State<'_, ScanManager>,
    scan_id: u64,
) -> Result<ScanResult, ScanCommandError> {
    manager.result(scan_id)
}

#[tauri::command]
pub fn dismiss_scan_result(
    manager: State<'_, ScanManager>,
    scan_id: u64,
) -> Result<(), ScanCommandError> {
    manager.dismiss(scan_id)
}

struct TauriScanObserver {
    app: AppHandle,
}

impl ScanObserver for TauriScanObserver {
    fn progress(&self, progress: ScanProgress) {
        if let Err(error) = self.app.emit("scan-progress", progress) {
            log::warn!("Unable to emit scan progress: {error}");
        }
    }

    fn completed(&self, completed: ScanCompleted) {
        if let Err(error) = self.app.emit("scan-complete", completed) {
            log::warn!("Unable to emit scan completion: {error}");
        }
    }
}
