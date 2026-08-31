use std::sync::atomic::AtomicBool;

use tauri::{AppHandle, Emitter, State};

use crate::scanner::discovery;
use crate::scanner::limits::ScanLimits;
use crate::scanner::manager::{ScanManager, ScanObserver};
use crate::scanner::models::{
    CancelAcknowledged, ScanCommandError, ScanCompleted, ScanProgress, ScanRequest, ScanResult,
    ScanStarted,
};
use crate::scanner::target::validate_target;

#[tauri::command]
pub fn app_info() -> String {
    let app_name = "leakline";
    let version = "0.1.0";

    format!("{}\nVersion: {}", app_name, version)
}

// Compatibility command for callers that only need the candidate file paths.
// Unlike the original implementation, discovery errors are returned instead of
// being silently discarded. New callers should use start_scan and get_scan_result.
#[tauri::command]
pub fn scan_directory(path: String) -> Result<Vec<String>, ScanCommandError> {
    let target = validate_target(&path)?;
    let cancellation = AtomicBool::new(false);
    let outcome = discovery::discover(
        &target.canonical_path,
        ScanLimits::default(),
        &cancellation,
        |_| {},
    );

    if outcome.issues.is_empty() && !outcome.coverage.candidate_limit_reached {
        Ok(outcome
            .files
            .into_iter()
            .map(|file| file.absolute_path.to_string_lossy().to_string())
            .collect())
    } else {
        Err(ScanCommandError::new(
            "directory_discovery_incomplete",
            "Directory discovery completed with coverage issues. Use start_scan to retrieve the structured result.",
        ))
    }
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
    let observer = TauriScanObserver { app };

    tauri::async_runtime::spawn_blocking(move || {
        manager.run(handle, &observer);
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
