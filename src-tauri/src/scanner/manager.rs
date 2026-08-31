use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::discovery;
use super::limits::ScanLimits;
use super::models::{
    CancelAcknowledged, CoverageSummary, ScanCommandError, ScanCompleted, ScanPhase, ScanProgress,
    ScanRequest, ScanResult, ScanStarted, ScanStatus, ScanSummary,
};
use super::target::{validate_target, ValidatedTarget};

pub trait ScanObserver: Send + Sync {
    fn progress(&self, progress: ScanProgress);
    fn completed(&self, completed: ScanCompleted);
}

#[derive(Debug, Default)]
pub struct NoopScanObserver;

impl ScanObserver for NoopScanObserver {
    fn progress(&self, _: ScanProgress) {}

    fn completed(&self, _: ScanCompleted) {}
}

#[derive(Clone)]
pub struct ScanManager {
    inner: Arc<Mutex<ManagerState>>,
    limits: ScanLimits,
}

struct ManagerState {
    next_scan_id: u64,
    active_targets: HashSet<PathBuf>,
    active_scans: HashMap<u64, Arc<AtomicBool>>,
    completed_scans: HashMap<u64, ScanResult>,
}

#[derive(Debug)]
pub struct ScanHandle {
    pub started: ScanStarted,
    target: ValidatedTarget,
    cancellation: Arc<AtomicBool>,
}

impl Default for ScanManager {
    fn default() -> Self {
        Self::new(ScanLimits::default())
    }
}

impl ScanManager {
    pub fn new(limits: ScanLimits) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ManagerState {
                next_scan_id: 1,
                active_targets: HashSet::new(),
                active_scans: HashMap::new(),
                completed_scans: HashMap::new(),
            })),
            limits,
        }
    }

    pub fn start(&self, request: ScanRequest) -> Result<ScanHandle, ScanCommandError> {
        let target = validate_target(&request.target_path)?;
        let mut state = self.inner.lock().expect("scan manager lock poisoned");

        if state.active_targets.contains(&target.canonical_path) {
            return Err(ScanCommandError::new(
                "scan_already_running",
                "A scan is already running for this target.",
            ));
        }

        let scan_id = state.next_scan_id;
        state.next_scan_id += 1;

        let cancellation = Arc::new(AtomicBool::new(false));
        state.active_targets.insert(target.canonical_path.clone());
        state.active_scans.insert(scan_id, cancellation.clone());

        Ok(ScanHandle {
            started: ScanStarted {
                scan_id,
                target: target.summary.clone(),
            },
            target,
            cancellation,
        })
    }

    pub fn run(&self, handle: ScanHandle, observer: &dyn ScanObserver) {
        let scan_id = handle.started.scan_id;
        let started_at_unix_ms = unix_time_ms();
        observer.progress(progress_for(
            scan_id,
            ScanPhase::Queued,
            &CoverageSummary::default(),
            0,
            0,
        ));
        observer.progress(progress_for(
            scan_id,
            ScanPhase::Discovering,
            &CoverageSummary::default(),
            0,
            0,
        ));

        let outcome = discovery::discover(
            &handle.target.canonical_path,
            self.limits,
            &handle.cancellation,
            |coverage| {
                observer.progress(progress_for(
                    scan_id,
                    ScanPhase::Discovering,
                    coverage,
                    0,
                    0,
                ));
            },
        );

        let status = if outcome.cancelled {
            ScanStatus::Cancelled
        } else if outcome.coverage.candidate_limit_reached {
            ScanStatus::Partial
        } else if outcome.issues.is_empty() {
            ScanStatus::Completed
        } else {
            ScanStatus::CompletedWithIssues
        };

        let result = ScanResult {
            scan_id,
            target: handle.started.target.clone(),
            status,
            started_at_unix_ms,
            finished_at_unix_ms: Some(unix_time_ms()),
            summary: ScanSummary::default(),
            coverage: outcome.coverage,
            findings: Vec::new(),
            issues: outcome.issues,
        };

        let completion_phase = if status == ScanStatus::Cancelled {
            ScanPhase::Cancelled
        } else {
            ScanPhase::Completed
        };
        let completion = ScanCompleted {
            scan_id,
            status,
            summary: result.summary.clone(),
        };
        let coverage = result.coverage.clone();
        let issue_count = result.issues.len() as u64;

        let mut state = self.inner.lock().expect("scan manager lock poisoned");
        state.active_targets.remove(&handle.target.canonical_path);
        state.active_scans.remove(&scan_id);
        state.completed_scans.insert(scan_id, result);
        drop(state);

        observer.progress(progress_for(
            scan_id,
            completion_phase,
            &coverage,
            0,
            issue_count,
        ));
        observer.completed(completion);
    }

    pub fn cancel(&self, scan_id: u64) -> Result<CancelAcknowledged, ScanCommandError> {
        let state = self.inner.lock().expect("scan manager lock poisoned");
        let cancellation = state.active_scans.get(&scan_id).ok_or_else(|| {
            ScanCommandError::new("scan_not_active", "The scan is not currently running.")
        })?;
        cancellation.store(true, Ordering::Relaxed);

        Ok(CancelAcknowledged { scan_id })
    }

    pub fn result(&self, scan_id: u64) -> Result<ScanResult, ScanCommandError> {
        let state = self.inner.lock().expect("scan manager lock poisoned");
        state.completed_scans.get(&scan_id).cloned().ok_or_else(|| {
            if state.active_scans.contains_key(&scan_id) {
                ScanCommandError::new("scan_running", "The scan has not completed yet.")
            } else {
                ScanCommandError::new("scan_not_found", "The scan result is not available.")
            }
        })
    }

    pub fn dismiss(&self, scan_id: u64) -> Result<(), ScanCommandError> {
        let mut state = self.inner.lock().expect("scan manager lock poisoned");
        if state.completed_scans.remove(&scan_id).is_some() {
            Ok(())
        } else {
            Err(ScanCommandError::new(
                "scan_not_found",
                "The scan result is not available.",
            ))
        }
    }
}

fn progress_for(
    scan_id: u64,
    phase: ScanPhase,
    coverage: &CoverageSummary,
    processed_files: u64,
    issue_count: u64,
) -> ScanProgress {
    ScanProgress {
        scan_id,
        phase,
        discovered_files: coverage.discovered_files,
        selected_files: coverage.selected_files,
        processed_files,
        finding_count: 0,
        issue_count,
    }
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{NoopScanObserver, ScanManager};
    use crate::scanner::limits::ScanLimits;
    use crate::scanner::models::{ScanRequest, ScanStatus};

    static NEXT_FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

    fn fixture_path(name: &str) -> PathBuf {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "leakline-manager-test-{}-{}-{}",
            std::process::id(),
            name,
            id
        ))
    }

    #[test]
    fn cancellation_produces_a_cancelled_in_memory_result() {
        let root = fixture_path("cancel");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("candidate.rs"), "fixture").unwrap();
        let manager = ScanManager::new(ScanLimits::default());
        let handle = manager
            .start(ScanRequest {
                target_path: root.display().to_string(),
            })
            .unwrap();

        manager.cancel(handle.started.scan_id).unwrap();
        let scan_id = handle.started.scan_id;
        manager.run(handle, &NoopScanObserver);

        let result = manager.result(scan_id).unwrap();
        assert_eq!(result.status, ScanStatus::Cancelled);
        manager.dismiss(scan_id).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn blocks_duplicate_active_target_scans() {
        let root = fixture_path("duplicate");
        fs::create_dir_all(&root).unwrap();
        let manager = ScanManager::default();

        let first = manager
            .start(ScanRequest {
                target_path: root.display().to_string(),
            })
            .unwrap();
        let error = manager
            .start(ScanRequest {
                target_path: root.display().to_string(),
            })
            .unwrap_err();

        assert_eq!(error.code, "scan_already_running");
        manager.cancel(first.started.scan_id).unwrap();
        manager.run(first, &NoopScanObserver);
        fs::remove_dir_all(root).unwrap();
    }
}
