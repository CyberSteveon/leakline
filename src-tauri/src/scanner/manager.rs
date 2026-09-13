use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::discovery;
use super::limits::ScanLimits;
use super::models::{
    CancelAcknowledged, CoverageSummary, ScanCommandError, ScanCompleted, ScanPhase, ScanProgress,
    ScanRequest, ScanResult, ScanStarted, ScanStatus, ScanSummary, ScanIssue, IssueStage, IssueSeverity
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
        let started_at_unix_ms = now_rfc3339();
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

        let mut outcome = discovery::discover(
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

        let mut findings = Vec::new();
        let mut total_bytes_read = 0;
        let mut processed_files = 0;
        let mut next_finding_id = 0;
        let native_scanner = crate::scanner::native::NativeScanner::default_scanner();

        observer.progress(progress_for(
            scan_id,
            ScanPhase::ScanningNative,
            &outcome.coverage,
            processed_files,
            outcome.issues.len() as u64,
        ));

        let mut limit_reached = false;

        for file in &outcome.files {
            if handle.cancellation.load(Ordering::Relaxed) {
                break;
            }

            if total_bytes_read >= self.limits.max_total_bytes_read {
                limit_reached = true;
                outcome.issues.push(ScanIssue {
                    issue_id: "native-limit".to_string(),
                    stage: IssueStage::Native,
                    code: "max_bytes_read".to_string(),
                    severity: IssueSeverity::Warning,
                    message: "Exceeded max total bytes read.".to_string(),
                    relative_path: None,
                    scanner_id: Some("native".to_string()),
                });
                break;
            }

            if let Ok(content) = std::fs::read_to_string(&file.absolute_path) {
                total_bytes_read += content.len() as u64;
                let rule_file = crate::scanner::native::RuleFile::new(&file.relative_path, &content);
                let native_outcome = native_scanner.scan_file(&rule_file, &mut next_finding_id);
                findings.extend(native_outcome.findings);
                outcome.issues.extend(native_outcome.issues);
            }
            processed_files += 1;
            
            if processed_files == 1 || processed_files % 100 == 0 {
                observer.progress(progress_for(
                    scan_id,
                    ScanPhase::ScanningNative,
                    &outcome.coverage,
                    processed_files,
                    outcome.issues.len() as u64,
                ));
            }
        }
        
        let mut summary = ScanSummary {
            finding_count: findings.len() as u64,
            ..Default::default()
        };
        for finding in &findings {
            match finding.severity {
                crate::scanner::models::Severity::Minimal => summary.minimal_count += 1,
                crate::scanner::models::Severity::Low => summary.low_count += 1,
                crate::scanner::models::Severity::Medium => summary.medium_count += 1,
                crate::scanner::models::Severity::High => summary.high_count += 1,
                crate::scanner::models::Severity::Critical => summary.critical_count += 1,
            }
        }

        let status = if handle.cancellation.load(Ordering::Relaxed) || outcome.cancelled {
            ScanStatus::Cancelled
        } else if outcome.coverage.candidate_limit_reached || limit_reached {
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
            started_at: started_at_unix_ms.clone(),
            finished_at: Some(now_rfc3339()),
            summary: summary.clone(),
            coverage: outcome.coverage,
            scanner_runs: Vec::new(),
            findings,
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

fn now_rfc3339() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut seconds = now;
    let days = seconds / 86400;
    seconds %= 86400;
    let hours = seconds / 3600;
    seconds %= 3600;
    let minutes = seconds / 60;
    let seconds = seconds % 60;

    let mut year = 1970;
    let mut days_remaining = days;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days_remaining >= days_in_year {
            days_remaining -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1;
    for &d in month_days.iter() {
        if days_remaining >= d {
            days_remaining -= d;
            month += 1;
        } else {
            break;
        }
    }
    let day = days_remaining + 1;

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hours, minutes, seconds)
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
                scanner_ids: None,
                exclude_paths: None,
                include_paths: None,
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
                scanner_ids: None,
                exclude_paths: None,
                include_paths: None,
            })
            .unwrap();
        let error = manager
            .start(ScanRequest {
                target_path: root.display().to_string(),
                scanner_ids: None,
                exclude_paths: None,
                include_paths: None,
            })
            .unwrap_err();

        assert_eq!(error.code, "scan_already_running");
        manager.cancel(first.started.scan_id).unwrap();
        manager.run(first, &NoopScanObserver);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_scanner_produces_findings() {
        let root = fixture_path("native");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("private.key"), "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----").unwrap();
        fs::write(root.join("config.env"), "password=supersecret\n").unwrap();
        
        let manager = ScanManager::new(ScanLimits::default());
        let handle = manager
            .start(ScanRequest {
                target_path: root.display().to_string(),
                scanner_ids: None,
                exclude_paths: None,
                include_paths: None,
            })
            .unwrap();
            
        let scan_id = handle.started.scan_id;
        manager.run(handle, &NoopScanObserver);
        
        let result = manager.result(scan_id).unwrap();
        assert_eq!(result.status, ScanStatus::Completed);
        assert_eq!(result.findings.len(), 2);
        
        let private_key_finding = result.findings.iter().find(|f| f.rule_id == "crypto.private_key").unwrap();
        assert_eq!(private_key_finding.severity, crate::scanner::models::Severity::Critical);
        
        let generic_finding = result.findings.iter().find(|f| f.rule_id == "generic.secret").unwrap();
        assert_eq!(generic_finding.severity, crate::scanner::models::Severity::Medium);
        
        let serialized = serde_json::to_string(&result.findings).unwrap();
        assert!(!serialized.contains("supersecret"));
        
        assert_eq!(result.summary.finding_count, 2);
        assert_eq!(result.summary.critical_count, 1);
        assert_eq!(result.summary.medium_count, 1);
        
        manager.dismiss(scan_id).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
