use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingLocation {
    pub relative_path: String,
    pub start_line: Option<u64>,
    pub start_column: Option<u64>,
    pub end_line: Option<u64>,
    pub end_column: Option<u64>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub finding_id: String,
    pub scanner_id: String,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub location: FindingLocation,
    pub tags: Vec<String>,
    pub remediation: Option<String>,
    pub fingerprint: String,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IssueStage {
    Target,
    Discovery,
    Native,
    Result,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IssueSeverity {
    Warning,
    Error,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanIssue {
    pub issue_id: String,
    pub stage: IssueStage,
    pub code: String,
    pub severity: IssueSeverity,
    pub message: String,
    pub relative_path: Option<String>,
    pub scanner_id: Option<String>,
}

#[derive(Debug, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSummary {
    pub discovered_files: u64,
    pub eligible_files: u64,
    pub selected_files: u64,
    pub selected_bytes: u64,
    pub skipped_by_policy: u64,
    pub excluded_vcs_entries: u64,
    pub skipped_symlinks: u64,
    pub skipped_oversized: u64,
    pub unreadable_files: u64,
    pub traversal_errors: u64,
    pub candidate_limit_reached: bool,
}

#[derive(Debug, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub finding_count: u64,
    pub minimal_count: u64,
    pub low_count: u64,
    pub medium_count: u64,
    pub high_count: u64,
    pub critical_count: u64,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanTargetSummary {
    pub display_path: String,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Running,
    Completed,
    CompletedWithIssues,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Queued,
    Discovering,
    Completed,
    Cancelled,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub scan_id: u64,
    pub phase: ScanPhase,
    pub discovered_files: u64,
    pub selected_files: u64,
    pub processed_files: u64,
    pub finding_count: u64,
    pub issue_count: u64,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanCompleted {
    pub scan_id: u64,
    pub status: ScanStatus,
    pub summary: ScanSummary,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub target_path: String,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanStarted {
    pub scan_id: u64,
    pub target: ScanTargetSummary,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CancelAcknowledged {
    pub scan_id: u64,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanCommandError {
    pub code: String,
    pub message: String,
}

impl ScanCommandError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub scan_id: u64,
    pub target: ScanTargetSummary,
    pub status: ScanStatus,
    pub started_at_unix_ms: u128,
    pub finished_at_unix_ms: Option<u128>,
    pub summary: ScanSummary,
    pub coverage: CoverageSummary,
    pub findings: Vec<Finding>,
    pub issues: Vec<ScanIssue>,
}
