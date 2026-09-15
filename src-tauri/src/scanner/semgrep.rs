use std::path::Path;
use std::process::Command;
use std::fs;
use crate::scanner::models::{Finding, FindingLocation, ScanIssue, IssueStage, IssueSeverity, Severity};
use serde::Deserialize;

#[derive(Deserialize)]
#[allow(dead_code)]
struct SemgrepOutput {
    results: Vec<SemgrepResult>,
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct SemgrepResult {
    check_id: String,
    path: String,
    start: SemgrepPosition,
    end: SemgrepPosition,
    extra: SemgrepExtra,
}

#[derive(Deserialize)]
struct SemgrepPosition {
    line: u64,
    col: u64,
}

#[derive(Deserialize)]
struct SemgrepExtra {
    message: String,
    severity: String,
}

pub fn run_semgrep(target_path: &Path, binary_path: &Path) -> (Vec<Finding>, Vec<ScanIssue>) {
    let mut findings = Vec::new();
    let mut issues = Vec::new();
    
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join(format!("semgrep_output_{}.json", std::process::id()));
    
    let result = Command::new(binary_path)
        .arg("scan")
        .arg("--json")
        .arg("--json-output")
        .arg(&output_file)
        .arg(target_path)
        .output();
        
    match result {
        Ok(_) => {
            if output_file.exists() {
                if let Ok(content) = fs::read_to_string(&output_file) {
                    if let Ok(output) = serde_json::from_str::<SemgrepOutput>(&content) {
                        for (i, r) in output.results.into_iter().enumerate() {
                            let severity = match r.extra.severity.as_str() {
                                "ERROR" => Severity::Critical,
                                "WARNING" => Severity::Medium,
                                _ => Severity::Low,
                            };
                            
                            findings.push(Finding {
                                finding_id: format!("semgrep-{}", i),
                                scanner_id: "semgrep".to_string(),
                                rule_id: r.check_id,
                                title: "Semgrep Finding".to_string(),
                                description: r.extra.message,
                                severity,
                                location: FindingLocation {
                                    relative_path: r.path,
                                    start_line: Some(r.start.line),
                                    start_column: Some(r.start.col),
                                    end_line: Some(r.end.line),
                                    end_column: Some(r.end.col),
                                },
                                tags: vec!["sast".to_string()],
                                remediation: None,
                                fingerprint: "".to_string(),
                            });
                        }
                    } else {
                        issues.push(ScanIssue {
                            issue_id: "semgrep-parse-error".to_string(),
                            stage: IssueStage::Semgrep,
                            code: "parse_error".to_string(),
                            severity: IssueSeverity::Error,
                            message: "Failed to parse semgrep JSON output".to_string(),
                            relative_path: None,
                            scanner_id: Some("semgrep".to_string()),
                        });
                    }
                }
                let _ = fs::remove_file(output_file);
            }
        },
        Err(e) => {
            issues.push(ScanIssue {
                issue_id: "semgrep-exec-error".to_string(),
                stage: IssueStage::Semgrep,
                code: "exec_error".to_string(),
                severity: IssueSeverity::Error,
                message: format!("Failed to execute semgrep: {}", e),
                relative_path: None,
                scanner_id: Some("semgrep".to_string()),
            });
        }
    }
    
    (findings, issues)
}
