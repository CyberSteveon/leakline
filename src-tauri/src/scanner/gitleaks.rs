use std::path::Path;
use std::process::Command;
use std::fs;
use crate::scanner::models::{Finding, FindingLocation, ScanIssue, IssueStage, IssueSeverity, Severity};
use serde::Deserialize;

#[derive(Deserialize)]
#[allow(dead_code)]
struct GitleaksMatch {
    #[serde(rename = "RuleID")]
    rule_id: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "File")]
    file: Option<String>,
    #[serde(rename = "StartLine")]
    start_line: Option<u64>,
    #[serde(rename = "EndLine")]
    end_line: Option<u64>,
    #[serde(rename = "StartColumn")]
    start_column: Option<u64>,
    #[serde(rename = "EndColumn")]
    end_column: Option<u64>,
    #[serde(rename = "Match")]
    match_content: Option<String>,
    #[serde(rename = "Secret")]
    secret: Option<String>,
    #[serde(rename = "Fingerprint")]
    fingerprint: Option<String>,
}

pub fn run_gitleaks(target_path: &Path, binary_path: &Path) -> (Vec<Finding>, Vec<ScanIssue>) {
    let mut findings = Vec::new();
    let mut issues = Vec::new();
    
    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join(format!("gitleaks_output_{}.json", std::process::id()));
    
    let result = Command::new(binary_path)
        .arg("detect")
        .arg("--no-git")
        .arg("--source")
        .arg(target_path)
        .arg("--report-format")
        .arg("json")
        .arg("--report-path")
        .arg(&output_file)
        .arg("--exit-code")
        .arg("0")
        .output();
        
    match result {
        Ok(_) => {
            if output_file.exists() {
                if let Ok(content) = fs::read_to_string(&output_file) {
                    if let Ok(matches) = serde_json::from_str::<Vec<GitleaksMatch>>(&content) {
                        for (i, m) in matches.into_iter().enumerate() {
                            findings.push(Finding {
                                finding_id: format!("gitleaks-{}", i),
                                scanner_id: "gitleaks".to_string(),
                                rule_id: m.rule_id.unwrap_or_else(|| "unknown".to_string()),
                                title: "Gitleaks Finding".to_string(),
                                description: m.description.unwrap_or_else(|| "Secret detected".to_string()),
                                severity: Severity::High,
                                location: FindingLocation {
                                    relative_path: m.file.unwrap_or_else(|| "unknown".to_string()),
                                    start_line: m.start_line,
                                    start_column: m.start_column,
                                    end_line: m.end_line,
                                    end_column: m.end_column,
                                },
                                tags: vec!["secret".to_string()],
                                remediation: None,
                                fingerprint: m.fingerprint.unwrap_or_else(|| "".to_string()),
                            });
                        }
                    } else {
                        issues.push(ScanIssue {
                            issue_id: "gitleaks-parse-error".to_string(),
                            stage: IssueStage::Gitleaks,
                            code: "parse_error".to_string(),
                            severity: IssueSeverity::Error,
                            message: "Failed to parse gitleaks JSON output".to_string(),
                            relative_path: None,
                            scanner_id: Some("gitleaks".to_string()),
                        });
                    }
                }
                let _ = fs::remove_file(output_file);
            }
        },
        Err(e) => {
            issues.push(ScanIssue {
                issue_id: "gitleaks-exec-error".to_string(),
                stage: IssueStage::Gitleaks,
                code: "exec_error".to_string(),
                severity: IssueSeverity::Error,
                message: format!("Failed to execute gitleaks: {}", e),
                relative_path: None,
                scanner_id: Some("gitleaks".to_string()),
            });
        }
    }
    
    (findings, issues)
}
