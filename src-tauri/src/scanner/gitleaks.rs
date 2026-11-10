use super::report::issue;
use crate::scanner::models::{Finding, FindingLocation, IssueStage, ScanIssue, Severity};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Deserialize)]
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

    #[serde(rename = "Fingerprint")]
    fingerprint: Option<String>,
}

pub fn run_gitleaks(target_path: &Path, binary_path: &Path) -> (Vec<Finding>, Vec<ScanIssue>) {
    // Each invocation must read only its own report.
    let Ok(dir) = tempfile::tempdir() else {
        return (
            vec![],
            vec![issue(
                IssueStage::Gitleaks,
                "report_unavailable",
                "Could not create a private report directory.",
            )],
        );
    };
    let report = dir.path().join("result.json");
    let status = Command::new(binary_path)
        .args(["detect", "--no-git", "--source"])
        .arg(target_path)
        .args(["--redact", "--report-format", "json", "--report-path"])
        .arg(&report)
        .args(["--exit-code", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) => parse_report(status.success(), &fs::read(report).unwrap_or_default()),
        Err(_) => (
            vec![],
            vec![issue(
                IssueStage::Gitleaks,
                "exec_error",
                "Could not start Gitleaks.",
            )],
        ),
    }
}

fn parse_report(success: bool, report: &[u8]) -> (Vec<Finding>, Vec<ScanIssue>) {
    let mut findings = Vec::new();
    let mut issues = Vec::new();
    if !success {
        issues.push(issue(
            IssueStage::Gitleaks,
            "process_failed",
            "Gitleaks did not finish successfully.",
        ));
    }
    let Ok(matches) = serde_json::from_slice::<Vec<GitleaksMatch>>(report) else {
        issues.push(issue(
            IssueStage::Gitleaks,
            "invalid_report",
            "Gitleaks returned no readable, valid report.",
        ));
        return (findings, issues);
    };

    for (match_index, rule_match) in matches.into_iter().enumerate() {
        findings.push(Finding {
            finding_id: format!("gitleaks-{match_index}"),
            scanner_id: "gitleaks".to_string(),
            rule_id: rule_match.rule_id.unwrap_or_else(|| "unknown".to_string()),
            title: "Gitleaks Finding".to_string(),
            description: rule_match
                .description
                .unwrap_or_else(|| "Secret detected".to_string()),
            severity: Severity::High,
            location: FindingLocation {
                relative_path: rule_match.file.unwrap_or_else(|| "unknown".to_string()),
                start_line: rule_match.start_line,
                start_column: rule_match.start_column,
                end_line: rule_match.end_line,
                end_column: rule_match.end_column,
            },
            tags: vec!["secret".to_string()],
            remediation: None,
            fingerprint: rule_match.fingerprint.unwrap_or_default(),
        });
    }
    (findings, issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_only_clean_with_positive_evidence() {
        let valid = br#"[]"#;
        assert!(parse_report(true, valid).1.is_empty());
        assert!(!parse_report(false, valid).1.is_empty());
        assert!(!parse_report(true, b"").1.is_empty());
        assert!(!parse_report(true, b"broken").1.is_empty());
    }
}
