use super::report::issue;
use crate::scanner::models::{Finding, FindingLocation, IssueStage, ScanIssue, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Deserialize)]
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
    severity: String,
}

pub fn run_semgrep(target_path: &Path, binary_path: &Path) -> (Vec<Finding>, Vec<ScanIssue>) {
    let output = Command::new(binary_path)
        .args(["scan", "--metrics=off", "--disable-version-check", "--json"])
        .arg(target_path)
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(out) => parse_report(out.status.success(), &out.stdout),
        Err(_) => (
            vec![],
            vec![issue(
                IssueStage::Semgrep,
                "exec_error",
                "Could not start Semgrep.",
            )],
        ),
    }
}

fn parse_report(success: bool, report: &[u8]) -> (Vec<Finding>, Vec<ScanIssue>) {
    let mut findings = Vec::new();
    let mut issues = Vec::new();
    if !success {
        issues.push(issue(
            IssueStage::Semgrep,
            "process_failed",
            "Semgrep did not finish successfully.",
        ));
    }
    let Ok(output) = serde_json::from_slice::<SemgrepOutput>(report) else {
        issues.push(issue(
            IssueStage::Semgrep,
            "invalid_report",
            "Semgrep returned no readable, valid report.",
        ));
        return (findings, issues);
    };
    if output
        .errors
        .as_ref()
        .is_some_and(|errors| !errors.is_empty())
    {
        issues.push(issue(
            IssueStage::Semgrep,
            "analysis_error",
            "Semgrep reported analysis errors; coverage is incomplete.",
        ));
    }
    for (match_index, rule_match) in output.results.into_iter().enumerate() {
        let severity = match rule_match.extra.severity.as_str() {
            "ERROR" => Severity::Critical,
            "WARNING" => Severity::Medium,
            _ => Severity::Low,
        };

        findings.push(Finding {
            finding_id: format!("semgrep-{match_index}"),
            scanner_id: "semgrep".to_string(),
            rule_id: rule_match.check_id,
            title: "Semgrep Finding".to_string(),
            description: "Semgrep rule matched.".into(),
            severity,
            location: FindingLocation {
                relative_path: rule_match.path,
                start_line: Some(rule_match.start.line),
                start_column: Some(rule_match.start.col),
                end_line: Some(rule_match.end.line),
                end_column: Some(rule_match.end.col),
            },
            tags: vec!["sast".to_string()],
            remediation: None,
            fingerprint: String::new(),
        });
    }
    (findings, issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_only_clean_with_positive_evidence() {
        let valid = br#"{"results":[],"errors":[]}"#;
        assert!(parse_report(true, valid).1.is_empty());
        assert!(!parse_report(false, valid).1.is_empty());
        assert!(!parse_report(true, b"").1.is_empty());
        assert!(!parse_report(true, b"broken").1.is_empty());
    }
    #[test]
    fn analysis_errors_preserve_findings_without_exposing_diagnostics() {
        let report = br#"{"results":[{"check_id":"example","path":"a.rs","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"private fixture","severity":"WARNING"}}],"errors":[{}]}"#;
        let (findings, issues) = parse_report(false, report);
        assert_eq!(findings.len(), 1);
        assert_eq!(issues.len(), 2);
        assert!(!serde_json::to_string(&findings)
            .unwrap()
            .contains("private fixture"));
    }
}
