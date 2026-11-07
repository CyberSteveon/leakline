use super::models::{IssueSeverity, IssueStage, ScanIssue};

/// Never expose subprocess stderr, source snippets, or report contents in diagnostics.
pub(super) fn issue(stage: IssueStage, code: &str, message: &str) -> ScanIssue {
    let scanner = match stage {
        IssueStage::Gitleaks => "gitleaks",
        IssueStage::Semgrep => "semgrep",
        _ => unreachable!("external scanner stage"),
    };
    ScanIssue {
        issue_id: format!("{scanner}-{code}"),
        stage,
        code: code.into(),
        severity: IssueSeverity::Error,
        message: message.into(),
        scanner_id: Some(scanner.into()),
        relative_path: None,
    }
}
