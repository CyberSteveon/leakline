use super::models::{
    Finding, FindingLocation, IssueSeverity, IssueStage, ScanIssue, Severity,
};

const NATIVE_SCANNER_ID: &str = "native";

/// Metadata shared by every finding produced by a native rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub tags: &'static [&'static str],
    pub remediation: Option<&'static str>,
}

/// A bounded, in-memory text view supplied by the future native file reader.
///
/// Rules receive no absolute path and cannot return this content through the
/// rule interface. Implementations must not log or retain `content`.
pub struct RuleFile<'a> {
    relative_path: &'a str,
    content: &'a str,
}

impl<'a> RuleFile<'a> {
    pub fn new(relative_path: &'a str, content: &'a str) -> Self {
        Self {
            relative_path,
            content,
        }
    }

    pub fn relative_path(&self) -> &str {
        self.relative_path
    }

    pub fn content(&self) -> &str {
        self.content
    }
}

/// A location-only rule match. It intentionally has no field for matched text,
/// source lines, or any other secret-bearing evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    start_line: Option<u64>,
    start_column: Option<u64>,
    end_line: Option<u64>,
    end_column: Option<u64>,
}

impl RuleMatch {
    pub fn new(
        start_line: Option<u64>,
        start_column: Option<u64>,
        end_line: Option<u64>,
        end_column: Option<u64>,
    ) -> Self {
        Self {
            start_line,
            start_column,
            end_line,
            end_column,
        }
    }

    fn location(&self, relative_path: &str) -> FindingLocation {
        FindingLocation {
            relative_path: relative_path.to_owned(),
            start_line: self.start_line,
            start_column: self.start_column,
            end_line: self.end_line,
            end_column: self.end_column,
        }
    }
}

/// A safe, user-facing rule execution error. Rule implementations must use
/// generic messages and may not put file contents or matched values here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    pub code: &'static str,
    pub message: &'static str,
}

impl RuleError {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

/// Local, synchronous content rule contract.
///
/// `applies_to` selects a file by its relative path. `evaluate` can inspect the
/// bounded file text and emits only location-only matches. The scanner performs
/// all finding normalization so rule code has no direct path to expose secrets
/// through the application result model.
pub trait NativeRule: Send + Sync {
    fn metadata(&self) -> RuleMetadata;

    fn applies_to(&self, file: &RuleFile<'_>) -> bool;

    fn evaluate(&self, file: &RuleFile<'_>) -> Result<Vec<RuleMatch>, RuleError>;
}

/// Runs the registered native rules synchronously for one file.
#[derive(Default)]
pub struct NativeScanner {
    rules: Vec<Box<dyn NativeRule>>,
}

impl NativeScanner {
    pub fn new(rules: Vec<Box<dyn NativeRule>>) -> Self {
        Self { rules }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn scan_file(&self, file: &RuleFile<'_>) -> NativeScanOutcome {
        let mut outcome = NativeScanOutcome::default();

        for rule in &self.rules {
            if !rule.applies_to(file) {
                continue;
            }

            let metadata = rule.metadata();
            match rule.evaluate(file) {
                Ok(matches) => {
                    for (match_index, rule_match) in matches.into_iter().enumerate() {
                        outcome.findings.push(normalize_match(
                            &metadata,
                            file.relative_path(),
                            &rule_match,
                            match_index,
                        ));
                    }
                }
                Err(error) => outcome.issues.push(normalize_rule_error(
                    &metadata,
                    file.relative_path(),
                    error,
                )),
            }
        }

        outcome
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct NativeScanOutcome {
    pub findings: Vec<Finding>,
    pub issues: Vec<ScanIssue>,
}

fn normalize_match(
    metadata: &RuleMetadata,
    relative_path: &str,
    rule_match: &RuleMatch,
    match_index: usize,
) -> Finding {
    let location = rule_match.location(relative_path);
    let identity = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        metadata.id,
        relative_path,
        location.start_line.unwrap_or_default(),
        location.start_column.unwrap_or_default(),
        location.end_line.unwrap_or_default(),
        location.end_column.unwrap_or_default(),
        match_index,
    );

    Finding {
        finding_id: format!("native:{identity}"),
        scanner_id: NATIVE_SCANNER_ID.to_owned(),
        rule_id: metadata.id.to_owned(),
        title: metadata.name.to_owned(),
        description: metadata.description.to_owned(),
        severity: metadata.severity,
        location,
        tags: metadata.tags.iter().map(|tag| (*tag).to_owned()).collect(),
        remediation: metadata.remediation.map(str::to_owned),
        fingerprint: format!("native:{identity}"),
    }
}

fn normalize_rule_error(
    metadata: &RuleMetadata,
    relative_path: &str,
    error: RuleError,
) -> ScanIssue {
    ScanIssue {
        issue_id: format!("native:{}:{}", metadata.id, relative_path),
        stage: IssueStage::Native,
        code: error.code.to_owned(),
        severity: IssueSeverity::Error,
        message: error.message.to_owned(),
        relative_path: Some(relative_path.to_owned()),
        scanner_id: Some(NATIVE_SCANNER_ID.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NativeRule, NativeScanner, RuleError, RuleFile, RuleMatch, RuleMetadata,
    };
    use crate::scanner::models::{IssueStage, Severity};

    struct FirstRule;

    impl NativeRule for FirstRule {
        fn metadata(&self) -> RuleMetadata {
            RuleMetadata {
                id: "test.first",
                name: "First test rule",
                description: "Reports a safe test finding.",
                severity: Severity::Medium,
                tags: &["test"],
                remediation: Some("Remove the test condition."),
            }
        }

        fn applies_to(&self, file: &RuleFile<'_>) -> bool {
            file.relative_path().ends_with(".env")
        }

        fn evaluate(&self, file: &RuleFile<'_>) -> Result<Vec<RuleMatch>, RuleError> {
            if file.content().contains("test-secret-value") {
                Ok(vec![RuleMatch::new(Some(2), Some(1), Some(2), Some(18))])
            } else {
                Ok(Vec::new())
            }
        }
    }

    struct SecondRule;

    impl NativeRule for SecondRule {
        fn metadata(&self) -> RuleMetadata {
            RuleMetadata {
                id: "test.second",
                name: "Second test rule",
                description: "Reports another safe test finding.",
                severity: Severity::High,
                tags: &["test", "second"],
                remediation: None,
            }
        }

        fn applies_to(&self, _: &RuleFile<'_>) -> bool {
            true
        }

        fn evaluate(&self, _: &RuleFile<'_>) -> Result<Vec<RuleMatch>, RuleError> {
            Ok(vec![RuleMatch::new(Some(1), Some(1), None, None)])
        }
    }

    struct FailingRule;

    impl NativeRule for FailingRule {
        fn metadata(&self) -> RuleMetadata {
            RuleMetadata {
                id: "test.failure",
                name: "Failing test rule",
                description: "Fails safely.",
                severity: Severity::Low,
                tags: &[],
                remediation: None,
            }
        }

        fn applies_to(&self, _: &RuleFile<'_>) -> bool {
            true
        }

        fn evaluate(&self, _: &RuleFile<'_>) -> Result<Vec<RuleMatch>, RuleError> {
            Err(RuleError::new("test_rule_failed", "The test rule failed."))
        }
    }

    #[test]
    fn runs_multiple_applicable_rules_for_one_file() {
        let scanner = NativeScanner::new(vec![Box::new(FirstRule), Box::new(SecondRule)]);
        let file = RuleFile::new("config/.env", "name=test-secret-value");

        let outcome = scanner.scan_file(&file);

        assert_eq!(outcome.findings.len(), 2);
        assert!(outcome.issues.is_empty());
        assert_eq!(outcome.findings[0].scanner_id, "native");
        assert_eq!(outcome.findings[0].location.relative_path, "config/.env");
        assert_eq!(outcome.findings[0].location.start_line, Some(2));
        assert_eq!(outcome.findings[1].rule_id, "test.second");
    }

    #[test]
    fn normalized_findings_do_not_expose_matched_content() {
        let scanner = NativeScanner::new(vec![Box::new(FirstRule)]);
        let file = RuleFile::new("config/.env", "name=test-secret-value");

        let outcome = scanner.scan_file(&file);
        let serialized = serde_json::to_string(&outcome.findings).unwrap();

        assert_eq!(outcome.findings.len(), 1);
        assert!(!serialized.contains("test-secret-value"));
        assert!(!serialized.contains("name="));
    }

    #[test]
    fn normalizes_rule_failures_as_scan_issues() {
        let scanner = NativeScanner::new(vec![Box::new(FailingRule)]);
        let file = RuleFile::new("config/.env", "name=test-secret-value");

        let outcome = scanner.scan_file(&file);

        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.issues.len(), 1);
        assert_eq!(outcome.issues[0].stage, IssueStage::Native);
        assert_eq!(outcome.issues[0].code, "test_rule_failed");
        assert!(!outcome.issues[0].message.contains("test-secret-value"));
    }
}
