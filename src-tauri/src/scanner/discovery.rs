use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use walkdir::WalkDir;

use super::limits::ScanLimits;
use super::models::{CoverageSummary, IssueSeverity, IssueStage, ScanIssue};
use super::policy::{is_allowed_extension, is_allowed_filename};
use super::target::relative_path_display;

#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub absolute_path: PathBuf,
    pub relative_path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Default)]
pub struct DiscoveryOutcome {
    pub files: Vec<DiscoveredFile>,
    pub coverage: CoverageSummary,
    pub issues: Vec<ScanIssue>,
    pub cancelled: bool,
}

pub fn discover(
    root: &Path,
    limits: ScanLimits,
    cancellation: &AtomicBool,
    mut on_progress: impl FnMut(&CoverageSummary),
) -> DiscoveryOutcome {
    let mut outcome = DiscoveryOutcome::default();
    let mut issue_sequence = 0_u64;
    let mut walker = WalkDir::new(root).follow_links(false).into_iter();

    while let Some(entry_result) = walker.next() {
        if cancellation.load(Ordering::Relaxed) {
            outcome.cancelled = true;
            break;
        }

        let entry = match entry_result {
            Ok(entry) => entry,
            Err(error) => {
                outcome.coverage.traversal_errors += 1;
                push_issue(
                    &mut outcome.issues,
                    &mut issue_sequence,
                    IssueStage::Discovery,
                    "traversal_error",
                    IssueSeverity::Error,
                    "Leakline could not traverse a path in the selected target.",
                    error.path().map(|path| relative_path_display(root, path)),
                );
                continue;
            }
        };

        if entry.depth() == 0 {
            continue;
        }

        let path = entry.path();
        let relative_path = relative_path_display(root, path);

        if entry.file_type().is_symlink() {
            outcome.coverage.skipped_symlinks += 1;
            push_issue(
                &mut outcome.issues,
                &mut issue_sequence,
                IssueStage::Discovery,
                "symlink_skipped",
                IssueSeverity::Warning,
                "Leakline does not follow symbolic links.",
                Some(relative_path),
            );
            continue;
        }

        if is_vcs_metadata(path) {
            outcome.coverage.excluded_vcs_entries += 1;
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        outcome.coverage.discovered_files += 1;

        if !is_allowed_extension(path.extension()) && !is_allowed_filename(path.file_name()) {
            outcome.coverage.skipped_by_policy += 1;
            report_progress(&mut on_progress, &outcome.coverage);
            continue;
        }

        outcome.coverage.eligible_files += 1;
        if outcome.coverage.eligible_files > limits.max_candidate_files {
            outcome.coverage.candidate_limit_reached = true;
            push_issue(
                &mut outcome.issues,
                &mut issue_sequence,
                IssueStage::Discovery,
                "candidate_limit_reached",
                IssueSeverity::Error,
                "Leakline stopped discovery because the candidate file limit was reached.",
                Some(relative_path),
            );
            break;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                outcome.coverage.unreadable_files += 1;
                push_issue(
                    &mut outcome.issues,
                    &mut issue_sequence,
                    IssueStage::Discovery,
                    "metadata_unavailable",
                    IssueSeverity::Error,
                    "Leakline could not read file metadata.",
                    Some(relative_path),
                );
                continue;
            }
        };

        let size_bytes = metadata.len();
        if size_bytes > limits.max_file_size_bytes {
            outcome.coverage.skipped_oversized += 1;
            push_issue(
                &mut outcome.issues,
                &mut issue_sequence,
                IssueStage::Discovery,
                "file_too_large",
                IssueSeverity::Warning,
                "Leakline skipped a candidate file because it exceeds the configured size limit.",
                Some(relative_path),
            );
            continue;
        }

        outcome.coverage.selected_files += 1;
        outcome.coverage.selected_bytes += size_bytes;
        outcome.files.push(DiscoveredFile {
            absolute_path: path.to_path_buf(),
            relative_path,
            size_bytes,
        });
        report_progress(&mut on_progress, &outcome.coverage);
    }

    outcome
}

fn report_progress(
    on_progress: &mut impl FnMut(&CoverageSummary),
    coverage: &CoverageSummary,
) {
    if coverage.discovered_files == 1 || coverage.discovered_files % 250 == 0 {
        on_progress(coverage);
    }
}

fn is_vcs_metadata(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | ".hg" | ".svn")
    )
}

fn push_issue(
    issues: &mut Vec<ScanIssue>,
    issue_sequence: &mut u64,
    stage: IssueStage,
    code: &str,
    severity: IssueSeverity,
    message: &str,
    relative_path: Option<String>,
) {
    *issue_sequence += 1;
    issues.push(ScanIssue {
        issue_id: format!("discovery-{}", issue_sequence),
        stage,
        code: code.to_owned(),
        severity,
        message: message.to_owned(),
        relative_path,
        scanner_id: None,
    });
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::discover;
    use crate::scanner::limits::ScanLimits;

    static NEXT_FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

    fn fixture_path(name: &str) -> PathBuf {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "leakline-discovery-test-{}-{}-{}",
            std::process::id(),
            name,
            id
        ))
    }

    #[test]
    fn records_vcs_exclusions_and_oversized_candidates() {
        let root = fixture_path("coverage");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/config"), "should not be discovered").unwrap();
        fs::write(root.join("eligible.rs"), "fn main() {}").unwrap();
        fs::write(root.join("ignored.bin"), "not a candidate").unwrap();
        fs::write(root.join("large.env"), "0123456789").unwrap();

        let cancellation = AtomicBool::new(false);
        let outcome = discover(
            &root,
            ScanLimits {
                max_file_size_bytes: 8,
                max_candidate_files: 100,
            },
            &cancellation,
            |_| {},
        );

        assert_eq!(outcome.coverage.selected_files, 0);
        assert_eq!(outcome.coverage.excluded_vcs_entries, 1);
        assert_eq!(outcome.coverage.skipped_by_policy, 1);
        assert_eq!(outcome.coverage.skipped_oversized, 2);
        assert!(outcome
            .issues
            .iter()
            .any(|issue| issue.code == "file_too_large"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_candidate_limit_as_partial_coverage() {
        let root = fixture_path("limit");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("one.rs"), "one").unwrap();
        fs::write(root.join("two.rs"), "two").unwrap();

        let cancellation = AtomicBool::new(false);
        let outcome = discover(
            &root,
            ScanLimits {
                max_file_size_bytes: 100,
                max_candidate_files: 1,
            },
            &cancellation,
            |_| {},
        );

        assert!(outcome.coverage.candidate_limit_reached);
        assert_eq!(outcome.coverage.selected_files, 1);
        assert!(outcome
            .issues
            .iter()
            .any(|issue| issue.code == "candidate_limit_reached"));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reports_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let root = fixture_path("symlink");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("real.rs"), "real").unwrap();
        symlink(root.join("real.rs"), root.join("linked.rs")).unwrap();

        let cancellation = AtomicBool::new(false);
        let outcome = discover(&root, ScanLimits::default(), &cancellation, |_| {});

        assert_eq!(outcome.coverage.selected_files, 1);
        assert_eq!(outcome.coverage.skipped_symlinks, 1);
        assert!(outcome
            .issues
            .iter()
            .any(|issue| issue.code == "symlink_skipped"));
        fs::remove_dir_all(root).unwrap();
    }
}
