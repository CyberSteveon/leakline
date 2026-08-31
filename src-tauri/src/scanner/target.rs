use std::fs;
use std::path::{Path, PathBuf};

use super::models::{ScanCommandError, ScanTargetSummary};

#[derive(Debug, Clone)]
pub struct ValidatedTarget {
    pub canonical_path: PathBuf,
    pub summary: ScanTargetSummary,
}

pub fn validate_target(target_path: &str) -> Result<ValidatedTarget, ScanCommandError> {
    if target_path.trim().is_empty() {
        return Err(ScanCommandError::new(
            "invalid_target",
            "A scan target directory is required.",
        ));
    }

    let submitted_path = Path::new(target_path);
    let metadata = fs::symlink_metadata(submitted_path).map_err(|_| {
        ScanCommandError::new(
            "target_unavailable",
            "The selected scan target could not be accessed.",
        )
    })?;

    if metadata.file_type().is_symlink() {
        return Err(ScanCommandError::new(
            "symlink_target",
            "Symbolic-link targets are not supported.",
        ));
    }

    if !metadata.is_dir() {
        return Err(ScanCommandError::new(
            "invalid_target_type",
            "The scan target must be a directory.",
        ));
    }

    let canonical_path = fs::canonicalize(submitted_path).map_err(|_| {
        ScanCommandError::new(
            "target_unavailable",
            "The selected scan target could not be resolved.",
        )
    })?;

    let display_path = canonical_path.to_str().map(str::to_owned).ok_or_else(|| {
        ScanCommandError::new(
            "unsupported_target_path",
            "The selected scan target path cannot be represented safely.",
        )
    })?;

    Ok(ValidatedTarget {
        canonical_path,
        summary: ScanTargetSummary { display_path },
    })
}

pub fn relative_path_display(root: &Path, path: &Path) -> String {
    let relative_path = path.strip_prefix(root).unwrap_or(path);

    relative_path
        .to_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{:?}", relative_path))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::validate_target;

    static NEXT_FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);

    fn fixture_path(name: &str) -> PathBuf {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "leakline-target-test-{}-{}-{}",
            std::process::id(),
            name,
            id
        ))
    }

    #[test]
    fn rejects_a_file_target() {
        let file_path = fixture_path("file");
        fs::write(&file_path, "fixture").unwrap();

        let error = validate_target(file_path.to_str().unwrap()).unwrap_err();

        assert_eq!(error.code, "invalid_target_type");
        fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn canonicalizes_a_directory_target() {
        let directory_path = fixture_path("directory");
        fs::create_dir_all(&directory_path).unwrap();

        let target = validate_target(directory_path.to_str().unwrap()).unwrap();

        assert!(target.canonical_path.is_absolute());
        assert_eq!(
            target.summary.display_path,
            target.canonical_path.display().to_string()
        );
        fs::remove_dir_all(directory_path).unwrap();
    }
}
