use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use super::models::{ScanCommandError, ScanTargetSummary};

#[derive(Debug, Clone)]
pub struct ValidatedTarget {
    pub canonical_path: PathBuf,
    pub summary: ScanTargetSummary,
}

#[cfg(windows)]
pub fn normalize_path(path_str: &str) -> String {
    let mut s = path_str.replace('\\', "/");
    if s.starts_with("//?/") {
        if s.starts_with("//?/UNC/") {
            s = format!("//{}", &s[8..]);
        } else {
            s = s[4..].to_string();
        }
    }
    s
}

#[cfg(not(windows))]
pub fn normalize_path(path_str: &str) -> String {
    path_str.to_string()
}

fn is_same_file(meta1: &fs::Metadata, meta2: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        meta1.dev() == meta2.dev() && meta1.ino() == meta2.ino()
    }
    #[cfg(windows)]
    {
        if let (Some(vol1), Some(vol2), Some(idx1), Some(idx2)) = (
            meta1.volume_serial_number(),
            meta2.volume_serial_number(),
            meta1.file_index(),
            meta2.file_index(),
        ) {
            vol1 == vol2 && idx1 == idx2
        } else {
            false
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

pub fn validate_target(target_path: &str) -> Result<ValidatedTarget, ScanCommandError> {
    if target_path.trim().is_empty() {
        return Err(ScanCommandError::new(
            "invalid_target",
            "A scan target directory is required.",
        ));
    }

    let submitted_path = Path::new(target_path);

    let canonical_path = fs::canonicalize(submitted_path).map_err(|_| {
        ScanCommandError::new(
            "target_unavailable",
            "The selected scan target could not be resolved.",
        )
    })?;

    let submitted_metadata = fs::symlink_metadata(submitted_path).map_err(|_| {
        ScanCommandError::new(
            "target_unavailable",
            "The selected scan target could not be accessed.",
        )
    })?;

    let canonical_metadata = fs::symlink_metadata(&canonical_path).map_err(|_| {
        ScanCommandError::new(
            "target_unavailable",
            "The selected scan target could not be accessed.",
        )
    })?;

    if submitted_metadata.file_type().is_symlink() {
        return Err(ScanCommandError::new(
            "symlink_target",
            "Symbolic-link targets are not supported.",
        ));
    }

    if !is_same_file(&submitted_metadata, &canonical_metadata) {
        return Err(ScanCommandError::new(
            "target_unavailable",
            "The scan target was modified during validation.",
        ));
    }

    if !canonical_metadata.is_dir() {
        return Err(ScanCommandError::new(
            "invalid_target_type",
            "The scan target must be a directory.",
        ));
    }

    let display_path_raw = canonical_path.to_str().map(str::to_owned).ok_or_else(|| {
        ScanCommandError::new(
            "unsupported_target_path",
            "The selected scan target path cannot be represented safely.",
        )
    })?;

    let display_path = normalize_path(&display_path_raw);

    Ok(ValidatedTarget {
        canonical_path,
        summary: ScanTargetSummary { display_path },
    })
}

pub fn relative_path_display(root: &Path, path: &Path) -> String {
    let relative_path = path.strip_prefix(root).unwrap_or(path);

    let raw = relative_path
        .to_str()
        .map(str::to_owned)
        .unwrap_or_else(|| relative_path.to_string_lossy().into_owned());
    normalize_path(&raw)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{validate_target, normalize_path};

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
            normalize_path(&target.canonical_path.display().to_string())
        );
        fs::remove_dir_all(directory_path).unwrap();
    }
}
