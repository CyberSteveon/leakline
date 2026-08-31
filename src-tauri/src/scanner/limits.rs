#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    pub max_file_size_bytes: u64,
    pub max_candidate_files: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 10 * 1024 * 1024,
            max_candidate_files: 100_000,
        }
    }
}
