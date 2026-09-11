#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    pub max_file_size_bytes: u64,
    pub max_candidate_files: u64,
    pub max_total_bytes_read: u64,
    pub max_external_scanner_runtime: u64,
    pub max_external_output_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 10 * 1024 * 1024,
            max_candidate_files: 100_000,
            max_total_bytes_read: 1_000_000_000,
            max_external_scanner_runtime: 300,
            max_external_output_bytes: 50 * 1024 * 1024,
        }
    }
}
