use std::ffi::OsStr;

// Allowlist for file extensions — add new extensions here as needed.
const ALLOWED_EXTENSIONS: &[&str] = &[
    // Systems & Compiled
    "rs",
    "c",
    "cpp",
    "cs",
    "go",
    "java",
    "swift",
    "kt",
    "dart",
    "scala",
    // Scripting
    "py",
    "rb",
    "php",
    "lua",
    "sh",
    "bash",
    "zsh",
    "fish", // shell variants
    "bat",
    "cmd",
    "vbs", // Windows scripting
    "ps1",
    "psm1",
    "psd1", // PowerShell script, module, data
    // Web
    "js",
    "ts",
    "jsx",
    "tsx", // includes React component files
    "html",
    "htm",
    "css",
    "scss",
    // Data & Config
    "json",
    "yaml",
    "yml",
    "toml",
    "xml",
    "ini",
    "cfg",
    "conf",
    "properties",
    "env",
    "config",
    // IaC & Cloud
    "tf",
    "tfvars",
    "hcl",
    "bicep",
    "template",
    // Certs & Keys — highest priority
    "pem",
    "key",
    "pub",
    "crt",
    "cer",
    "csr",
    "p12",
    "pfx",
    "jks",
    // Database & API
    "sql",
    "prisma",
    "graphql",
    "gql",
    // Package & Dependency
    "gradle",
    "lock",
    "mod",
    // SAP
    "abap",
    // Group Policy
    "admx",
    "adml",
    "pol",
    // Docs — credentials appear in logs and notes
    "md",
    "txt",
    "log",
];

// Exact filename matches.
const ALLOWED_FILENAMES: &[&str] = &[
    ".npmrc",        // npm auth tokens
    ".yarnrc",       // yarn config
    ".htaccess",     // Apache auth rules
    ".editorconfig", // editor config
    ".dockerignore", // docker ignore
    ".profile",      // shell profile
    "procfile",      // Heroku
    "gemfile",       // Ruby
    "pipfile",       // Python
    "go.sum",        // Go dependency checksums
];

// Checks if a file extension is in the allowlist.
// Accepts Option<&OsStr> directly from .extension() — conversion handled internally.
pub fn is_allowed_extension(ext: Option<&OsStr>) -> bool {
    let ext_str = match ext.and_then(|value| value.to_str()) {
        Some(value) => value.to_ascii_lowercase(),
        None => return false,
    };

    ALLOWED_EXTENSIONS.contains(&ext_str.as_str())
}

// Checks if a filename matches any known sensitive file pattern.
// Accepts Option<&OsStr> directly from .file_name() — conversion handled internally.
pub fn is_allowed_filename(filename: Option<&OsStr>) -> bool {
    let name = match filename.and_then(|value| value.to_str()) {
        Some(value) => value.to_ascii_lowercase(),
        None => return false,
    };

    // prefix families — catches Dockerfile.malicious, Jenkinsfile_backup etc
    let prefixes = ["dockerfile", "jenkinsfile", "makefile", "vagrantfile"];

    // starts_with families — catches .env.production, .gitconfig, .bashrc, .zshenv etc
    let starts_with = [".env", ".git", ".bash", ".zsh"];

    // ends_with families — catches backup.env, prod.env, local.env etc
    let ends_with = [".env"];

    // Order matters — cheapest checks first, any() short circuits on first true.
    prefixes.iter().any(|prefix| name.starts_with(prefix))
        || starts_with.iter().any(|prefix| name.starts_with(prefix))
        || ends_with.iter().any(|suffix| name.ends_with(suffix))
        // Exact matches pulled from const — single source of truth, no duplication.
        || ALLOWED_FILENAMES.iter().any(|allowed| name.as_str() == *allowed)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::{is_allowed_extension, is_allowed_filename};

    #[test]
    fn accepts_case_insensitive_extensions_and_exact_filenames() {
        assert!(is_allowed_extension(Some(OsStr::new("RS"))));
        assert!(is_allowed_filename(Some(OsStr::new("Procfile"))));
        assert!(is_allowed_filename(Some(OsStr::new("Gemfile"))));
        assert!(is_allowed_filename(Some(OsStr::new("Pipfile"))));
    }
}
