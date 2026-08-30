use serde::Serialize;
use walkdir::WalkDir;

// Data structures for scan results

#[derive(Debug, Serialize, Clone)]
enum Severity {
  Minimal,
  Low,
  Medium,
  High,
  Critical,
}

#[derive(Debug, Serialize)]
struct FindingVuln {
  pub title: String,
  pub id: String,
  pub description: String,
  pub severity: Severity,
  pub file: String,
  pub line: usize,
}

#[derive(Debug, Serialize)]
struct ScanResult {
  pub path: String,
  pub findings: Vec<FindingVuln>,
  pub scan_time: String,
}

// Allowlist for file extensions — add new extensions here as needed
const ALLOWED_EXTENSIONS: &[&str] = &[
    // Systems & Compiled
    "rs", "c", "cpp", "cs", "go", "java", "swift", "kt", "dart", "scala",
    // Scripting
    "py", "rb", "php", "lua",
    "sh", "bash", "zsh", "fish",       // shell variants
    "bat", "cmd", "vbs",               // Windows scripting
    "ps1", "psm1", "psd1",             // PowerShell script, module, data
    // Web
    "js", "ts", "jsx", "tsx",          // includes React component files
    "html", "htm", "css", "scss",
    // Data & Config
    "json", "yaml", "yml", "toml",
    "xml", "ini", "cfg", "conf",
    "properties", "env", "config",
    // IaC & Cloud
    "tf", "tfvars", "hcl", "bicep", "template",
    // Certs & Keys — highest priority
    "pem", "key", "pub",
    "crt", "cer", "csr",
    "p12", "pfx", "jks",
    // Database & API
    "sql", "prisma", "graphql", "gql",
    // Package & Dependency
    "gradle", "lock", "mod",
    // SAP
    "abap",
    // Group Policy
    "admx", "adml", "pol",
    // Docs — credentials appear in logs and notes
    "md", "txt", "log",
];

// Exact filename matches
const ALLOWED_FILENAMES: &[&str] = &[
    ".npmrc",           // npm auth tokens
    ".yarnrc",          // yarn config
    ".htaccess",        // Apache auth rules
    ".editorconfig",    // editor config
    ".dockerignore",    // docker ignore
    ".profile",         // shell profile
    "Procfile",         // Heroku
    "Gemfile",          // Ruby
    "Pipfile",          // Python
    "go.sum",           // Go dependency checksums
];

// Checks if a file extension is in the allowlist
// Accepts Option<&OsStr> directly from .extension() — conversion handled internally
pub fn is_allowed_extension(ext: Option<&std::ffi::OsStr>) -> bool {
    let ext_str = match ext.and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return false,
    };
    ALLOWED_EXTENSIONS.contains(&ext_str)
}

// Checks if a filename matches any known sensitive file pattern
// Accepts Option<&OsStr> directly from .file_name() — conversion handled internally
pub fn is_allowed_filename(filename: Option<&std::ffi::OsStr>) -> bool {
    let name = match filename.and_then(|s| s.to_str()) {
        Some(s) => s.to_lowercase(),
        None => return false,
    };

    // prefix families — catches Dockerfile.malicious, Jenkinsfile_backup etc
    let prefixes = ["dockerfile", "jenkinsfile", "makefile", "vagrantfile"];

    // starts_with families — catches .env.production, .gitconfig, .bashrc, .zshenv etc
    let starts_with = [".env", ".git", ".bash", ".zsh"];

    // ends_with families — catches backup.env, prod.env, local.env etc
    let ends_with = [".env"];

    // order matters — cheapest checks first, any() short circuits on first true
    prefixes.iter().any(|p| name.starts_with(p))
    || starts_with.iter().any(|p| name.starts_with(p))
    || ends_with.iter().any(|p| name.ends_with(p))
    // exact matches pulled from const — single source of truth, no duplication
    || ALLOWED_FILENAMES.iter().any(|p| name.as_str() == *p)
}

// Tauri Commands

#[tauri::command]
fn app_info() -> String {
  let app_name = "leakline";
  let version = "0.1.0";

  format!("{}\nVersion: {}", app_name, version)
}
// Walks a directory recursively and returns all files matching the allowlist
#[tauri::command]
fn scan_directory(path: String) -> Vec<String> {
    WalkDir::new(&path)               // &path borrows the String for WalkDir
        .into_iter()
        .filter_map(|e| e.ok())              // drop permission/IO errors silently
        .filter(|e| e.file_type().is_file()) // skip directories
        .filter(|e| {                         // allowlist gate — extension OR filename
            is_allowed_extension(e.path().extension())
            || is_allowed_filename(e.path().file_name())
        })
        .map(|e| e.path().to_string_lossy().to_string()) // PathBuf → String for JS
        .collect()                            // pull into Vec<String>
}
// Tauri Application Setup

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .invoke_handler(tauri::generate_handler![app_info, scan_directory]) 
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}