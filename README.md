# Leakline

A desktop security scanner built for IT teams, MSPs, and sysadmins. Leakline performs local, on-premises file scanning for secrets, vulnerabilities, and environment-specific misconfigurations — no data leaves your machine.

Built with Tauri v2, Rust, and React.

---

## Features

- **Secrets detection** via Gitleaks integration
- **Static analysis** via Semgrep integration
- **Custom pattern matching** for AD/SCCM and SAP environments with a native Rust scanning engine
- **Dynamic Dependency Management** — one-click download/uninstall for third-party scanners (Gitleaks & Semgrep) directly from the UI
- **File system scanning** with allowlist-based filtering and memory-safe chunking
- **Severity classification** — Minimal, Low, Medium, High, Critical
- **Sleek Security Dashboard** — Dark-themed React UI with real-time scan progress and native OS folder selection
- Fully local — no cloud dependency, no telemetry

---

## Tech Stack

| Layer | Technology |
|---|---|
| Desktop shell | Tauri v2 |
| Backend / scanning engine | Rust |
| Frontend | React + JavaScript |
| Secrets detection | Gitleaks (Dynamically Managed) |
| Static analysis | Semgrep (Dynamically Managed) |

---

## Prerequisites

To build and run Leakline from source, you will need:
- [Rust](https://www.rust-lang.org/tools/install)
- [Node.js](https://nodejs.org/)

*(Note: Gitleaks and Semgrep are **not** required to be on your system PATH. Leakline features an internal dependency manager that will securely download them to your local app data directory.)*

---

## Getting Started

```bash
# Clone the repo
git clone https://github.com/CyberSteveon/leakline.git
cd leakline

# Install frontend dependencies
npm install

# Run in development mode
npm run tauri dev
```

```powershell (windows)
# Clone the repo
git clone https://github.com/CyberSteveon/leakline.git
Set-Location leakline

# Install frontend dependencies
npm install

# Run in development mode
npm run tauri dev
```

---

## How to Use

1. **Launch the App:** Open Leakline via `npm run tauri dev` or by launching the built executable.
2. **Manage Dependencies:** On the dashboard, you can optionally click **Install Missing** for Gitleaks and Semgrep to enable advanced static analysis and secrets detection. If you skip this, Leakline will gracefully fall back to its native Rust scanning engine.
3. **Select a Target:** Click the **Browse** button to open your OS's native file picker and select the project directory you want to scan.
4. **Scan:** Click **Start Scan**. You will see real-time progress as Leakline discovers files and processes them.
5. **Review Results:** Once complete, review the aggregated findings in the table, categorized by severity, to locate vulnerabilities and hardcoded secrets.

---

## Project Structure

```text
leakline/
├── src/                  # React frontend
├── __tests__/            # Frontend unit tests
├── src-tauri/
│   ├── src/
│   │   ├── scanner/      # Core scanning engine module
│   │   ├── commands.rs   # Tauri commands
│   │   ├── lib.rs        # App setup and routing
│   │   └── main.rs       # Entry point
│   ├── Cargo.toml
│   └── Cargo.lock
└── package.json
```

---

## Status

Roadmap Completed!

- [x] Phase 0 — Project scaffolding
- [x] Phase 1 — Core types and Tauri command setup
- [x] Phase 2 — File scanning engine (walkdir)
- [x] Phase 3 — Pattern-based vulnerability detection
- [x] Phase 4 — Gitleaks and Semgrep integration
- [x] Phase 5 — Frontend UI and results display

---

## Author

Steven — [github.com/CyberSteveon](https://github.com/CyberSteveon)
