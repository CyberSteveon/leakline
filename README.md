# Leakline

A desktop security scanner built for IT teams, MSPs, and sysadmins. Leakline performs local, on-premises file scanning for secrets, vulnerabilities, and environment-specific misconfigurations — no data leaves your machine.

Built with Tauri v2, Rust, and React.

---

## Features

- **Secrets detection** via Gitleaks integration
- **Static analysis** via Semgrep integration
- **Custom pattern matching** for AD/SCCM and SAP environments
- **File system scanning** with allowlist-based filtering
- **Severity classification** — Minimal, Low, Medium, High, Critical
- Fully local — no cloud dependency, no telemetry

---

## Tech Stack

| Layer | Technology |
|---|---|
| Desktop shell | Tauri v2 |
| Backend / scanning engine | Rust |
| Frontend | React + JavaScript |
| Secrets detection | Gitleaks |
| Static analysis | Semgrep |

---

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Node.js](https://nodejs.org/)
- [Gitleaks](https://github.com/gitleaks/gitleaks) installed and on PATH
- [Semgrep](https://semgrep.dev/docs/getting-started/) installed and on PATH

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
git clone https://github.com/CyberSteveon/leaklin.git
Set-Location leaklin

# Install frontend dependencies
npm install

# Run in development mode
npm run tauri dev
```

---

## Project Structure


leakline/
├── src/                  # React frontend
├── src-tauri/
│   ├── src/
│   │   ├── main.rs       # Entry point only
│   │   └── lib.rs        # All commands, structs, and Tauri setup
│   ├── Cargo.toml
│   └── Cargo.lock
└── package.json


---

## Status

Currently in active development.

- [x] Phase 0 — Project scaffolding
- [x] Phase 1 — Core types and Tauri command setup
- [x] Phase 2 — File scanning engine (walkdir)
- [ ] Phase 3 — Pattern-based vulnerability detection
- [ ] Phase 4 — Gitleaks and Semgrep integration
- [ ] Phase 5 — Frontend UI and results display

---

## Author

Steven — [github.com/CyberSteveon](https://github.com/CyberSteveon)
