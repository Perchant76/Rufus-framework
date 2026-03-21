# ProbeScan — Professional Penetration Testing Framework

A native desktop application built with **Tauri 2 + Rust + React** for professional web and server penetration testing.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Shell | Tauri 2 (Rust) |
| Frontend | React 18 + TypeScript + Vite |
| Storage | SQLite via sqlx |
| Subprocess | tokio::process::Command |
| Styling | CSS custom properties, JetBrains Mono + Syne |

---

## Prerequisites

### System dependencies

**macOS:**
```bash
xcode-select --install
brew install cmake
```

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install -y \
  libwebkit2gtk-4.1-dev build-essential curl wget file \
  libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

**Windows:**
- Install [Microsoft Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- Install [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/)

### Language runtimes
```bash
# Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Node.js 18+ (use nvm or brew)
brew install node       # macOS
sudo apt install nodejs npm  # Ubuntu

# Go (for go-based tools)
brew install go         # macOS
sudo apt install golang # Ubuntu
```

---

## Install External Scanning Tools

ProbeScan wraps these CLI tools. Install each one you want to use:

```bash
# subfinder — subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# katana — web crawler
go install github.com/projectdiscovery/katana/cmd/katana@latest

# nuclei — vulnerability scanner
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates   # download template library

# feroxbuster — directory brute-force
cargo install feroxbuster

# nmap — port scanner (requires root/sudo for SYN scan)
brew install nmap          # macOS
sudo apt install nmap      # Ubuntu

# testssl.sh — TLS analyzer
brew install testssl       # macOS
sudo apt install testssl   # Ubuntu (or download from testssl.sh)

# wapiti3 — web vulnerability scanner
pip install wapiti3

# whatweb — technology fingerprinting
sudo apt install whatweb   # Ubuntu
gem install whatweb        # macOS (requires ruby)
```

After installing, the **Target & Scope** tab shows availability of each tool at startup.

---

## Project Setup

```bash
# 1. Clone / copy project
cd probescan

# 2. Install frontend dependencies
npm install

# 3. Run in development mode (hot-reload)
npm run tauri dev

# 4. Build production binary
npm run tauri build
```

The built binary will be in `src-tauri/target/release/` and installer packages in `src-tauri/target/release/bundle/`.

---

## Project Structure

```
probescan/
├── src/                          # React frontend
│   ├── App.tsx                   # Root component, global state
│   ├── index.css                 # Design tokens, base styles
│   ├── main.tsx                  # React entry point
│   ├── types/index.ts            # All TypeScript types
│   ├── lib/api.ts                # Tauri invoke wrappers
│   └── components/
│       ├── ui/index.tsx          # Shared UI primitives
│       └── tabs/
│           ├── TabTarget.tsx     # Target, scope, auth, tool config
│           ├── TabDiscovery.tsx  # Subdomain tree, live log, assets
│           ├── TabActiveScan.tsx # Tool selection, scan control, progress
│           ├── TabVulns.tsx      # Finding list, filters, detail expand
│           ├── TabComparison.tsx # Multi-scan diff, persistence tracking
│           └── TabExport.tsx     # PDF, CSV, Burp, Caido export
│
├── src-tauri/                    # Rust backend
│   ├── build.rs
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── capabilities/default.json
│   └── src/
│       ├── main.rs               # Binary entry point
│       ├── lib.rs                # App setup, state, command registration
│       ├── commands/
│       │   ├── mod.rs
│       │   ├── scan.rs           # create_scan, start_scan, stop_scan
│       │   ├── findings.rs       # get_findings, delete_finding
│       │   ├── tools.rs          # check_all_tools
│       │   ├── comparison.rs     # compare_scans + export commands
│       │   └── export.rs         # re-exports
│       ├── db/
│       │   ├── mod.rs            # Pool init
│       │   ├── models.rs         # All Rust structs (Scan, VulnFinding, …)
│       │   ├── migrations.rs     # CREATE TABLE statements
│       │   ├── scans.rs          # Scan CRUD
│       │   ├── findings.rs       # Finding CRUD + comparison queries
│       │   └── assets.rs         # DiscoveredAsset CRUD
│       ├── scanner/
│       │   ├── mod.rs
│       │   ├── scope.rs          # ScopeEngine (domain/CIDR matching)
│       │   ├── runner.rs         # SubprocessRunner + Tauri event emitter
│       │   └── tools.rs          # Tool availability checker
│       └── parsers/
│           ├── mod.rs            # ToolParser trait
│           ├── subfinder.rs      # JSONL → assets
│           ├── feroxbuster.rs    # JSONL → findings
│           ├── katana.rs         # JSONL → endpoints + findings
│           ├── nmap.rs           # XML → port findings + CVE matching
│           ├── nuclei.rs         # JSONL → findings with CVE/CVSS
│           ├── testssl.rs        # JSON → TLS findings
│           ├── whatweb.rs        # JSON → tech fingerprint findings
│           └── wapiti.rs         # JSON → OWASP findings
│
├── .cursor/rules/main.mdc        # Cursor AI rules (always-apply)
├── package.json
├── tsconfig.json
├── vite.config.ts
└── README.md
```

---

## Scan Flow

```
User clicks ▶ Scan
     │
     ▼
start_scan (Rust Tauri command)
     │
     ├── Phase 1: Discovery
     │     ├── subfinder  → subdomains → DiscoveredAsset rows → scan_asset events
     │     ├── katana     → endpoints  → DiscoveredAsset rows
     │     └── feroxbuster → paths    → VulnFinding rows → scan_finding events
     │
     ├── Phase 2: Port/Service Scan
     │     └── nmap → open ports → VulnFinding rows (per port classification + CVE lookup)
     │
     └── Phase 3: Vulnerability Scan
           ├── nuclei    → OWASP/CVE templates → VulnFinding rows
           ├── wapiti3   → active web scan     → VulnFinding rows
           ├── testssl.sh → TLS analysis       → VulnFinding rows
           └── whatweb   → tech fingerprinting → VulnFinding rows

All findings → scope check (ScopeEngine) → SQLite → scan_finding event → React UI
```

---

## Stealth Mode

When Stealth Mode is enabled:
- Concurrency forced to 1 thread
- Randomized delay between requests (configurable min/max ms)
- User-agent rotation from browser UA list
- subfinder uses `-passive` flag (CT logs + OSINT only, no DNS brute-force)
- katana disables `-xhr` aggressive crawling
- nuclei rate-limited to 10 req/s
- robots.txt respected

---

## Adding a New Tool

1. Add parser in `src-tauri/src/parsers/yournewparser.rs` implementing `ToolParser`
2. Add `ToolDef` entry in `src-tauri/src/scanner/tools.rs`
3. Add invocation block in `src-tauri/src/commands/scan.rs`
4. Add to `ALL_TOOLS` in `src/types/index.ts`
5. Re-run `npm run tauri dev`

---

## Notes

- **No root required** for most scans. nmap SYN scan (`-sS`) requires root/sudo; the app falls back to TCP connect scan if not elevated.
- **SQLite** database stored in OS app data dir (`~/.local/share/probescan/` on Linux, `~/Library/Application Support/probescan/` on macOS).
- **Scope engine** checks every discovered asset before active scanning. Out-of-scope assets are stored and displayed but never actively probed.
- **Export HTML report** can be converted to PDF via browser print-to-PDF or `wkhtmltopdf`.
