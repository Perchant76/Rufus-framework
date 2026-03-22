# ProbeScan — AI Feature Upgrade Prompt

## How to use this
Paste the entire contents of this file into Cursor (or Claude Code) at the start of a new session,
followed by: "Implement [FEATURE NAME] as described below."
Work through features one at a time. Each section is self-contained.

---

## Project Context

ProbeScan is a professional penetration testing desktop app built with:
- **Backend:** Rust + Tauri 2
- **Frontend:** React 18 + TypeScript + Vite
- **Storage:** Flat JSON files (no database) in app data dir
- **Theme:** Dark, blood-red accent (#e8001a), JetBrains Mono + Syne fonts
- **Architecture:** Tauri commands (`invoke()`), events streamed via `listen()`
- **Data dir:** `%APPDATA%\com.probescan.pentest\scans\` on Windows

The app already has: subdomain enum, web crawling, dir brute-force, port scanning,
nuclei vuln scanning, TLS analysis, tech fingerprinting, wapiti OWASP scanning,
scope engine, stealth mode, scan comparison, PDF/CSV/Burp/Caido export.

All new Rust commands must follow this pattern:
```rust
#[tauri::command]
pub async fn command_name(state: State<'_, Mutex<AppState>>) -> Result<ReturnType, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    // ... logic
}
```

Never hold MutexGuard across an .await point — always drop it in a block first.

---

## FEATURE 1 — Bug Bounty Program Manager

**Inspired by:** ars0n-framework's scope target system (Company / Wildcard / URL types)

### What to build
A new "Programs" tab that manages a list of bug bounty programs the user is hunting on.
Each program has:
- Name (e.g. "Google VRP")
- Type: `company` | `wildcard` | `url`
- Platform: HackerOne / Bugcrowd / Intigriti / YesWeHack / Custom
- In-scope assets (domains, wildcards, IP ranges)
- Out-of-scope assets
- Max bounty (optional, for prioritisation)
- Notes
- Linked scans (list of scan IDs run against this program)

### Storage
Add `programs.json` to the store dir. Each program is a struct:
```rust
pub struct BugBountyProgram {
    pub id: String,
    pub name: String,
    pub program_type: String,   // "company" | "wildcard" | "url"
    pub platform: String,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub max_bounty: Option<u32>,
    pub notes: String,
    pub scan_ids: Vec<String>,
    pub created_at: String,
}
```

### Tauri commands needed
- `create_program(program: BugBountyProgram) -> BugBountyProgram`
- `list_programs() -> Vec<BugBountyProgram>`
- `update_program(program: BugBountyProgram) -> BugBountyProgram`
- `delete_program(id: String) -> ()`
- `link_scan_to_program(program_id: String, scan_id: String) -> ()`

### UI
- Card grid of programs with platform badge, type badge, finding count
- Click to expand — shows full scope, linked scans, notes editor
- "Start Scan" button pre-fills the Target & Scope tab with program scope
- Filter by platform, sort by max bounty or finding count
- Color-code platforms: HackerOne=green, Bugcrowd=orange, Intigriti=red

---

## FEATURE 2 — Attack Surface Map (Visual)

**Inspired by:** ars0n-framework's asset relationship visualization

### What to build
A new "Attack Surface" tab showing a force-directed graph of the discovered asset tree.
Nodes = subdomains/IPs/endpoints. Edges = parent→child relationships.
Built with a simple SVG canvas (no D3, use React state + SVG directly for simplicity).

### Layout
- Root domain in center, large node
- Subdomains as medium nodes radiating outward
- Endpoints as small nodes on subdomain edges
- Color by status: green=200, yellow=301/302, red=403/404, grey=unknown
- Size by finding count (bigger = more vulnerabilities)
- Click a node → side panel shows IP, tech stack, finding list for that asset
- Zoom in/out with scroll wheel (scale transform)
- Toggle: show/hide endpoints (too many can crowd the view)
- Export as SVG button

### Data source
Uses existing `DiscoveredAsset[]` from the current scan's assets file.
Build the tree by grouping `asset_type === "subdomain"` using `parent` field.

---

## FEATURE 3 — Methodology Workflow Engine

**Inspired by:** ars0n-framework's forced methodology approach

### What to build
A guided workflow system that walks users through a structured recon methodology.
Located in a new "Workflow" tab.

Three workflow modes (matching ars0n's approach):
1. **Company Hunt** — Start with company name, discover ASNs → root domains → subdomains → vulns
2. **Wildcard Hunt** — Start with `*.example.com`, enumerate → fingerprint → scan
3. **Single Target** — Start with one URL, crawl → fuzz → vuln scan

Each workflow is a series of **stages**. Each stage has:
- Name + description
- Which tools to run
- What the output feeds into the next stage
- A "Why does this matter?" explanation box (the learning component)
- Status: locked / ready / running / complete / skipped

### Storage
```rust
pub struct WorkflowRun {
    pub id: String,
    pub workflow_type: String,
    pub target: String,
    pub current_stage: usize,
    pub stages: Vec<WorkflowStage>,
    pub created_at: String,
}
pub struct WorkflowStage {
    pub name: String,
    pub description: String,
    pub why: String,
    pub tools: Vec<String>,
    pub status: String,
    pub findings_count: usize,
    pub completed_at: Option<String>,
}
```

### UI
- Visual pipeline: horizontal stage cards connected by arrows
- Current stage highlighted in blood red with pulsing border
- Completed stages show finding count badge
- Locked future stages shown greyed out
- Clicking a stage expands the "Why does this matter?" panel
- "Run This Stage" button triggers the relevant tools

---

## FEATURE 4 — Custom Wordlist Builder

**Inspired by:** ars0n-framework's CeWL integration

### What to build
A wordlist management system. Users can:
- Import wordlists from file (drag & drop txt/csv)
- Generate a wordlist by spidering a URL (runs `cewl` if available, falls back to built-in crawler extracting visible words)
- View/filter/edit the wordlist
- Tag wordlists: `directories` | `subdomains` | `parameters` | `passwords`
- Select which wordlist feroxbuster uses at scan time

### Storage
Wordlists stored as `wordlists/<id>.txt` in the app data dir alongside scan JSON files.
Metadata stored in `wordlists.json`:
```rust
pub struct Wordlist {
    pub id: String,
    pub name: String,
    pub tag: String,
    pub word_count: usize,
    pub source: String,   // "imported" | "generated" | "builtin"
    pub created_at: String,
}
```

### Built-in wordlists
Bundle three small wordlists directly in the binary as `include_str!()`:
- 500 common directories (SecLists top 500)
- 200 common subdomains
- 100 common parameters

### Tauri commands
- `list_wordlists() -> Vec<Wordlist>`
- `import_wordlist(name: String, tag: String, content: String) -> Wordlist`
- `generate_wordlist_from_url(url: String, name: String) -> Wordlist`
- `delete_wordlist(id: String) -> ()`
- `get_wordlist_content(id: String) -> Vec<String>`

---

## FEATURE 5 — Nuclei Template Manager

**Inspired by:** ars0n-framework's extensive nuclei integration

### What to build
A UI for managing and selecting nuclei templates before scanning.
- Run `nuclei -tl` to list all installed templates
- Group by category: cves, exposures, misconfiguration, network, technologies
- Checkbox tree to select/deselect template groups or individual templates
- Search/filter templates by name or CVE ID
- Show template severity distribution (pie chart — simple SVG donut)
- Save template selection as named "profiles" (e.g. "Quick CVE Scan", "Full OWASP")
- Selected profile is passed to the nuclei invocation at scan time

### Storage
```rust
pub struct NucleiProfile {
    pub id: String,
    pub name: String,
    pub selected_tags: Vec<String>,    // e.g. ["cve", "xss", "sqli"]
    pub selected_severities: Vec<String>,
    pub exclude_tags: Vec<String>,
    pub created_at: String,
}
```

---

## FEATURE 6 — Live HTTP Request Interceptor / Replay

**Inspired by:** ars0n-framework's Burp/Caido integration + manual testing support

### What to build
A simple HTTP request editor and replayer built directly into ProbeScan.
No proxy needed — just a request builder + sender.

The "Replay" tab has two panels:
- **Left:** Request editor (method, URL, headers, body) — syntax-highlighted textarea
- **Right:** Response viewer (status, headers, body) — with diff mode to compare two responses

Features:
- Pre-populate from any finding's `http_request` field
- Save requests to a "request library" (stored as JSON in app data)
- Variable substitution: `{{TARGET}}`, `{{PAYLOAD}}` placeholders
- Quick payload lists for common injection tests (XSS, SQLi, SSTI, path traversal)
- Response diff: send two requests and highlight differences line by line
- "Send to Finding" — create a new finding from a replay response

### Rust side
Add a `send_http_request` Tauri command that uses `tokio` to make the actual HTTP request:
```rust
#[tauri::command]
pub async fn send_http_request(
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    follow_redirects: bool,
    timeout_secs: u64,
) -> Result<HttpResponse, String>

pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub duration_ms: u64,
    pub redirect_chain: Vec<String>,
}
```
Use `tokio::net::TcpStream` + manual HTTP/1.1 or pull in `reqwest` as a dependency.

---

## FEATURE 7 — GitHub Dorking & OSINT Module

**Inspired by:** ars0n-framework's GitHub Recon Tools

### What to build
A passive OSINT tab that runs structured searches without spawning external processes.
Uses the GitHub Search API (unauthenticated for basic, token for extended rate limits).

Search types:
- **Code search:** `"target.com" password` / `"target.com" api_key` / `"target.com" secret`
- **Commit search:** leaked credentials in commit history
- **Google dorks:** Open the user's default browser with pre-built dork queries

Dork templates (editable):
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
inurl:target.com ext:env OR ext:config
"@target.com" password filetype:txt
```

### UI
- Input: target domain
- Run button fires all dorks as separate searches
- Results table: dork query | result count | "Open in browser" button
- Manual notes field per result
- Export results as markdown report

### Storage
```rust
pub struct OsintResult {
    pub id: String,
    pub scan_id: Option<String>,
    pub source: String,         // "github" | "google_dork" | "manual"
    pub query: String,
    pub result_count: Option<u32>,
    pub url: String,
    pub notes: String,
    pub severity: String,
    pub created_at: String,
}
```

---

## FEATURE 8 — Cloud Asset Enumeration

**Inspired by:** ars0n-framework's Cloud Enum integration

### What to build
A cloud-specific recon module that checks for exposed cloud storage and services.

For a given company name or domain, check:
- **AWS S3:** `<company>.s3.amazonaws.com`, `<company>-backup.s3...`, `<company>-dev.s3...`
- **Azure Blob:** `<company>.blob.core.windows.net`
- **GCP Storage:** `<company>.storage.googleapis.com`
- **CloudFront:** detect if subdomains resolve to CloudFront distributions
- **Subdomain takeover candidates:** CNAMEs pointing to deprovisioned cloud services

Implementation: Pure Rust DNS + HTTP checks, no external tool required.
For each permutation, do a DNS lookup then HTTP HEAD request.
Flag any that return 200/403 (exists) vs 404 (not found).

```rust
pub struct CloudAsset {
    pub id: String,
    pub scan_id: String,
    pub provider: String,     // "aws_s3" | "azure_blob" | "gcp_storage"
    pub url: String,
    pub status: u16,
    pub accessible: bool,     // true if 200 or directory listing
    pub takeover_candidate: bool,
    pub checked_at: String,
}
```

Tauri command: `enumerate_cloud_assets(target: String, scan_id: String) -> Vec<CloudAsset>`

---

## FEATURE 9 — Findings Triage & Notes System

**Inspired by:** ars0n-framework's help/learning system + manual triage workflow

### What to build
Enhance the Vulnerabilities tab with a full triage workflow.

Each finding gets:
- **Triage status:** `new` | `confirmed` | `false_positive` | `needs_verification` | `reported`
- **Priority override:** ability to manually bump severity up/down
- **Notes field:** rich text notes per finding (stored in the JSON)
- **Reproduction steps:** structured field for PoC documentation
- **CVSS calculator:** interactive CVSS 3.1 scoring widget — sliders for each metric, auto-calculates score
- **Similar findings:** auto-group findings with same title across scans

### CVSS Calculator Widget
Build as a React component. CVSS 3.1 base metrics:
- Attack Vector (N/A/L/P)
- Attack Complexity (L/H)
- Privileges Required (N/L/H)
- User Interaction (N/R)
- Scope (U/C)
- Confidentiality (N/L/H)
- Integrity (N/L/H)
- Availability (N/L/H)

Formula implementation in TypeScript — no library needed, the spec is public.
Display the calculated score + vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

### Storage changes to VulnFinding
Add these fields:
```typescript
triage_status: "new" | "confirmed" | "false_positive" | "needs_verification" | "reported";
priority_override: string | null;
analyst_notes: string;
reproduction_steps: string;
cvss_vector: string | null;
reported_at: string | null;
```

---

## FEATURE 10 — Automated Subdomain Takeover Detection

**Inspired by:** ars0n-framework's DNS/subdomain analysis

### What to build
After subdomain enumeration, automatically check each discovered subdomain for
takeover vulnerabilities. A subdomain is takeover-vulnerable when:
- Its CNAME points to a third-party service that is not provisioned
- HTTP response matches a known "available" fingerprint

Check against these services and their fingerprints:
```
GitHub Pages     → "There isn't a GitHub Pages site here"
Heroku           → "No such app"
Shopify          → "Sorry, this shop is currently unavailable"
Fastly           → "Fastly error: unknown domain"
Pantheon         → "The gods are wise"
Netlify          → "Not Found - Request ID"
AWS S3           → "NoSuchBucket"
Azure            → "404 Web Site not found"
WP Engine        → "The site you were looking for couldn't be found"
```

Implementation: Pure Rust in the scanner module. For each subdomain:
1. DNS CNAME lookup
2. HTTP GET request
3. Response body match against fingerprint list

```rust
pub struct TakeoverCandidate {
    pub subdomain: String,
    pub cname: Option<String>,
    pub service: String,
    pub fingerprint_matched: String,
    pub confidence: String,   // "HIGH" | "MEDIUM" | "LOW"
}
```

Auto-creates a CRITICAL finding for HIGH confidence candidates.

---

## UI REDESIGN — Color System (Apply to ALL components)

The current blue (#00d4ff) accent must be replaced everywhere with blood red (#e8001a).
Update `src/index.css` and every component:

```css
:root {
  --accent:       #e8001a;
  --accent-dim:   rgba(232, 0, 26, 0.10);
  --accent-glow:  rgba(232, 0, 26, 0.25);
  --bg0: #080608;
  --bg1: #0e080a;
  --bg2: #130a0d;
  --bg3: #1a0d11;
  --bg4: #231318;
  --border:       #2d1218;
  --border-hi:    #4a1e28;
  --text:         #d4b8bc;
  --text-dim:     #7a4a52;
  --text-hi:      #f0dde0;
}
```

Additional UI changes:
- The logo "P" in the topbar should glow red with `animation: glow-pulse 3s infinite`
- Active tab indicator uses a blood-red underline + red text
- Severity badges stay their existing colors (red/orange/yellow/green) — don't change these
- The scan button in running state should pulse red
- Add a subtle scanline texture overlay (CSS `repeating-linear-gradient` with 2px gaps, 1.5% opacity)
- Log lines: `error` → `#ff0033`, `ok` → `#00e676`, `warn` → `#ffab00`, `info` → `#e8001a`
- Section header left bar accent → blood red
- Progress bar gradient → `#e8001a` to `#c62828`
- All focus outlines on inputs → `border-color: #e8001a`
- Card hover border → `#4a1e28`
- Stealth toggle ON state → keep green (it's a positive/safe indicator)

---

## MISSING FEATURES ANALYSIS

After reviewing ars0n-framework and ProbeScan, here are the gaps:

**Not in ProbeScan but in ars0n:**
1. ASN / IP range discovery (Metabigor, Amass Intel) — company-level recon
2. DNS bulk resolution (DNSx / ShuffleDNS) — validate which subdomains are live
3. GAU (GetAllURLs) — fetch historical URLs from Wayback Machine / CommonCrawl
4. Port scanner UI (naabu) — separate from nmap, faster SYN scanner
5. Cloud enumeration — S3/Azure/GCP asset discovery
6. GitHub recon — search for leaked secrets
7. Reverse WHOIS — find all domains owned by same registrant
8. Forced methodology / workflow engine — guided step-by-step approach
9. "Help me learn" education panel per tool
10. Import/export of entire program scan state (.rs0n format)

**Not in either — genuinely missing from the space:**
1. CVSS calculator built-in
2. HTTP request replayer (without needing Burp)
3. Subdomain takeover auto-detection
4. Custom wordlist builder with CeWL-style generation
5. Nuclei template selector UI
6. Bug bounty program manager with scope import
7. Scan scheduling (run every 24h against a target)
8. Triage workflow (new → confirmed → reported)
9. Slack/Discord webhook notifications when CRITICAL found
10. Visual attack surface graph

---

## IMPLEMENTATION ORDER (Recommended)

Start with these — highest impact, lowest complexity:

1. **UI Redesign** (1-2 hours) — Pure CSS changes, zero Rust
2. **FEATURE 9: Triage & Notes** (2-3 hours) — Just adds fields to existing findings
3. **FEATURE 10: Takeover Detection** (3-4 hours) — Pure Rust, no new UI tab needed
4. **FEATURE 1: Program Manager** (4-5 hours) — New tab + new store methods
5. **FEATURE 6: HTTP Replayer** (5-6 hours) — New tab + reqwest dependency
6. **FEATURE 8: Cloud Enum** (4-5 hours) — Pure Rust DNS/HTTP checks
7. **FEATURE 5: Nuclei Templates** (3-4 hours) — Shells out to nuclei -tl
8. **FEATURE 4: Wordlist Builder** (4-5 hours) — File I/O + built-in wordlists
9. **FEATURE 3: Workflow Engine** (6-8 hours) — Complex state machine
10. **FEATURE 2: Attack Surface Map** (8-10 hours) — SVG force graph

---

## DEPENDENCY ADDITIONS (Cargo.toml)

For FEATURE 6 (HTTP Replayer), add:
```toml
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
```

For FEATURE 10 (Takeover + Cloud DNS):
```toml
hickory-resolver = { version = "0.24", features = ["tokio-runtime"] }
```

Everything else can be implemented with existing dependencies.

---

## CURSOR RULES ADDITION (.cursor/rules/features.mdc)

```markdown
---
description: ProbeScan feature additions
alwaysApply: true
---

# New Feature Rules

## Store pattern for new entity types
Every new entity type (Program, Wordlist, WorkflowRun, etc.) follows this pattern:
1. Add struct to `src-tauri/src/db/models.rs` with `#[derive(Debug, Clone, Serialize, Deserialize)]`
2. Add methods to `src-tauri/src/db/store.rs` (read/write JSON files)
3. Add Tauri commands to a new file `src-tauri/src/commands/<feature>.rs`
4. Register commands in `src-tauri/src/lib.rs` invoke_handler
5. Add API wrappers to `src/lib/api.ts`
6. Add TypeScript types to `src/types/index.ts`
7. Build React tab component in `src/components/tabs/Tab<Name>.tsx`
8. Add tab to App.tsx TABS array and render in content area

## Color rules
- NEVER use #00d4ff (old cyan accent) anywhere
- Primary accent is ALWAYS #e8001a (blood red)
- var(--accent) = #e8001a
- var(--accent-dim) = rgba(232,0,26,0.10)
- Severity badge colors are FIXED and must not change:
  CRITICAL=#ff0033, HIGH=#ff5722, MEDIUM=#ffab00, LOW=#00e676, INFO=#e8001a

## Never use
- sqlx or any SQL database
- localStorage or sessionStorage  
- External UI component libraries
- CSS frameworks (no Tailwind, no Bootstrap)
- React Router (single page app, tabs only)
```
