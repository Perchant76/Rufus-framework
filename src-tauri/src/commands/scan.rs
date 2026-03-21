// src-tauri/src/commands/scan.rs
use std::sync::Mutex;
use tauri::{AppHandle, State};

use crate::AppState;
use crate::db::{self, models::*};
use crate::scanner::{ScopeEngine, SubprocessRunner};
use crate::parsers::{
    subfinder::SubfinderParser,
    feroxbuster::FeroxbusterParser,
    katana::KatanaParser,
    nmap::NmapParser,
    nuclei::NucleiParser,
    testssl::TestsslParser,
    whatweb::WhatwebParser,
    wapiti::WapitiParser,
    ToolParser,
};

#[tauri::command]
pub async fn create_scan(
    state: State<'_, Mutex<AppState>>,
    config: ScanConfig,
) -> Result<Scan, String> {
    let pool = { state.lock().unwrap().db.clone() };
    db::scans::create(&pool, &config).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scans(state: State<'_, Mutex<AppState>>) -> Result<Vec<Scan>, String> {
    let pool = { state.lock().unwrap().db.clone() };
    db::scans::list(&pool).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scan(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<Option<Scan>, String> {
    let pool = { state.lock().unwrap().db.clone() };
    db::scans::get(&pool, &scan_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_scan(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<(), String> {
    let pool = { state.lock().unwrap().db.clone() };
    db::scans::delete(&pool, &scan_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn stop_scan(state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    let mut s = state.lock().unwrap();
    s.scan_running = false;
    if let Some(ref id) = s.active_scan_id.clone() {
        let pool = s.db.clone();
        drop(s);
        db::scans::update_status(&pool, id, "stopped")
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Main scan orchestrator — runs all enabled tools sequentially,
/// normalizes output into the unified schema, and emits events.
#[tauri::command]
pub async fn start_scan(
    app_handle: AppHandle,
    state: State<'_, Mutex<AppState>>,
    config: ScanConfig,
) -> Result<String, String> {
    // Create scan record
    let pool = { state.lock().unwrap().db.clone() };
    let scan = db::scans::create(&pool, &config).await.map_err(|e| e.to_string())?;
    let scan_id = scan.id.clone();

    // Mark running
    {
        let mut s = state.lock().unwrap();
        s.active_scan_id = Some(scan_id.clone());
        s.scan_running = true;
    }
    db::scans::update_status(&pool, &scan_id, "running").await.map_err(|e| e.to_string())?;

    let runner = SubprocessRunner::new(app_handle.clone(), scan_id.clone());
    let scope = ScopeEngine::new(&config.scope);
    let target = config.target.clone();
    let is_domain = config.target_type == "DOMAIN";

    // ── Build auth args that get appended to tool invocations ─────────────
    let mut _cookie_args: Vec<String> = vec![];
    let mut _header_args: Vec<String> = vec![];

    if let Some(ref auth) = config.auth {
        match auth.mode.as_str() {
            "cookie" => {
                if let Some(ref c) = auth.cookie_string {
                    _cookie_args = vec!["-H".to_string(), format!("Cookie: {}", c)];
                }
            }
            "bearer" => {
                if let Some(ref t) = auth.bearer_token {
                    _header_args = vec!["-H".to_string(), format!("Authorization: Bearer {}", t)];
                }
            }
            _ => {}
        }
    }

    // ── Stealth delay helper ───────────────────────────────────────────────
    let delay_min = config.delay_min_ms;
    let delay_max = config.delay_max_ms;

    macro_rules! stealth_delay {
        () => {
            if config.stealth_mode && delay_max > 0 {
                let ms = delay_min + rand_range(delay_max - delay_min);
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            }
        };
    }

    // ── Check still running ────────────────────────────────────────────────
    macro_rules! check_running {
        () => {
            if !state.lock().unwrap().scan_running {
                runner.emit_progress("system", 100.0, "Scan stopped by user.", "warn");
                return Ok(scan_id);
            }
        };
    }

    // ═════════════════════════════════════════════════════════════════════
    // PHASE 1: DISCOVERY
    // ═════════════════════════════════════════════════════════════════════

    if is_domain && config.tools.contains(&"subfinder".to_string()) {
        check_running!();
        runner.emit_progress("subfinder", 0.0, "[subfinder] Starting subdomain enumeration...", "info");

        let mut args = vec!["-d", &target, "-oJ", "-all", "-recursive", "-silent"];
        if config.stealth_mode {
            args.extend_from_slice(&["-passive"]);
        }

        let output = runner.run("subfinder", &args, None).await.unwrap_or_default();

        // Parse and store as assets
        for (host, ip) in crate::parsers::subfinder::parse_assets(&output) {
            let in_scope = scope.is_in_scope(&host);
            let asset = db::assets::insert(
                &pool, &scan_id, "subdomain", &host,
                ip.as_deref(), None, None, None, None, Some(&target), in_scope,
            ).await.ok();
            if let Some(a) = asset { runner.emit_asset(&a); }

            if in_scope {
                // Store INFO finding
                let raw = RawFinding {
                    source_tool: "subfinder".to_string(),
                    severity: "INFO".to_string(),
                    title: format!("Subdomain: {}", host),
                    description: format!("Subdomain {} discovered via CT logs / passive OSINT", host),
                    affected_url: format!("https://{}", host),
                    affected_port: None,
                    cve_references: vec![],
                    cvss_score: None,
                    evidence: format!("Host: {}\nIP: {}", host, ip.unwrap_or_default()),
                    remediation: String::new(),
                    http_request: None,
                    http_response: None,
                };
                if let Ok(f) = db::findings::insert(&pool, &scan_id, &raw, true).await {
                    runner.emit_finding(&f);
                }
            }
        }

        stealth_delay!();
    }

    // ── Katana (web crawl) ─────────────────────────────────────────────────
    if is_domain && config.tools.contains(&"katana".to_string()) {
        check_running!();
        runner.emit_progress("katana", 0.0, "[katana] Starting web crawl...", "info");

        let url = format!("https://{}", target);
        let depth = "5";
        let concurrency = config.concurrency.to_string();
        let mut args = vec![
            "-u", &url, "-json", "-d", depth, "-jc", "-kf", "all",
            "-c", &concurrency, "-silent",
        ];
        if !config.stealth_mode {
            args.extend_from_slice(&["-xhr"]);
        }

        let output = runner.run("katana", &args, None).await.unwrap_or_default();

        for endpoint in crate::parsers::katana::parse_endpoints(&output) {
            let in_scope = scope.is_in_scope(&endpoint);
            let _ = db::assets::insert(
                &pool, &scan_id, "endpoint", &endpoint,
                None, None, None, None, None, None, in_scope,
            ).await;
        }

        // Parse for interesting findings
        let parser = KatanaParser;
        for raw in parser.parse(&output) {
            let in_scope = scope.is_in_scope(&raw.affected_url);
            if let Ok(f) = db::findings::insert(&pool, &scan_id, &raw, in_scope).await {
                runner.emit_finding(&f);
            }
        }

        stealth_delay!();
    }

    // ── Feroxbuster (dir brute-force) ──────────────────────────────────────
    if is_domain && config.tools.contains(&"feroxbuster".to_string()) {
        check_running!();
        runner.emit_progress("feroxbuster", 0.0, "[feroxbuster] Starting directory brute-force...", "info");

        let url = format!("https://{}", target);
        let threads = config.concurrency.to_string();
        let wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt";
        let output = runner.run(
            "feroxbuster",
            &["-u", &url, "--json", "-t", &threads, "-w", wordlist,
              "-x", "php,asp,aspx,jsp,html,txt,bak,config",
              "--no-state", "-q", "--silent"],
            None,
        ).await.unwrap_or_default();

        let parser = FeroxbusterParser;
        for raw in parser.parse(&output) {
            let in_scope = scope.is_in_scope(&raw.affected_url);
            if let Ok(f) = db::findings::insert(&pool, &scan_id, &raw, in_scope).await {
                runner.emit_finding(&f);
            }
        }

        stealth_delay!();
    }

    // ═════════════════════════════════════════════════════════════════════
    // PHASE 2: PORT / SERVICE SCAN (IP targets or always for server focus)
    // ═════════════════════════════════════════════════════════════════════

    if config.tools.contains(&"nmap".to_string()) {
        check_running!();
        runner.emit_progress("nmap", 0.0, "[nmap] Starting port scan...", "info");

        let timing = if config.stealth_mode { "-T2" } else { "-T4" };
        let output = runner.run(
            "nmap",
            &["-sV", "-O", "-oX", "-", timing, "--open", &target],
            None,
        ).await.unwrap_or_default();

        let parser = NmapParser;
        for mut raw in parser.parse(&output) {
            raw.affected_url = format!("{}:{}", target, raw.affected_port.unwrap_or(0));
            let in_scope = scope.is_in_scope(&target);
            if let Ok(f) = db::findings::insert(&pool, &scan_id, &raw, in_scope).await {
                runner.emit_finding(&f);
            }
        }

        stealth_delay!();
    }

    // ═════════════════════════════════════════════════════════════════════
    // PHASE 3: VULNERABILITY SCANNING
    // ═════════════════════════════════════════════════════════════════════

    // ── Nuclei ─────────────────────────────────────────────────────────────
    if config.tools.contains(&"nuclei".to_string()) {
        check_running!();
        runner.emit_progress("nuclei", 0.0, "[nuclei] Running vulnerability templates...", "info");

        let url = if is_domain { format!("https://{}", target) } else { format!("http://{}", target) };
        let concurrency = config.concurrency.to_string();

        let mut args = vec![
            "-u", &url, "-json", "-silent",
            "-c", &concurrency,
            "-s", "critical,high,medium,low",
        ];
        if config.stealth_mode {
            args.extend_from_slice(&["-rate-limit", "10"]);
        }

        let output = runner.run("nuclei", &args, None).await.unwrap_or_default();

        let parser = NucleiParser;
        for raw in parser.parse(&output) {
            let in_scope = scope.is_in_scope(&raw.affected_url);
            if let Ok(f) = db::findings::insert(&pool, &scan_id, &raw, in_scope).await {
                runner.emit_finding(&f);
            }
        }

        stealth_delay!();
    }

    // ── Wapiti ─────────────────────────────────────────────────────────────
    if is_domain && config.tools.contains(&"wapiti3".to_string()) {
        check_running!();
        runner.emit_progress("wapiti3", 0.0, "[wapiti3] Starting OWASP active scan...", "info");

        let url = format!("https://{}", target);
        let output_file = format!("/tmp/wapiti_{}.json", scan_id);

        let output = runner.run(
            "wapiti3",
            &["-u", &url, "-f", "json", "-o", &output_file, "--flush-session", "-q"],
            None,
        ).await.unwrap_or_default();

        // Read file output if it exists
        let file_content = tokio::fs::read_to_string(&output_file).await.unwrap_or(output);
        let parser = WapitiParser;
        for raw in parser.parse(&file_content) {
            let in_scope = scope.is_in_scope(&raw.affected_url);
            if let Ok(f) = db::findings::insert(&pool, &scan_id, &raw, in_scope).await {
                runner.emit_finding(&f);
            }
        }

        // Clean up temp file
        let _ = tokio::fs::remove_file(&output_file).await;
        stealth_delay!();
    }

    // ── testssl.sh ─────────────────────────────────────────────────────────
    if is_domain && config.tools.contains(&"testssl.sh".to_string()) {
        check_running!();
        runner.emit_progress("testssl.sh", 0.0, "[testssl.sh] Analyzing TLS configuration...", "info");

        let tls_target = format!("{}:443", target);
        let output_file = format!("/tmp/testssl_{}.json", scan_id);

        let output = runner.run(
            "testssl.sh",
            &["--jsonfile", &output_file, "--quiet", "--color", "0", &tls_target],
            None,
        ).await.unwrap_or_default();

        let file_content = tokio::fs::read_to_string(&output_file).await.unwrap_or(output);
        let parser = TestsslParser;
        for mut raw in parser.parse(&file_content) {
            raw.affected_url = format!("https://{}", target);
            let in_scope = scope.is_in_scope(&target);
            if let Ok(f) = db::findings::insert(&pool, &scan_id, &raw, in_scope).await {
                runner.emit_finding(&f);
            }
        }

        let _ = tokio::fs::remove_file(&output_file).await;
        stealth_delay!();
    }

    // ── WhatWeb ────────────────────────────────────────────────────────────
    if config.tools.contains(&"whatweb".to_string()) {
        check_running!();
        runner.emit_progress("whatweb", 0.0, "[whatweb] Fingerprinting technology stack...", "info");

        let url = format!("https://{}", target);
        let output_file = format!("/tmp/whatweb_{}.json", scan_id);

        let _ = runner.run(
            "whatweb",
            &[&url, &format!("--log-json={}", output_file), "-q"],
            None,
        ).await;

        let file_content = tokio::fs::read_to_string(&output_file).await.unwrap_or_default();
        let parser = WhatwebParser;
        for raw in parser.parse(&file_content) {
            let in_scope = scope.is_in_scope(&raw.affected_url);
            if let Ok(f) = db::findings::insert(&pool, &scan_id, &raw, in_scope).await {
                runner.emit_finding(&f);
            }
        }

        let _ = tokio::fs::remove_file(&output_file).await;
    }

    // ═════════════════════════════════════════════════════════════════════
    // COMPLETE
    // ═════════════════════════════════════════════════════════════════════
    {
        let mut s = state.lock().unwrap();
        s.scan_running = false;
        s.active_scan_id = None;
    }

    db::scans::update_status(&pool, &scan_id, "complete")
        .await
        .map_err(|e| e.to_string())?;

    runner.emit_progress("system", 100.0, "✓ Scan complete.", "ok");

    Ok(scan_id)
}

/// Simple rand range without pulling in the rand crate
fn rand_range(max: u64) -> u64 {
    if max == 0 { return 0; }
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    nanos % max
}
