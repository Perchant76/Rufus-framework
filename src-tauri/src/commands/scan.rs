// src-tauri/src/commands/scan.rs
use std::sync::Mutex;
use tauri::{AppHandle, State};
use crate::AppState;
use crate::db::models::*;
use crate::scanner::{ScopeEngine, SubprocessRunner};
use crate::parsers::{
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
    let store = { state.lock().unwrap().store.clone_ref() };
    store.create_scan(&config).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scans(state: State<'_, Mutex<AppState>>) -> Result<Vec<Scan>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_scans().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scan(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<Option<Scan>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.get_scan(&scan_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_scan(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_scan(&scan_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn stop_scan(state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    let (store, scan_id) = {
        let mut s = state.lock().unwrap();
        s.scan_running = false;
        let store = s.store.clone_ref();
        let id = s.active_scan_id.clone();
        (store, id)
    };
    if let Some(id) = scan_id {
        store.update_scan_status(&id, "stopped").map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn start_scan(
    app_handle: AppHandle,
    state: State<'_, Mutex<AppState>>,
    config: ScanConfig,
) -> Result<String, String> {
    let store = {
        let mut s = state.lock().unwrap();
        let store = s.store.clone_ref();
        let scan = store.create_scan(&config).map_err(|e| e.to_string())?;
        s.active_scan_id = Some(scan.id.clone());
        s.scan_running = true;
        store.update_scan_status(&scan.id, "running").map_err(|e| e.to_string())?;
        (store, scan.id)
    };
    let (store, scan_id) = store;

    let runner = SubprocessRunner::new(app_handle.clone(), scan_id.clone());
    let scope = ScopeEngine::new(&config.scope);
    let target = config.target.clone();
    let is_domain = config.target_type == "DOMAIN";
    let delay_min = config.delay_min_ms;
    let delay_max = config.delay_max_ms;

    macro_rules! stealth_delay {
        () => {
            if config.stealth_mode && delay_max > 0 {
                let ms = delay_min + rand_u64(delay_max - delay_min);
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            }
        };
    }

    macro_rules! check_running {
        () => {{
            let running = state.lock().unwrap().scan_running;
            if !running {
                runner.emit_progress("system", 100.0, "Scan stopped by user.", "warn");
                store.update_scan_status(&scan_id, "stopped").ok();
                return Ok(scan_id);
            }
        }};
    }

    macro_rules! save_finding {
        ($raw:expr) => {{
            let in_scope = scope.is_in_scope(&$raw.affected_url);
            if let Ok(f) = store.add_finding(&scan_id, &$raw, in_scope) {
                runner.emit_finding(&f);
            }
        }};
    }

    // ── PHASE 1: Discovery ────────────────────────────────────────────────────

    if is_domain && config.tools.contains(&"subfinder".to_string()) {
        check_running!();
        runner.emit_progress("subfinder", 0.0, "[subfinder] Starting subdomain enumeration...", "info");
        let mut args = vec!["-d", &target, "-oJ", "-all", "-recursive", "-silent"];
        if config.stealth_mode { args.push("-passive"); }
        let output = runner.run("subfinder", &args, None).await.unwrap_or_default();

        for (host, ip) in crate::parsers::subfinder::parse_assets(&output) {
            let in_scope = scope.is_in_scope(&host);
            if let Ok(a) = store.add_asset(&scan_id, "subdomain", &host,
                ip.as_deref(), None, None, vec![], Some(&target), in_scope) {
                runner.emit_asset(&a);
            }
            if in_scope {
                let raw = RawFinding {
                    source_tool: "subfinder".to_string(),
                    severity: "INFO".to_string(),
                    title: format!("Subdomain Discovered: {}", host),
                    description: format!("Found via CT logs / OSINT"),
                    affected_url: format!("https://{}", host),
                    affected_port: None, cve_references: vec![], cvss_score: None,
                    evidence: format!("Host: {}\nIP: {}", host, ip.unwrap_or_default()),
                    remediation: String::new(), http_request: None, http_response: None,
                };
                save_finding!(raw);
            }
        }
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"katana".to_string()) {
        check_running!();
        runner.emit_progress("katana", 0.0, "[katana] Crawling...", "info");
        let url = format!("https://{}", target);
        let concurrency = config.concurrency.to_string();
        let output = runner.run("katana",
            &["-u", &url, "-json", "-d", "5", "-jc", "-kf", "all", "-c", &concurrency, "-silent"],
            None).await.unwrap_or_default();

        for endpoint in crate::parsers::katana::parse_endpoints(&output) {
            let in_scope = scope.is_in_scope(&endpoint);
            store.add_asset(&scan_id, "endpoint", &endpoint, None, None, None, vec![], None, in_scope).ok();
        }
        for raw in KatanaParser.parse(&output) { save_finding!(raw); }
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"feroxbuster".to_string()) {
        check_running!();
        runner.emit_progress("feroxbuster", 0.0, "[feroxbuster] Dir brute-force...", "info");
        let url = format!("https://{}", target);
        let threads = config.concurrency.to_string();
        let wordlist = if cfg!(windows) {
            "C:\\wordlists\\directory-list-2.3-medium.txt"
        } else {
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        };
        let output = runner.run("feroxbuster",
            &["-u", &url, "--json", "-t", &threads, "-w", wordlist,
              "-x", "php,asp,aspx,jsp,html,txt,bak", "--no-state", "-q"],
            None).await.unwrap_or_default();
        for raw in FeroxbusterParser.parse(&output) { save_finding!(raw); }
        stealth_delay!();
    }

    // ── PHASE 2: Ports ────────────────────────────────────────────────────────

    if config.tools.contains(&"nmap".to_string()) {
        check_running!();
        runner.emit_progress("nmap", 0.0, "[nmap] Port scan...", "info");
        let timing = if config.stealth_mode { "-T2" } else { "-T4" };
        let output = runner.run("nmap",
            &["-sV", "-oX", "-", timing, "--open", &target],
            None).await.unwrap_or_default();
        for mut raw in NmapParser.parse(&output) {
            raw.affected_url = format!("{}:{}", target, raw.affected_port.unwrap_or(0));
            save_finding!(raw);
        }
        stealth_delay!();
    }

    // ── PHASE 3: Vuln scanning ────────────────────────────────────────────────

    if config.tools.contains(&"nuclei".to_string()) {
        check_running!();
        runner.emit_progress("nuclei", 0.0, "[nuclei] Vulnerability templates...", "info");
        let url = if is_domain { format!("https://{}", target) } else { format!("http://{}", target) };
        let concurrency = config.concurrency.to_string();
        let mut args = vec!["-u", &url, "-json", "-silent", "-c", &concurrency];
        if config.stealth_mode { args.extend_from_slice(&["-rate-limit", "10"]); }
        let output = runner.run("nuclei", &args, None).await.unwrap_or_default();
        for raw in NucleiParser.parse(&output) { save_finding!(raw); }
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"wapiti3".to_string()) {
        check_running!();
        runner.emit_progress("wapiti3", 0.0, "[wapiti3] OWASP scan...", "info");
        let url = format!("https://{}", target);
        let tmp = std::env::temp_dir().join(format!("wapiti_{}.json", scan_id));
        let tmp_str = tmp.to_string_lossy().to_string();
        let output = runner.run("wapiti3",
            &["-u", &url, "-f", "json", "-o", &tmp_str, "--flush-session", "-q"],
            None).await.unwrap_or_default();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or(output);
        for raw in WapitiParser.parse(&content) { save_finding!(raw); }
        tokio::fs::remove_file(&tmp).await.ok();
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"testssl.sh".to_string()) {
        check_running!();
        runner.emit_progress("testssl.sh", 0.0, "[testssl.sh] TLS analysis...", "info");
        let tls_target = format!("{}:443", target);
        let tmp = std::env::temp_dir().join(format!("testssl_{}.json", scan_id));
        let tmp_str = tmp.to_string_lossy().to_string();
        let output = runner.run("testssl.sh",
            &["--jsonfile", &tmp_str, "--quiet", "--color", "0", &tls_target],
            None).await.unwrap_or_default();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or(output);
        for mut raw in TestsslParser.parse(&content) {
            raw.affected_url = format!("https://{}", target);
            save_finding!(raw);
        }
        tokio::fs::remove_file(&tmp).await.ok();
        stealth_delay!();
    }

    if config.tools.contains(&"whatweb".to_string()) {
        check_running!();
        runner.emit_progress("whatweb", 0.0, "[whatweb] Tech fingerprint...", "info");
        let url = format!("https://{}", target);
        let tmp = std::env::temp_dir().join(format!("whatweb_{}.json", scan_id));
        let tmp_str = tmp.to_string_lossy().to_string();
        runner.run("whatweb", &[&url, &format!("--log-json={}", tmp_str), "-q"], None).await.ok();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or_default();
        for raw in WhatwebParser.parse(&content) { save_finding!(raw); }
        tokio::fs::remove_file(&tmp).await.ok();
    }

    // ── Complete ──────────────────────────────────────────────────────────────
    {
        let mut s = state.lock().unwrap();
        s.scan_running = false;
        s.active_scan_id = None;
    }
    store.update_scan_status(&scan_id, "complete").map_err(|e| e.to_string())?;
    runner.emit_progress("system", 100.0, "✓ Scan complete.", "ok");
    Ok(scan_id)
}

fn rand_u64(max: u64) -> u64 {
    if max == 0 { return 0; }
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 % max).unwrap_or(0)
}
