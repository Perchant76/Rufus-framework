// src-tauri/src/commands/scan.rs
use std::sync::Mutex;
use tauri::{AppHandle, State};
use crate::AppState;
use crate::db::models::*;
use crate::scanner::{ScopeEngine, SubprocessRunner};
use crate::parsers::{
    subfinder, amass,
    feroxbuster::FeroxbusterParser,
    katana::KatanaParser,
    nmap::NmapParser,
    naabu::NaabuParser,
    nuclei::NucleiParser,
    testssl::TestsslParser,
    whatweb::WhatwebParser,
    wapiti::WapitiParser,
    httpx::HttpxParser,
    dnsx::DnsxParser,
    gau::GauParser,
    sqlmap::SqlmapParser,
    nikto::NiktoParser,
    ffuf::FfufParser,
    ToolParser,
};

#[tauri::command]
pub async fn create_scan(state: State<'_, Mutex<AppState>>, config: ScanConfig) -> Result<Scan, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.create_scan(&config).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scans(state: State<'_, Mutex<AppState>>) -> Result<Vec<Scan>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_scans().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scan(state: State<'_, Mutex<AppState>>, scan_id: String) -> Result<Option<Scan>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.get_scan(&scan_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_scan(state: State<'_, Mutex<AppState>>, scan_id: String) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_scan(&scan_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn stop_scan(state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    let (store, scan_id) = {
        let mut s = state.lock().unwrap();
        s.scan_running = false;
        (s.store.clone_ref(), s.active_scan_id.clone())
    };
    if let Some(id) = scan_id {
        store.update_scan_status(&id, "stopped").map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn start_scan(app_handle: AppHandle, state: State<'_, Mutex<AppState>>, config: ScanConfig) -> Result<String, String> {
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

    macro_rules! stealth_delay { () => {
        if config.stealth_mode && delay_max > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_min + rand_u64(delay_max - delay_min))).await;
        }
    };}
    macro_rules! check_running { () => {{
        let running = state.lock().unwrap().scan_running;
        if !running { runner.emit_progress("system", 100.0, "Scan stopped by user.", "warn"); store.update_scan_status(&scan_id, "stopped").ok(); return Ok(scan_id); }
    }};}
    macro_rules! save_finding { ($raw:expr) => {{
        let in_scope = scope.is_in_scope(&$raw.affected_url);
        if let Ok(f) = store.add_finding(&scan_id, &$raw, in_scope) { runner.emit_finding(&f); }
    }};}

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 1 — SUBDOMAIN ENUMERATION
    // ═══════════════════════════════════════════════════════════════════

    if is_domain && config.tools.contains(&"subfinder".to_string()) {
        check_running!();
        runner.emit_progress("subfinder", 0.0, "[subfinder] Enumerating subdomains (passive + CT logs)...", "info");
        let mut args = vec!["-d", &target, "-oJ", "-all", "-recursive", "-silent"];
        if config.stealth_mode { args.push("-passive"); }
        let output = runner.run("subfinder", &args, None).await.unwrap_or_default();
        for (host, ip) in subfinder::parse_assets(&output) {
            let in_scope = scope.is_in_scope(&host);
            if let Ok(a) = store.add_asset(&scan_id, "subdomain", &host, ip.as_deref(), None, None, vec![], Some(&target), in_scope) { runner.emit_asset(&a); }
            if in_scope { let raw = RawFinding { source_tool: "subfinder".to_string(), severity: "INFO".to_string(), title: format!("Subdomain: {}", host), description: format!("Discovered via CT logs / OSINT"), affected_url: format!("https://{}", host), affected_port: None, cve_references: vec![], cvss_score: None, evidence: format!("Host: {}\nIP: {}", host, ip.unwrap_or_default()), remediation: String::new(), http_request: None, http_response: None }; save_finding!(raw); }
        }
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"amass".to_string()) {
        check_running!();
        runner.emit_progress("amass", 0.0, "[amass] Deep subdomain enumeration...", "info");
        let tmp = std::env::temp_dir().join(format!("amass_{}.json", scan_id));
        let tmp_s = tmp.to_string_lossy().to_string();
        runner.run("amass", &["enum", "-passive", "-d", &target, "-json", &tmp_s, "-silent"], None).await.ok();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or_default();
        for (host, ip) in amass::parse_subdomains(&content) {
            let in_scope = scope.is_in_scope(&host);
            if let Ok(a) = store.add_asset(&scan_id, "subdomain", &host, ip.as_deref(), None, None, vec![], Some(&target), in_scope) { runner.emit_asset(&a); }
        }
        for raw in crate::parsers::amass::AmassParser.parse(&content) { save_finding!(raw); }
        tokio::fs::remove_file(&tmp).await.ok();
        stealth_delay!();
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 2 — DNS RESOLUTION & LIVE HOST DETECTION
    // ═══════════════════════════════════════════════════════════════════

    if is_domain && config.tools.contains(&"dnsx".to_string()) {
        check_running!();
        runner.emit_progress("dnsx", 0.0, "[dnsx] Resolving subdomains and extracting DNS records...", "info");
        let output = runner.run("dnsx", &["-d", &target, "-json", "-silent", "-a", "-cname", "-resp", "-asn"], None).await.unwrap_or_default();
        for raw in DnsxParser.parse(&output) { save_finding!(raw); }
        for entry in crate::parsers::dnsx::parse_resolved_hosts(&output) {
            let in_scope = scope.is_in_scope(&entry.host);
            let ip = entry.a.first().map(|s| s.as_str());
            store.add_asset(&scan_id, "subdomain", &entry.host, ip, None, None, vec![], None, in_scope).ok();
        }
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"httpx".to_string()) {
        check_running!();
        runner.emit_progress("httpx", 0.0, "[httpx] Probing live hosts and fingerprinting...", "info");
        let output = runner.run("httpx",
            &["-u", &format!("https://{}", target), "-json", "-silent", "-title", "-tech-detect", "-status-code", "-content-length", "-tls-grab"],
            None).await.unwrap_or_default();
        for raw in HttpxParser.parse(&output) { save_finding!(raw); }
        for entry in crate::parsers::httpx::parse_live_hosts(&output) {
            if entry.url.is_empty() { continue; }
            let in_scope = scope.is_in_scope(&entry.url);
            store.add_asset(&scan_id, "endpoint", &entry.url, entry.ip.as_deref(), Some(entry.status_code as i64), Some(&entry.title), entry.tech.clone(), None, in_scope).ok();
        }
        stealth_delay!();
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 3 — URL & ENDPOINT DISCOVERY
    // ═══════════════════════════════════════════════════════════════════

    if is_domain && config.tools.contains(&"gau".to_string()) {
        check_running!();
        runner.emit_progress("gau", 0.0, "[gau] Fetching historical URLs from Wayback Machine / CommonCrawl...", "info");
        let output = runner.run("gau", &["--subs", "--json", &target], None).await.unwrap_or_default();
        for raw in GauParser.parse(&output) { save_finding!(raw); }
        for url in crate::parsers::gau::parse_urls(&output).iter().take(500) {
            if scope.is_in_scope(url) {
                store.add_asset(&scan_id, "endpoint", url, None, None, None, vec![], None, true).ok();
            }
        }
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"katana".to_string()) {
        check_running!();
        runner.emit_progress("katana", 0.0, "[katana] Active web crawl...", "info");
        let url = format!("https://{}", target);
        let concurrency = config.concurrency.to_string();
        let output = runner.run("katana", &["-u", &url, "-json", "-d", "5", "-jc", "-kf", "all", "-c", &concurrency, "-silent"], None).await.unwrap_or_default();
        for endpoint in crate::parsers::katana::parse_endpoints(&output) {
            store.add_asset(&scan_id, "endpoint", &endpoint, None, None, None, vec![], None, scope.is_in_scope(&endpoint)).ok();
        }
        for raw in KatanaParser.parse(&output) { save_finding!(raw); }
        stealth_delay!();
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 4 — DIRECTORY / CONTENT DISCOVERY
    // ═══════════════════════════════════════════════════════════════════

    if is_domain && config.tools.contains(&"feroxbuster".to_string()) {
        check_running!();
        runner.emit_progress("feroxbuster", 0.0, "[feroxbuster] Directory brute-force...", "info");
        let url = format!("https://{}", target);
        let threads = config.concurrency.to_string();
        let wordlist = if cfg!(windows) { "C:\\wordlists\\directory-list-2.3-medium.txt" } else { "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" };
        let output = runner.run("feroxbuster", &["-u", &url, "--json", "-t", &threads, "-w", wordlist, "-x", "php,asp,aspx,html,txt,bak", "--no-state", "-q"], None).await.unwrap_or_default();
        for raw in FeroxbusterParser.parse(&output) { save_finding!(raw); }
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"ffuf".to_string()) {
        check_running!();
        runner.emit_progress("ffuf", 0.0, "[ffuf] Fast web fuzzing...", "info");
        let url = format!("https://{}/FUZZ", target);
        let threads = config.concurrency.to_string();
        let tmp = std::env::temp_dir().join(format!("ffuf_{}.json", scan_id));
        let tmp_s = tmp.to_string_lossy().to_string();
        let wordlist = if cfg!(windows) { "C:\\wordlists\\directory-list-2.3-medium.txt" } else { "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" };
        runner.run("ffuf", &["-u", &url, "-w", wordlist, "-o", &tmp_s, "-of", "json", "-mc", "200,301,302,403", "-t", &threads, "-s"], None).await.ok();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or_default();
        for raw in FfufParser.parse(&content) { save_finding!(raw); }
        tokio::fs::remove_file(&tmp).await.ok();
        stealth_delay!();
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 5 — PORT SCANNING
    // ═══════════════════════════════════════════════════════════════════

    if config.tools.contains(&"naabu".to_string()) {
        check_running!();
        runner.emit_progress("naabu", 0.0, "[naabu] Fast port scan (top 1000)...", "info");
        let output = runner.run("naabu", &["-host", &target, "-json", "-silent", "-top-ports", "1000", "-exclude-cdn"], None).await.unwrap_or_default();
        for raw in NaabuParser.parse(&output) { save_finding!(raw); }
        stealth_delay!();
    }

    if config.tools.contains(&"nmap".to_string()) {
        check_running!();
        runner.emit_progress("nmap", 0.0, "[nmap] Deep service fingerprinting...", "info");
        let timing = if config.stealth_mode { "-T2" } else { "-T4" };
        let output = runner.run("nmap", &["-sV", "-oX", "-", timing, "--open", &target], None).await.unwrap_or_default();
        for mut raw in NmapParser.parse(&output) { raw.affected_url = format!("{}:{}", target, raw.affected_port.unwrap_or(0)); save_finding!(raw); }
        stealth_delay!();
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 6 — VULNERABILITY SCANNING
    // ═══════════════════════════════════════════════════════════════════

    if config.tools.contains(&"nuclei".to_string()) {
        check_running!();
        runner.emit_progress("nuclei", 0.0, "[nuclei] Template-based vulnerability scan...", "info");
        let url = if is_domain { format!("https://{}", target) } else { format!("http://{}", target) };
        let concurrency = config.concurrency.to_string();
        let mut args = vec!["-u", &url, "-json", "-silent", "-c", &concurrency];
        if config.stealth_mode { args.extend_from_slice(&["-rate-limit", "10"]); }
        let output = runner.run("nuclei", &args, None).await.unwrap_or_default();
        for raw in NucleiParser.parse(&output) { save_finding!(raw); }
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"nikto".to_string()) {
        check_running!();
        runner.emit_progress("nikto", 0.0, "[nikto] Web server vulnerability scan...", "info");
        let tmp = std::env::temp_dir().join(format!("nikto_{}.json", scan_id));
        let tmp_s = tmp.to_string_lossy().to_string();
        let target_url = format!("https://{}", target);
        let output = runner.run("nikto", &["-h", &target_url, "-Format", "json", "-output", &tmp_s, "-nointeractive"], None).await.unwrap_or_default();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or(output);
        for raw in NiktoParser.parse(&content) { save_finding!(raw); }
        tokio::fs::remove_file(&tmp).await.ok();
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"sqlmap".to_string()) {
        check_running!();
        runner.emit_progress("sqlmap", 0.0, "[sqlmap] SQL injection testing on discovered parameters...", "info");
        let tmp_dir = std::env::temp_dir().join(format!("sqlmap_{}", scan_id));
        let tmp_s = tmp_dir.to_string_lossy().to_string();
        let url = format!("https://{}/", target);
        let output = runner.run("sqlmap",
            &["-u", &url, "--batch", "--level=1", "--risk=1", "--output-dir", &tmp_s, "--forms", "--crawl=2", "--quiet"],
            None).await.unwrap_or_default();
        for raw in SqlmapParser.parse(&output) { save_finding!(raw); }
        tokio::fs::remove_dir_all(&tmp_dir).await.ok();
        stealth_delay!();
    }

    if is_domain && config.tools.contains(&"wapiti3".to_string()) {
        check_running!();
        runner.emit_progress("wapiti3", 0.0, "[wapiti3] OWASP active scan...", "info");
        let url = format!("https://{}", target);
        let tmp = std::env::temp_dir().join(format!("wapiti_{}.json", scan_id));
        let tmp_s = tmp.to_string_lossy().to_string();
        let output = runner.run("wapiti3", &["-u", &url, "-f", "json", "-o", &tmp_s, "--flush-session", "-q"], None).await.unwrap_or_default();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or(output);
        for raw in WapitiParser.parse(&content) { save_finding!(raw); }
        tokio::fs::remove_file(&tmp).await.ok();
        stealth_delay!();
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 7 — TLS / TECH ANALYSIS
    // ═══════════════════════════════════════════════════════════════════

    if is_domain && config.tools.contains(&"testssl.sh".to_string()) {
        check_running!();
        runner.emit_progress("testssl.sh", 0.0, "[testssl.sh] TLS/SSL analysis...", "info");
        let tls_target = format!("{}:443", target);
        let tmp = std::env::temp_dir().join(format!("testssl_{}.json", scan_id));
        let tmp_s = tmp.to_string_lossy().to_string();
        let output = runner.run("testssl.sh", &["--jsonfile", &tmp_s, "--quiet", "--color", "0", &tls_target], None).await.unwrap_or_default();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or(output);
        for mut raw in TestsslParser.parse(&content) { raw.affected_url = format!("https://{}", target); save_finding!(raw); }
        tokio::fs::remove_file(&tmp).await.ok();
        stealth_delay!();
    }

    if config.tools.contains(&"whatweb".to_string()) {
        check_running!();
        runner.emit_progress("whatweb", 0.0, "[whatweb] Technology fingerprinting...", "info");
        let url = format!("https://{}", target);
        let tmp = std::env::temp_dir().join(format!("whatweb_{}.json", scan_id));
        let tmp_s = tmp.to_string_lossy().to_string();
        runner.run("whatweb", &[&url, &format!("--log-json={}", tmp_s), "-q"], None).await.ok();
        let content = tokio::fs::read_to_string(&tmp).await.unwrap_or_default();
        for raw in WhatwebParser.parse(&content) { save_finding!(raw); }
        tokio::fs::remove_file(&tmp).await.ok();
    }

    // ═══════════════════════════════════════════════════════════════════
    // COMPLETE
    // ═══════════════════════════════════════════════════════════════════
    { let mut s = state.lock().unwrap(); s.scan_running = false; s.active_scan_id = None; }
    store.update_scan_status(&scan_id, "complete").map_err(|e| e.to_string())?;
    runner.emit_progress("system", 100.0, "✓ Scan complete.", "ok");
    Ok(scan_id)
}

fn rand_u64(max: u64) -> u64 {
    if max == 0 { return 0; }
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos() as u64 % max).unwrap_or(0)
}
