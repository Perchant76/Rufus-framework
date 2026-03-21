// src-tauri/src/commands/workflows.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::models::{WorkflowRun, WorkflowStage};

fn company_stages() -> Vec<WorkflowStage> {
    vec![
        WorkflowStage { name: "ASN Discovery".into(), description: "Discover Autonomous System Numbers owned by the target company.".into(), why: "ASNs tell you which IP ranges the company owns. Without this, you might miss entire server farms. Every IP in those ranges is a potential attack vector.".into(), tools: vec!["amass".into(), "metabigor".into()], status: "ready".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Root Domain Discovery".into(), description: "Find all root domains registered to the company using CT logs, WHOIS, and Google dorking.".into(), why: "Companies often have dozens of domains beyond their main site. Each one is an independent attack surface. Missing even one can mean missing critical vulnerabilities.".into(), tools: vec!["subfinder".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Subdomain Enumeration".into(), description: "Enumerate all subdomains across every discovered root domain.".into(), why: "Subdomains often expose staging environments, admin panels, and forgotten services with weaker security than the main domain.".into(), tools: vec!["subfinder".into(), "katana".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Live Host Detection".into(), description: "Filter enumerated subdomains to only those with live HTTP/HTTPS services.".into(), why: "Many subdomains resolve DNS but serve nothing. Running vuln scans against dead hosts wastes time. Filter first, scan second.".into(), tools: vec!["nmap".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Tech Fingerprinting".into(), description: "Identify technology stacks, CMS, frameworks, and server software on live hosts.".into(), why: "Knowing what software runs on a target lets you look up known CVEs and focus your attack on the weakest components.".into(), tools: vec!["whatweb".into(), "nuclei".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Vulnerability Scanning".into(), description: "Run active vulnerability scans against all live in-scope hosts.".into(), why: "This is where you find the bugs that pay. Templates cover OWASP Top 10, known CVEs, misconfigurations, and exposure of sensitive data.".into(), tools: vec!["nuclei".into(), "wapiti3".into()], status: "locked".into(), findings_count: 0, completed_at: None },
    ]
}

fn wildcard_stages() -> Vec<WorkflowStage> {
    vec![
        WorkflowStage { name: "Subdomain Enumeration".into(), description: "Enumerate all subdomains under the wildcard scope using multiple sources.".into(), why: "The more subdomains you find, the more attack surface you have. Different tools find different subdomains — use all of them.".into(), tools: vec!["subfinder".into()], status: "ready".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Web Crawling".into(), description: "Spider all live subdomains to build a complete sitemap of endpoints.".into(), why: "Endpoints are injection points. A 404 page might still process user input. A hidden admin route might have no auth. Crawl everything.".into(), tools: vec!["katana".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Directory Brute-force".into(), description: "Brute-force common paths and filenames to find hidden content.".into(), why: "Developers often leave /admin, /api/debug, config.bak, .env files accessible. These rarely appear in crawls because they're not linked.".into(), tools: vec!["feroxbuster".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "TLS Analysis".into(), description: "Check SSL/TLS configuration for weak ciphers, expired certs, and known vulnerabilities.".into(), why: "TLS issues are low-hanging fruit. BEAST, POODLE, and expired certificates are often missed and earn consistent bounties.".into(), tools: vec!["testssl.sh".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Vulnerability Scanning".into(), description: "Run full nuclei and OWASP active scans against all discovered endpoints.".into(), why: "This is the payoff. All previous stages feed context into this one — you're not scanning blind, you're scanning with full knowledge of the attack surface.".into(), tools: vec!["nuclei".into(), "wapiti3".into()], status: "locked".into(), findings_count: 0, completed_at: None },
    ]
}

fn single_target_stages() -> Vec<WorkflowStage> {
    vec![
        WorkflowStage { name: "Web Crawling".into(), description: "Build a complete sitemap of the target URL and all linked pages.".into(), why: "Before you test anything, understand what's there. Crawling reveals the full attack surface: forms, APIs, file uploads, redirects.".into(), tools: vec!["katana".into()], status: "ready".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Directory Brute-force".into(), description: "Discover hidden paths, admin panels, and sensitive files.".into(), why: "The most critical vulnerabilities are often on paths that aren't linked anywhere. /admin, /graphql, /.env, /api/v2.".into(), tools: vec!["feroxbuster".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "Tech Fingerprinting".into(), description: "Identify the exact software stack and versions running on the target.".into(), why: "Version disclosure tells you exactly which CVEs to check. A WordPress 5.8 install has a known list of unpatched RCEs.".into(), tools: vec!["whatweb".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "OWASP Active Scan".into(), description: "Test all discovered endpoints for OWASP Top 10 vulnerabilities.".into(), why: "SQLi, XSS, SSRF, command injection — all found by systematically testing every input. This is where your crawl data pays off.".into(), tools: vec!["wapiti3".into(), "nuclei".into()], status: "locked".into(), findings_count: 0, completed_at: None },
        WorkflowStage { name: "TLS Analysis".into(), description: "Audit the SSL/TLS configuration of the target.".into(), why: "Even if the app logic is solid, weak TLS can expose all traffic. Certificate issues and old cipher suites are reliably reportable.".into(), tools: vec!["testssl.sh".into()], status: "locked".into(), findings_count: 0, completed_at: None },
    ]
}

#[tauri::command]
pub async fn create_workflow(state: State<'_, Mutex<AppState>>, workflow_type: String, target: String) -> Result<WorkflowRun, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let stages = match workflow_type.as_str() {
        "company"  => company_stages(),
        "wildcard" => wildcard_stages(),
        _          => single_target_stages(),
    };
    let w = WorkflowRun { id: String::new(), workflow_type, target, current_stage: 0, stages, created_at: String::new() };
    store.create_workflow(w).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_workflows(state: State<'_, Mutex<AppState>>) -> Result<Vec<WorkflowRun>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_workflows().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_workflow(state: State<'_, Mutex<AppState>>, workflow: WorkflowRun) -> Result<WorkflowRun, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.update_workflow(workflow).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_workflow(state: State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_workflow(&id).map_err(|e| e.to_string())
}
