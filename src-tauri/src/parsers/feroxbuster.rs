// src-tauri/src/parsers/feroxbuster.rs
//
// feroxbuster invoked with: feroxbuster -u https://target.com --json -o /tmp/ferox.json
// Output is JSONL, one result per line:
// {"type":"response","url":"https://target.com/admin","status":200,"content_length":4821,...}

use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct FeroxEntry {
    #[serde(rename = "type")]
    entry_type: String,
    url: String,
    status: u16,
    #[serde(default)]
    content_length: u64,
    #[serde(default)]
    words: u64,
    #[serde(default)]
    lines: u64,
    #[serde(default)]
    method: String,
}

pub struct FeroxbusterParser;

impl ToolParser for FeroxbusterParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output
            .lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|line| serde_json::from_str::<FeroxEntry>(line).ok())
            .filter(|e| e.entry_type == "response")
            .filter_map(|e| classify_path(&e))
            .collect()
    }
}

fn classify_path(e: &FeroxEntry) -> Option<RawFinding> {
    let url_lower = e.url.to_lowercase();

    // Detect interesting paths
    let (severity, title, description, remediation) = if is_sensitive_path(&url_lower) {
        (
            "HIGH",
            format!("Sensitive Path Exposed: {}", e.url),
            format!(
                "A sensitive endpoint was found accessible at {} (HTTP {}). Content-Length: {} bytes.",
                e.url, e.status, e.content_length
            ),
            "Restrict access to sensitive paths via authentication, IP allowlisting, or removal from public web root.".to_string(),
        )
    } else if e.status == 200 && is_backup_file(&url_lower) {
        (
            "CRITICAL",
            format!("Backup/Config File Exposed: {}", e.url),
            format!("A backup or configuration file is directly accessible at {}", e.url),
            "Remove backup and config files from the web root. Add to .gitignore and redeploy.".to_string(),
        )
    } else if e.status == 200 {
        (
            "INFO",
            format!("Endpoint Discovered: {}", e.url),
            format!("HTTP {} endpoint at {} ({} bytes)", e.status, e.url, e.content_length),
            String::new(),
        )
    } else if e.status == 403 {
        (
            "LOW",
            format!("Forbidden Resource: {}", e.url),
            format!("Server returned 403 Forbidden for {}. Resource exists but access is restricted.", e.url),
            "Verify that directory listing and server-side includes are disabled.".to_string(),
        )
    } else {
        return None; // Skip non-interesting status codes
    };

    Some(RawFinding {
        source_tool: "feroxbuster".to_string(),
        severity: severity.to_string(),
        title,
        description,
        affected_url: e.url.clone(),
        affected_port: None,
        cve_references: vec![],
        cvss_score: None,
        evidence: format!(
            "GET {} → HTTP {}\nContent-Length: {}\nWords: {} Lines: {}",
            e.url, e.status, e.content_length, e.words, e.lines
        ),
        remediation,
        http_request: Some(format!("GET {} HTTP/1.1", e.url)),
        http_response: Some(format!("HTTP/1.1 {} ...", e.status)),
    })
}

fn is_sensitive_path(url: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
        "/.env", "/config", "/dashboard", "/console", "/manage",
        "/api/internal", "/graphql", "/.git", "/actuator", "/metrics",
        "/swagger", "/api-docs", "/debug", "/_debug", "/jenkins",
        "/kibana", "/solr", "/jmx-console",
    ];
    SENSITIVE.iter().any(|s| url.contains(s))
}

fn is_backup_file(url: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        ".bak", ".backup", ".old", ".orig", ".copy", ".swp",
        ".sql", ".dump", ".tar.gz", ".zip", ".7z", ".config.bak",
        "web.config.bak", ".env.bak", "database.yml",
    ];
    EXTENSIONS.iter().any(|ext| url.ends_with(ext))
}
