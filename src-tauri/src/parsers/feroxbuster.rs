// src-tauri/src/parsers/feroxbuster.rs
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct FeroxEntry {
    #[serde(rename = "type")] entry_type: String,
    url: String,
    status: u16,
    #[serde(default)] content_length: u64,
    #[serde(default)] words: u64,
    #[serde(default)] lines: u64,
}

pub struct FeroxbusterParser;

impl ToolParser for FeroxbusterParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str::<FeroxEntry>(l).ok())
            .filter(|e| e.entry_type == "response")
            .filter_map(classify_path)
            .collect()
    }
}

fn classify_path(e: FeroxEntry) -> Option<RawFinding> {
    let url_lower = e.url.to_lowercase();
    let (severity, title, description, remediation) = if is_backup_file(&url_lower) && e.status == 200 {
        ("CRITICAL",
         format!("Backup/Config File Exposed: {}", e.url),
         format!("Backup or configuration file accessible at {}", e.url),
         "Remove backup and config files from web root.".to_string())
    } else if is_sensitive_path(&url_lower) && e.status == 200 {
        ("HIGH",
         format!("Sensitive Path Exposed: {}", e.url),
         format!("Sensitive endpoint accessible at {} (HTTP {})", e.url, e.status),
         "Restrict access via authentication or IP allowlisting.".to_string())
    } else if e.status == 200 {
        ("INFO",
         format!("Endpoint: {}", e.url),
         format!("HTTP {} at {} ({} bytes)", e.status, e.url, e.content_length),
         String::new())
    } else if e.status == 403 {
        ("LOW",
         format!("Forbidden Resource: {}", e.url),
         format!("403 Forbidden at {} — resource exists but blocked.", e.url),
         "Verify directory listing is disabled.".to_string())
    } else {
        return None;
    };

    Some(RawFinding {
        source_tool: "feroxbuster".to_string(),
        severity: severity.to_string(),
        title, description,
        affected_url: e.url.clone(),
        affected_port: None,
        cve_references: vec![],
        cvss_score: None,
        evidence: format!("GET {} → HTTP {}\nSize: {} Words: {} Lines: {}",
            e.url, e.status, e.content_length, e.words, e.lines),
        remediation,
        http_request: Some(format!("GET {} HTTP/1.1", e.url)),
        http_response: Some(format!("HTTP/1.1 {}", e.status)),
    })
}

fn is_sensitive_path(url: &str) -> bool {
    ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config",
     "/dashboard", "/.git", "/actuator", "/swagger", "/jenkins",
     "/console", "/api/internal", "/graphql", "/debug"].iter()
        .any(|s| url.contains(s))
}

fn is_backup_file(url: &str) -> bool {
    [".bak", ".backup", ".old", ".sql", ".dump", ".zip", ".tar.gz",
     "web.config.bak", ".env.bak"].iter()
        .any(|ext| url.ends_with(ext))
}
