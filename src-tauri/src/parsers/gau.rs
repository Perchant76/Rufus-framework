// src-tauri/src/parsers/gau.rs
// gau --json target.com
// Each line: { "url":"https://...", "statuscode":200, "mime":"text/html" }
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct GauEntry {
    url: String,
}

pub struct GauParser;

impl ToolParser for GauParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        let mut findings = vec![];
        for line in output.lines().filter(|l| !l.is_empty()) {
            // gau can output plain URLs or JSON
            let url = if line.starts_with('{') {
                serde_json::from_str::<GauEntry>(line).ok().map(|e| e.url)
            } else if line.starts_with("http") {
                Some(line.trim().to_string())
            } else {
                None
            };

            if let Some(url) = url {
                if is_interesting_url(&url) {
                    let (severity, reason) = classify_url(&url);
                    findings.push(RawFinding {
                        source_tool: "gau".to_string(),
                        severity: severity.to_string(),
                        title: format!("Historical URL: {}", reason),
                        description: format!("URL found in web archives: {}", url),
                        affected_url: url.clone(),
                        affected_port: None,
                        cve_references: vec![],
                        cvss_score: None,
                        evidence: format!("Source: Wayback Machine / Common Crawl\nURL: {}", url),
                        remediation: "Verify this endpoint still exists and is not exposing sensitive data.".to_string(),
                        http_request: None,
                        http_response: None,
                    });
                }
            }
        }
        findings
    }
}

pub fn parse_urls(output: &str) -> Vec<String> {
    output.lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            if l.starts_with('{') {
                serde_json::from_str::<GauEntry>(l).ok().map(|e| e.url)
            } else if l.starts_with("http") {
                Some(l.trim().to_string())
            } else {
                None
            }
        })
        .collect()
}

fn is_interesting_url(url: &str) -> bool {
    let low = url.to_lowercase();
    INTERESTING_PATTERNS.iter().any(|p| low.contains(p))
}

fn classify_url(url: &str) -> (&'static str, &'static str) {
    let low = url.to_lowercase();
    if low.contains(".env") || low.contains("config.") || low.contains(".xml") { return ("HIGH", "Config/env file in archive"); }
    if low.contains("admin") || low.contains("panel") || low.contains("dashboard") { return ("MEDIUM", "Admin panel in archive"); }
    if low.contains("backup") || low.contains(".bak") || low.contains(".sql") { return ("HIGH", "Backup file in archive"); }
    if low.contains("api/") || low.contains("/v1/") || low.contains("/v2/") { return ("INFO", "API endpoint in archive"); }
    if low.contains("token=") || low.contains("key=") || low.contains("secret=") { return ("HIGH", "Sensitive param in archived URL"); }
    ("INFO", "Interesting archived URL")
}

const INTERESTING_PATTERNS: &[&str] = &[
    ".env", ".bak", ".sql", ".backup", "admin", "panel", "dashboard",
    "api/", "/v1/", "/v2/", "token=", "key=", "secret=", "password=",
    "config", "setup", "install", "backup", "export", "debug",
    ".git", "swagger", "graphql", "actuator", "jenkins",
];
