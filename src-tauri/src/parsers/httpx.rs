// src-tauri/src/parsers/httpx.rs
// httpx -l subdomains.txt -json -title -tech-detect -status-code -cdn -follow-redirects
// Each line: { "url":"...", "status-code":200, "title":"...", "tech":["..."], "cdn":true, ... }
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
pub struct HttpxEntry {
    #[serde(default)] pub url: String,
    #[serde(rename = "status-code", default)] pub status_code: u16,
    #[serde(default)] pub title: String,
    #[serde(default)] pub tech: Vec<String>,
    #[serde(default)] pub cdn: bool,
    #[serde(rename = "cdn-name", default)] pub cdn_name: String,
    #[serde(rename = "webserver", default)] pub webserver: String,
    #[serde(default)] pub ip: Option<String>,
    #[serde(rename = "final-url", default)] pub _final_url: Option<String>,
}

pub struct HttpxParser;

impl ToolParser for HttpxParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str::<HttpxEntry>(l).ok())
            .filter_map(|e| classify_httpx(&e))
            .collect()
    }
}

fn classify_httpx(e: &HttpxEntry) -> Option<RawFinding> {
    // Flag interesting status codes
    let (severity, title, desc) = match e.status_code {
        200 => return None, // Normal — store as asset, not finding
        401 => ("LOW",  format!("Auth Required: {}", e.url), "Endpoint requires authentication — confirm bypass isn't possible.".to_string()),
        403 => ("LOW",  format!("Forbidden: {}", e.url), "403 response — resource exists but access blocked. Check for bypass techniques.".to_string()),
        500..=599 => ("MEDIUM", format!("Server Error {}: {}", e.status_code, e.url), format!("HTTP {} server error — may indicate internal issues or injection vector.", e.status_code)),
        _ => return None,
    };

    Some(RawFinding {
        source_tool: "httpx".to_string(),
        severity: severity.to_string(),
        title,
        description: desc,
        affected_url: e.url.clone(),
        affected_port: None,
        cve_references: vec![],
        cvss_score: None,
        evidence: format!("HTTP {} | Title: {} | Tech: {} | CDN: {}",
            e.status_code, e.title, e.tech.join(", "), if e.cdn { &e.cdn_name } else { "none" }),
        remediation: "Review endpoint access controls and error handling.".to_string(),
        http_request: None,
        http_response: None,
    })
}

pub fn parse_live_hosts(output: &str) -> Vec<HttpxEntry> {
    output.lines()
        .filter(|l| !l.is_empty() && l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<HttpxEntry>(l).ok())
        .collect()
}
