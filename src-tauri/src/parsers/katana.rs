// src-tauri/src/parsers/katana.rs
//
// katana invoked with: katana -u https://target.com -json -d 5 -jc -kf all
// Each line is a JSON object with crawled endpoint info

use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct KatanaEntry {
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    method: String,
    #[serde(rename = "response", default)]
    response: Option<KatanaResponse>,
}

#[derive(Debug, Deserialize)]
struct KatanaResponse {
    #[serde(default)]
    status_code: u16,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    body: String,
}

pub struct KatanaParser;

impl ToolParser for KatanaParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        let entries: Vec<KatanaEntry> = output
            .lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        let mut findings = vec![];

        // Flag endpoints with interesting patterns
        for e in &entries {
            let url_lower = e.endpoint.to_lowercase();

            // Detect forms that could be injection points
            if e.endpoint.contains('?') {
                findings.push(RawFinding {
                    source_tool: "katana".to_string(),
                    severity: "INFO".to_string(),
                    title: format!("Query Parameter Endpoint: {}", e.endpoint),
                    description: "Endpoint accepts query parameters — potential injection surface.".to_string(),
                    affected_url: e.endpoint.clone(),
                    affected_port: None,
                    cve_references: vec![],
                    cvss_score: None,
                    evidence: format!("Crawled via: {}\nMethod: {}", e.source, e.method),
                    remediation: "Validate and sanitize all query parameters server-side.".to_string(),
                    http_request: None,
                    http_response: None,
                });
            }

            // API endpoints
            if url_lower.contains("/api/") || url_lower.contains("/v1/") || url_lower.contains("/v2/") {
                findings.push(RawFinding {
                    source_tool: "katana".to_string(),
                    severity: "INFO".to_string(),
                    title: format!("API Endpoint: {}", e.endpoint),
                    description: "API endpoint discovered during crawl.".to_string(),
                    affected_url: e.endpoint.clone(),
                    affected_port: None,
                    cve_references: vec![],
                    cvss_score: None,
                    evidence: format!("Method: {}\nSource: {}", e.method, e.source),
                    remediation: "Ensure API endpoints enforce authentication and rate limiting.".to_string(),
                    http_request: None,
                    http_response: None,
                });
            }
        }

        findings
    }
}

/// Returns all discovered URLs for asset storage
pub fn parse_endpoints(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|l| !l.is_empty() && l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<KatanaEntry>(l).ok())
        .map(|e| e.endpoint)
        .filter(|e| !e.is_empty())
        .collect()
}
