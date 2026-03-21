// src-tauri/src/parsers/katana.rs
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct KatanaEntry {
    #[serde(default)] endpoint: String,
    #[serde(default)] source: String,
    #[serde(default)] method: String,
}

pub struct KatanaParser;

impl ToolParser for KatanaParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str::<KatanaEntry>(l).ok())
            .filter(|e| !e.endpoint.is_empty())
            .filter_map(|e| {
                let url_lower = e.endpoint.to_lowercase();
                if e.endpoint.contains('?') {
                    Some(RawFinding {
                        source_tool: "katana".to_string(),
                        severity: "INFO".to_string(),
                        title: format!("Query Parameter Endpoint: {}", e.endpoint),
                        description: "Endpoint accepts query parameters — potential injection surface.".to_string(),
                        affected_url: e.endpoint.clone(),
                        affected_port: None, cve_references: vec![], cvss_score: None,
                        evidence: format!("Method: {}\nSource: {}", e.method, e.source),
                        remediation: "Validate and sanitize all query parameters server-side.".to_string(),
                        http_request: None, http_response: None,
                    })
                } else if url_lower.contains("/api/") || url_lower.contains("/v1/") || url_lower.contains("/v2/") {
                    Some(RawFinding {
                        source_tool: "katana".to_string(),
                        severity: "INFO".to_string(),
                        title: format!("API Endpoint: {}", e.endpoint),
                        description: "API endpoint discovered during crawl.".to_string(),
                        affected_url: e.endpoint.clone(),
                        affected_port: None, cve_references: vec![], cvss_score: None,
                        evidence: format!("Method: {}\nSource: {}", e.method, e.source),
                        remediation: "Ensure API endpoints enforce authentication and rate limiting.".to_string(),
                        http_request: None, http_response: None,
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

pub fn parse_endpoints(output: &str) -> Vec<String> {
    output.lines()
        .filter(|l| !l.is_empty() && l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<KatanaEntry>(l).ok())
        .map(|e| e.endpoint)
        .filter(|e| !e.is_empty())
        .collect()
}
