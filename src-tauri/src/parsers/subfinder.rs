// src-tauri/src/parsers/subfinder.rs
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct SubfinderEntry {
    host: String,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    source: Vec<String>,
}

pub struct SubfinderParser;

impl ToolParser for SubfinderParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_str::<SubfinderEntry>(l).ok())
            .map(|e| RawFinding {
                source_tool: "subfinder".to_string(),
                severity: "INFO".to_string(),
                title: format!("Subdomain: {}", e.host),
                description: format!("Discovered via: {}", e.source.join(", ")),
                affected_url: format!("https://{}", e.host),
                affected_port: None,
                cve_references: vec![],
                cvss_score: None,
                evidence: format!("Host: {}\nIP: {}", e.host, e.ip.as_deref().unwrap_or("")),
                remediation: String::new(),
                http_request: None,
                http_response: None,
            })
            .collect()
    }
}

pub fn parse_assets(output: &str) -> Vec<(String, Option<String>)> {
    output.lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            if let Ok(e) = serde_json::from_str::<SubfinderEntry>(l) {
                Some((e.host, e.ip))
            } else if !l.contains('{') {
                Some((l.trim().to_string(), None))
            } else {
                None
            }
        })
        .collect()
}
