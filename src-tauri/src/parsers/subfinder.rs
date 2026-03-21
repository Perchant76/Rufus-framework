// src-tauri/src/parsers/subfinder.rs
//
// subfinder is invoked with: subfinder -d target.com -oJ -all -recursive
// Each line of output is a JSON object:
// {"host":"sub.example.com","input":"example.com","source":["crtsh"]}

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
        // subfinder output is JSONL (one JSON object per line)
        // We return INFO findings for each discovered subdomain
        output
            .lines()
            .filter(|l| !l.is_empty())
            .filter_map(|line| {
                serde_json::from_str::<SubfinderEntry>(line).ok()
            })
            .map(|entry| {
                let sources = entry.source.join(", ");
                RawFinding {
                    source_tool: "subfinder".to_string(),
                    severity: "INFO".to_string(),
                    title: format!("Subdomain Discovered: {}", entry.host),
                    description: format!("Subdomain {} was discovered via: {}", entry.host, sources),
                    affected_url: format!("https://{}", entry.host),
                    affected_port: None,
                    cve_references: vec![],
                    cvss_score: None,
                    evidence: format!("Host: {}\nSources: {}\nIP: {}", entry.host, sources, entry.ip.unwrap_or_default()),
                    remediation: String::new(),
                    http_request: None,
                    http_response: None,
                }
            })
            .collect()
    }
}

/// Parse subdomain lines into (hostname, ip) pairs for the assets table
pub fn parse_assets(output: &str) -> Vec<(String, Option<String>)> {
    output
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            if let Ok(entry) = serde_json::from_str::<SubfinderEntry>(line) {
                Some((entry.host, entry.ip))
            } else if !line.contains('{') {
                // Plain text fallback: just the hostname
                Some((line.trim().to_string(), None))
            } else {
                None
            }
        })
        .collect()
}
