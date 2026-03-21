// src-tauri/src/parsers/amass.rs
// amass: go install -v github.com/owasp-amass/amass/v4/...@master
// Invocation: amass enum -passive -d target.com -json /tmp/amass_out.json
// Output: JSONL {"name":"sub.target.com","domain":"target.com","addresses":[...],"sources":[...]}
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct AmassResult {
    name: String,
    #[serde(default)] domain: String,
    #[serde(default)] addresses: Vec<AmassAddr>,
    #[serde(default)] sources: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AmassAddr {
    #[serde(default)] ip: String,
    #[serde(rename = "asn", default)] asn: Option<i64>,
    #[serde(rename = "desc", default)] desc: Option<String>,
}

pub struct AmassParser;

impl ToolParser for AmassParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str::<AmassResult>(l).ok())
            .map(|r| {
                let ips: Vec<String> = r.addresses.iter().map(|a| a.ip.clone()).collect();
                let asn_info = r.addresses.first()
                    .and_then(|a| a.desc.as_ref())
                    .map(|d| format!(" ({})", d))
                    .unwrap_or_default();
                RawFinding {
                    source_tool: "amass".to_string(),
                    severity: "INFO".to_string(),
                    title: format!("Subdomain (Amass): {}", r.name),
                    description: format!("Subdomain {} discovered via {}{}", r.name, r.sources.join(", "), asn_info),
                    affected_url: format!("https://{}", r.name),
                    affected_port: None,
                    cve_references: vec![],
                    cvss_score: None,
                    evidence: format!("Name: {}\nDomain: {}\nIPs: {}\nASN: {}\nSources: {}",
                        r.name, r.domain, ips.join(", "),
                        r.addresses.first().and_then(|a| a.asn).map(|n| n.to_string()).unwrap_or_default(),
                        r.sources.join(", ")),
                    remediation: String::new(),
                    http_request: None,
                    http_response: None,
                }
            })
            .collect()
    }
}

pub fn parse_subdomains(output: &str) -> Vec<(String, Option<String>)> {
    output.lines()
        .filter(|l| !l.is_empty() && l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<AmassResult>(l).ok())
        .map(|r| {
            let ip = r.addresses.first().map(|a| a.ip.clone());
            (r.name, ip)
        })
        .collect()
}
