// src-tauri/src/parsers/dnsx.rs
// dnsx -l subdomains.txt -json -a -cname -mx -ns -resp -silent
// Output: { "host":"sub.example.com", "a":["1.2.3.4"], "cname":["cdn.provider.com"], ... }
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
pub struct DnsxEntry {
    #[serde(default)] pub host: String,
    #[serde(default)] pub a: Vec<String>,
    #[serde(default)] pub cname: Vec<String>,
    #[serde(default)] pub mx: Vec<String>,
    #[serde(default)] pub ns: Vec<String>,
    #[serde(rename = "status-code", default)] pub status: Option<String>,
}

pub struct DnsxParser;

impl ToolParser for DnsxParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str::<DnsxEntry>(l).ok())
            .flat_map(|e| dns_findings(&e))
            .collect()
    }
}

fn dns_findings(e: &DnsxEntry) -> Vec<RawFinding> {
    let mut findings = vec![];

    // Check for wildcard DNS (indicates loose DNS config)
    if e.a.iter().any(|ip| is_known_wildcard_ip(ip)) {
        findings.push(RawFinding {
            source_tool: "dnsx".to_string(),
            severity: "LOW".to_string(),
            title: format!("Wildcard DNS Response: {}", e.host),
            description: "Domain resolves to a wildcard IP — may indicate DNS misconfiguration.".to_string(),
            affected_url: format!("https://{}", e.host),
            affected_port: None,
            cve_references: vec![],
            cvss_score: None,
            evidence: format!("Host: {} → A: {}", e.host, e.a.join(", ")),
            remediation: "Review DNS configuration. Wildcard records can obscure misconfigured subdomains.".to_string(),
            http_request: None,
            http_response: None,
        });
    }

    // Flag interesting CNAMEs (potential takeover surface)
    for cname in &e.cname {
        let cname_lower = cname.to_lowercase();
        let takeover_services = [
            "github.io", "herokuapp.com", "netlify.app", "surge.sh",
            "azurewebsites.net", "cloudfront.net", "fastly.net", "wpengine.com",
        ];
        if takeover_services.iter().any(|s| cname_lower.contains(s)) {
            findings.push(RawFinding {
                source_tool: "dnsx".to_string(),
                severity: "MEDIUM".to_string(),
                title: format!("Third-party CNAME: {} → {}", e.host, cname),
                description: "CNAME points to a third-party service — potential subdomain takeover surface.".to_string(),
                affected_url: format!("https://{}", e.host),
                affected_port: None,
                cve_references: vec![],
                cvss_score: Some(5.4),
                evidence: format!("{} CNAME → {}\nA records: {}", e.host, cname, e.a.join(", ")),
                remediation: "Verify the third-party service is still provisioned. If not, remove the CNAME.".to_string(),
                http_request: None,
                http_response: None,
            });
        }
    }

    findings
}

fn is_known_wildcard_ip(ip: &str) -> bool {
    // Common wildcard "catch-all" IPs used by providers
    matches!(ip, "0.0.0.0" | "127.0.0.1")
}

pub fn parse_resolved_hosts(output: &str) -> Vec<DnsxEntry> {
    output.lines()
        .filter(|l| !l.is_empty() && l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<DnsxEntry>(l).ok())
        .filter(|e| !e.a.is_empty()) // Only hosts with A records (actually live)
        .collect()
}
