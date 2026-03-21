// src-tauri/src/parsers/nikto.rs
// nikto -h target.com -Format json -output /tmp/nikto.json
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct NiktoReport {
    #[serde(default)] vulnerabilities: Vec<NiktoVuln>,
}

#[derive(Debug, Deserialize)]
struct NiktoVuln {
    #[serde(rename = "id", default)] id: String,
    #[serde(rename = "OSVDB", default)] osvdb: String,
    #[serde(rename = "method", default)] method: String,
    #[serde(rename = "url", default)] url: String,
    #[serde(rename = "msg", default)] msg: String,
    #[serde(rename = "references", default)] references: Option<NiktoRef>,
}

#[derive(Debug, Deserialize)]
struct NiktoRef {
    #[serde(rename = "CVE", default)] cve: Vec<String>,
}

pub struct NiktoParser;

impl ToolParser for NiktoParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        // Try JSON format first
        if let Ok(report) = serde_json::from_str::<NiktoReport>(output) {
            return report.vulnerabilities.iter().map(|v| {
                let severity = classify_nikto_severity(&v.msg);
                let cves = v.references.as_ref()
                    .map(|r| r.cve.clone())
                    .unwrap_or_default();
                RawFinding {
                    source_tool: "nikto".to_string(),
                    severity: severity.to_string(),
                    title: format!("Nikto: {}", truncate(&v.msg, 80)),
                    description: v.msg.clone(),
                    affected_url: v.url.clone(),
                    affected_port: None,
                    cve_references: cves,
                    cvss_score: None,
                    evidence: format!("ID: {} | OSVDB: {} | Method: {}\n{}", v.id, v.osvdb, v.method, v.msg),
                    remediation: nikto_remediation(&v.msg),
                    http_request: None,
                    http_response: None,
                }
            }).collect();
        }

        // Fallback: parse text output
        output.lines()
            .filter(|l| l.starts_with("+ "))
            .map(|l| {
                let msg = l.trim_start_matches("+ ").trim();
                let severity = classify_nikto_severity(msg);
                RawFinding {
                    source_tool: "nikto".to_string(),
                    severity: severity.to_string(),
                    title: format!("Nikto: {}", truncate(msg, 80)),
                    description: msg.to_string(),
                    affected_url: String::new(),
                    affected_port: None,
                    cve_references: vec![],
                    cvss_score: None,
                    evidence: l.to_string(),
                    remediation: nikto_remediation(msg),
                    http_request: None,
                    http_response: None,
                }
            })
            .collect()
    }
}

fn classify_nikto_severity(msg: &str) -> &'static str {
    let m = msg.to_lowercase();
    if m.contains("remote code") || m.contains("rce") || m.contains("unauthenticated") { return "CRITICAL"; }
    if m.contains("sql injection") || m.contains("xss") || m.contains("file inclusion") { return "HIGH"; }
    if m.contains("default password") || m.contains("default credential") { return "HIGH"; }
    if m.contains("phpinfo") || m.contains("server status") || m.contains("directory listing") { return "MEDIUM"; }
    if m.contains("header") || m.contains("cookie") || m.contains("version") { return "LOW"; }
    "INFO"
}

fn nikto_remediation(msg: &str) -> String {
    let m = msg.to_lowercase();
    if m.contains("phpinfo") { return "Remove phpinfo() pages from production. They disclose server configuration.".into(); }
    if m.contains("directory listing") { return "Disable directory listing (Options -Indexes in Apache, autoindex off in Nginx).".into(); }
    if m.contains("default password") { return "Change all default credentials immediately. Audit all service accounts.".into(); }
    if m.contains("header") { return "Add security headers: X-Frame-Options, X-Content-Type-Options, CSP, HSTS.".into(); }
    "Review finding and apply appropriate remediation per vendor guidance.".into()
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}
