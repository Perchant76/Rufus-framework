// src-tauri/src/parsers/dalfox.rs
// dalfox url https://target.com --format json
// Output: { "type":"G", "poc":{"method":"GET","data":"..."}, "param":"q", "evidence":"...", "message":"..." }
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct DalfoxResult {
    #[serde(rename = "type", default)] result_type: String,
    #[serde(default)] param: String,
    #[serde(default)] evidence: String,
    #[serde(default)] message: String,
    #[serde(default)] poc: Option<DalfoxPoc>,
}

#[derive(Debug, Deserialize)]
struct DalfoxPoc {
    #[serde(default)] method: String,
    #[serde(default)] data: String,
    #[serde(default)] path: String,
}

pub struct DalfoxParser;

impl ToolParser for DalfoxParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        // Try JSON array first, then JSONL
        let results: Vec<DalfoxResult> = if output.trim_start().starts_with('[') {
            serde_json::from_str(output).unwrap_or_default()
        } else {
            output.lines()
                .filter(|l| !l.is_empty() && l.starts_with('{'))
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        };

        results.iter().filter_map(|r| {
            // Only report G (verified) and R (reflected) types
            if r.result_type != "G" && r.result_type != "R" && r.result_type != "V" {
                return None;
            }

            let severity = if r.result_type == "G" { "HIGH" } else { "MEDIUM" };
            let xss_type = match r.result_type.as_str() {
                "G" => "Reflected XSS (Verified)",
                "R" => "Reflected XSS (Potential)",
                "V" => "DOM-based XSS",
                _ => "XSS",
            };

            let poc = r.poc.as_ref();
            let url = poc.map(|p| p.path.as_str()).unwrap_or("").to_string();

            Some(RawFinding {
                source_tool: "dalfox".to_string(),
                severity: severity.to_string(),
                title: format!("{} — Parameter: {}", xss_type, r.param),
                description: format!(
                    "{} vulnerability found in parameter '{}'. {}",
                    xss_type, r.param, r.message
                ),
                affected_url: url,
                affected_port: None,
                cve_references: vec!["CWE-79".to_string()],
                cvss_score: if r.result_type == "G" { Some(6.1) } else { Some(4.7) },
                evidence: format!(
                    "Parameter: {}\nEvidence: {}\nPoC: {}",
                    r.param, r.evidence,
                    poc.map(|p| format!("{} {}", p.method, p.data)).unwrap_or_default()
                ),
                remediation: "1. HTML-encode all user-supplied output.\n2. Implement Content-Security-Policy (CSP).\n3. Use framework-level XSS protection (React JSX, Angular templates).\n4. Set HttpOnly and Secure flags on session cookies.".to_string(),
                http_request: poc.map(|p| format!("{} {}", p.method, p.data)),
                http_response: None,
            })
        }).collect()
    }
}
