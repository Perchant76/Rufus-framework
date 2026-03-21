// src-tauri/src/parsers/wapiti.rs
//
// wapiti3 invoked with: wapiti -u https://target.com -f json -o /tmp/wapiti.json
// JSON output: { "vulnerabilities": { "SQL Injection": [...], "XSS": [...], ... } }

use serde::{Deserialize};
use serde_json::Value;
use crate::db::models::RawFinding;
use super::ToolParser;

pub struct WapitiParser;

impl ToolParser for WapitiParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        let v: Value = match serde_json::from_str(output) {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let vulns = match v.get("vulnerabilities").and_then(|v| v.as_object()) {
            Some(v) => v,
            None => return vec![],
        };

        let mut findings = vec![];

        for (vuln_type, entries) in vulns {
            let arr = match entries.as_array() {
                Some(a) => a,
                None => continue,
            };

            for entry in arr {
                let path = entry.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let parameter = entry.get("parameter").and_then(|v| v.as_str()).unwrap_or("");
                let method = entry.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
                let info = entry.get("info").and_then(|v| v.as_str()).unwrap_or("");
                let http_req = entry.get("http_request").and_then(|v| v.as_str()).map(str::to_string);
                let curl_cmd = entry.get("curl_command").and_then(|v| v.as_str()).unwrap_or("");
                let ref_url = entry.get("ref").and_then(|v| v.as_str()).unwrap_or("");

                let (severity, title, desc, remediation, cves) = map_wapiti_vuln(vuln_type, parameter, path);

                findings.push(RawFinding {
                    source_tool: "wapiti3".to_string(),
                    severity: severity.to_string(),
                    title,
                    description: desc,
                    affected_url: path.to_string(),
                    affected_port: None,
                    cve_references: cves,
                    cvss_score: None,
                    evidence: format!(
                        "Parameter: {}\nMethod: {}\nInfo: {}\nCurl: {}",
                        parameter, method, info, curl_cmd
                    ),
                    remediation,
                    http_request: http_req,
                    http_response: None,
                });
            }
        }

        findings
    }
}

fn map_wapiti_vuln(vuln_type: &str, parameter: &str, path: &str) -> (&'static str, String, String, String, Vec<String>) {
    match vuln_type {
        "SQL Injection" => (
            "CRITICAL",
            format!("SQL Injection — Parameter: {}", parameter),
            format!("SQL injection vulnerability detected in parameter '{}' at {}.", parameter, path),
            "Use parameterized queries / prepared statements. Never concatenate user input into SQL.".to_string(),
            vec!["CWE-89".to_string()],
        ),
        "Blind SQL Injection" => (
            "CRITICAL",
            format!("Blind SQL Injection — Parameter: {}", parameter),
            format!("Blind SQL injection detected via timing or boolean analysis in '{}' at {}.", parameter, path),
            "Use parameterized queries. Implement WAF rules for SQLi patterns.".to_string(),
            vec!["CWE-89".to_string()],
        ),
        "Cross Site Scripting" | "Reflected Cross Site Scripting" => (
            "HIGH",
            format!("Reflected XSS — Parameter: {}", parameter),
            format!("Reflected XSS in parameter '{}' at {}.", parameter, path),
            "Encode all user-supplied output. Implement a strict Content-Security-Policy.".to_string(),
            vec!["CWE-79".to_string()],
        ),
        "Stored Cross Site Scripting" | "Permanent XSS" => (
            "HIGH",
            format!("Stored XSS — Parameter: {}", parameter),
            format!("Persistent XSS found — payload stored and reflected at {}.", path),
            "Sanitize HTML input server-side. Use output encoding. Apply strict CSP.".to_string(),
            vec!["CWE-79".to_string()],
        ),
        "Command Execution" | "Command injection" => (
            "CRITICAL",
            format!("OS Command Injection — Parameter: {}", parameter),
            format!("Command injection in '{}' at {}. Attacker can execute arbitrary OS commands.", parameter, path),
            "Never pass user input to shell commands. Use language APIs instead of exec/system calls.".to_string(),
            vec!["CWE-78".to_string()],
        ),
        "Path Traversal" => (
            "HIGH",
            format!("Path Traversal — Parameter: {}", parameter),
            format!("Directory traversal in '{}' at {} allows reading arbitrary files.", parameter, path),
            "Validate and canonicalize file paths. Restrict access to web root only.".to_string(),
            vec!["CWE-22".to_string()],
        ),
        "CSRF" => (
            "MEDIUM",
            format!("CSRF — Endpoint: {}", path),
            format!("Cross-Site Request Forgery vulnerability at {}.", path),
            "Implement anti-CSRF tokens (synchronizer token pattern). Use SameSite=Strict cookie attribute.".to_string(),
            vec!["CWE-352".to_string()],
        ),
        "Open Redirect" => (
            "MEDIUM",
            format!("Open Redirect — Parameter: {}", parameter),
            format!("Unvalidated redirect via '{}' at {}.", parameter, path),
            "Validate redirect destinations against an allowlist. Never redirect to user-supplied URLs.".to_string(),
            vec!["CWE-601".to_string()],
        ),
        "SSRF" | "Server Side Request Forgery" => (
            "CRITICAL",
            format!("SSRF — Parameter: {}", parameter),
            format!("Server-Side Request Forgery in '{}' at {} — can access internal services.", parameter, path),
            "Validate and allowlist URLs for server-side requests. Block requests to private IP ranges.".to_string(),
            vec!["CWE-918".to_string()],
        ),
        "XXE" | "XML External Entity" => (
            "HIGH",
            format!("XXE Injection — {}", path),
            "XML External Entity injection — can read files and trigger SSRF.".to_string(),
            "Disable external entity processing in XML parsers. Use JSON where possible.".to_string(),
            vec!["CWE-611".to_string()],
        ),
        _ => (
            "MEDIUM",
            format!("{} — {}", vuln_type, path),
            format!("Web vulnerability '{}' detected at {}.", vuln_type, path),
            "Review finding and apply OWASP remediation guidance.".to_string(),
            vec![],
        ),
    }
}
