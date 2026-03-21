// src-tauri/src/parsers/testssl.rs
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct TestsslFinding {
    id: String,
    severity: String,
    finding: String,
    #[serde(default)] cve: Option<String>,
}

pub struct TestsslParser;

impl ToolParser for TestsslParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        let entries: Vec<TestsslFinding> = {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(output) {
                // Try nested format { "scanResult": [{ "finding": [...] }] }
                if let Some(arr) = v.get("scanResult").and_then(|r| r.as_array()) {
                    arr.iter()
                        .filter_map(|item| item.get("finding").and_then(|f| f.as_array()))
                        .flatten()
                        .filter_map(|f| serde_json::from_value(f.clone()).ok())
                        .collect()
                } else {
                    // Try flat array
                    serde_json::from_value(v).unwrap_or_default()
                }
            } else {
                return vec![];
            }
        };

        entries.into_iter()
            .filter(|e| e.severity != "OK" && e.severity != "INFO"
                && !e.finding.contains("not vulnerable"))
            .filter_map(|e| map_finding(&e))
            .collect()
    }
}

fn map_finding(e: &TestsslFinding) -> Option<RawFinding> {
    let (severity, title, remediation) = match e.id.as_str() {
        "HEARTBLEED"  => ("CRITICAL", "Heartbleed (CVE-2014-0160)",
            "Update OpenSSL immediately. Rotate all private keys."),
        "POODLE"      => ("HIGH", "POODLE — SSLv3 Enabled",
            "Disable SSLv3. Enable TLS 1.2/1.3 only."),
        "DROWN"       => ("CRITICAL", "DROWN Attack — SSLv2 Enabled",
            "Disable SSLv2 on all servers sharing this key."),
        "ROBOT"       => ("HIGH", "ROBOT Attack — Weak RSA",
            "Disable RSA key exchange. Use ECDHE."),
        "BEAST"       => ("MEDIUM", "BEAST Attack — TLS 1.0 CBC",
            "Disable TLS 1.0. Use TLS 1.2+ with GCM ciphers."),
        "FREAK"       => ("HIGH", "FREAK — Export Ciphers Enabled",
            "Disable all export-grade cipher suites."),
        "LOGJAM"      => ("HIGH", "Logjam — Weak Diffie-Hellman",
            "Use DH parameters ≥ 2048 bits or prefer ECDHE."),
        "RC4"         => ("MEDIUM", "RC4 Cipher Suite Enabled",
            "Disable all RC4 cipher suites — cryptographically broken."),
        "SWEET32"     => ("MEDIUM", "Sweet32 — 64-bit Block Ciphers",
            "Disable 3DES and other 64-bit block ciphers."),
        _             => ("INFO", e.id.as_str(),
            "Review TLS configuration and apply vendor recommendations."),
    };

    let cves: Vec<String> = e.cve.as_ref()
        .map(|c| c.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    Some(RawFinding {
        source_tool: "testssl.sh".to_string(),
        severity: override_severity(&e.severity, severity).to_string(),
        title: title.to_string(),
        description: e.finding.clone(),
        affected_url: String::new(),
        affected_port: Some(443),
        cve_references: cves,
        cvss_score: None,
        evidence: format!("ID: {}\nFinding: {}", e.id, e.finding),
        remediation: remediation.to_string(),
        http_request: None,
        http_response: None,
    })
}

fn override_severity<'a>(testssl: &str, fallback: &'a str) -> &'a str {
    match testssl.to_uppercase().as_str() {
        "CRITICAL" | "FATAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" | "WARN" => "MEDIUM",
        "LOW" => "LOW",
        _ => fallback,
    }
}
