// src-tauri/src/parsers/testssl.rs
//
// testssl.sh invoked with: testssl.sh --jsonfile /tmp/testssl.json --quiet target:443
// JSON output is an array of finding objects

use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct TestsslFinding {
    id: String,
    severity: String,
    finding: String,
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    cwe: Option<String>,
}

pub struct TestsslParser;

impl ToolParser for TestsslParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        // Output may be wrapped in an outer array under key "scanResult"
        let entries: Vec<TestsslFinding> = if let Ok(v) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(arr) = v.get("scanResult").and_then(|r| r.as_array()) {
                arr.iter()
                    .filter_map(|item| {
                        item.get("finding")
                            .and_then(|f| f.as_array())
                            .map(|findings| {
                                findings.iter()
                                    .filter_map(|f| serde_json::from_value(f.clone()).ok())
                                    .collect::<Vec<TestsslFinding>>()
                            })
                    })
                    .flatten()
                    .collect()
            } else if let Ok(arr) = serde_json::from_value::<Vec<TestsslFinding>>(v) {
                arr
            } else {
                return vec![]
            }
        } else {
            return vec![]
        };

        entries
            .into_iter()
            .filter(|e| e.severity != "OK" && e.severity != "INFO" && !e.finding.contains("not vulnerable"))
            .filter_map(|e| map_testssl_finding(&e))
            .collect()
    }
}

fn map_testssl_finding(e: &TestsslFinding) -> Option<RawFinding> {
    let (severity, title, remediation) = match e.id.as_str() {
        "BEAST" => ("MEDIUM", "BEAST Attack (TLS 1.0 CBC)", "Disable TLS 1.0. Use TLS 1.2+ with GCM cipher suites."),
        "POODLE" => ("HIGH", "POODLE Attack (SSLv3)", "Disable SSLv3 immediately. Enable TLS 1.2/1.3 only."),
        "HEARTBLEED" => ("CRITICAL", "Heartbleed (CVE-2014-0160)", "Update OpenSSL immediately. Rotate all private keys and certificates."),
        "CCS" | "CCS_injection" => ("HIGH", "OpenSSL CCS Injection (CVE-2014-0224)", "Update OpenSSL to 0.9.8za / 1.0.0m / 1.0.1h or later."),
        "ROBOT" => ("HIGH", "ROBOT Attack (RSA PKCS#1 v1.5)", "Disable RSA key exchange cipher suites. Use ECDHE."),
        "CRIME_TLS" => ("MEDIUM", "CRIME Attack (TLS Compression)", "Disable TLS compression on the server."),
        "BREACH" => ("MEDIUM", "BREACH Attack (HTTP Compression)", "Disable HTTP compression for sensitive responses or use CSRF tokens."),
        "RC4" => ("MEDIUM", "RC4 Cipher Suite Enabled", "Disable all RC4 cipher suites. RC4 is cryptographically broken."),
        "SWEET32" => ("MEDIUM", "Sweet32 Attack (64-bit Block Ciphers)", "Disable 3DES and other 64-bit block cipher suites."),
        "FREAK" => ("HIGH", "FREAK Attack (Export Ciphers)", "Disable export-grade cipher suites."),
        "LOGJAM" => ("HIGH", "Logjam Attack (Weak DH)", "Use DH parameters of 2048 bits or more. Prefer ECDHE."),
        "DROWN" => ("CRITICAL", "DROWN Attack (SSLv2)", "Disable SSLv2 on all servers sharing the same private key."),
        s if s.starts_with("tls1") && e.severity.to_lowercase() == "low" => (
            "LOW", "Legacy TLS Version Enabled", "Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 minimum."
        ),
        _ => ("INFO", e.id.as_str(), "Review TLS configuration and apply vendor recommendations."),
    };

    let cves: Vec<String> = e.cve.as_ref()
        .map(|c| c.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    Some(RawFinding {
        source_tool: "testssl.sh".to_string(),
        severity: map_severity_str(&e.severity, severity),
        title: title.to_string(),
        description: e.finding.clone(),
        affected_url: String::new(), // filled in by caller with target URL
        affected_port: Some(443),
        cve_references: cves,
        cvss_score: None,
        evidence: format!("testssl.sh ID: {}\nFinding: {}", e.id, e.finding),
        remediation: remediation.to_string(),
        http_request: None,
        http_response: None,
    })
}

fn map_severity_str(testssl_sev: &str, fallback: &str) -> String {
    match testssl_sev.to_uppercase().as_str() {
        "CRITICAL" | "FATAL" => "CRITICAL",
        "HIGH" => "HIGH",
        "MEDIUM" | "WARN" => "MEDIUM",
        "LOW" => "LOW",
        _ => fallback,
    }.to_string()
}
