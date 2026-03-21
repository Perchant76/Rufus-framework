// src-tauri/src/parsers/whatweb.rs
use serde_json::Value;
use crate::db::models::RawFinding;
use super::ToolParser;

pub struct WhatwebParser;

impl ToolParser for WhatwebParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        let entries: Vec<Value> = serde_json::from_str(output).unwrap_or_default();
        let mut findings = vec![];

        for entry in &entries {
            let target = entry.get("target").and_then(|t| t.as_str()).unwrap_or("");
            let plugins = match entry.get("plugins").and_then(|p| p.as_object()) {
                Some(p) => p,
                None => continue,
            };

            for (name, data) in plugins {
                let version = data.get("version")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if let Some((sev, cves, remediation)) = known_vuln_tech(name, version) {
                    findings.push(RawFinding {
                        source_tool: "whatweb".to_string(),
                        severity: sev.to_string(),
                        title: format!("Vulnerable Tech Detected: {} {}", name, version),
                        description: format!(
                            "{} version {} detected on {}. Known vulnerabilities exist.",
                            name, version, target
                        ),
                        affected_url: target.to_string(),
                        affected_port: None,
                        cve_references: cves,
                        cvss_score: None,
                        evidence: format!("WhatWeb detected: {} v{} on {}", name, version, target),
                        remediation: remediation.to_string(),
                        http_request: None,
                        http_response: None,
                    });
                } else if !version.is_empty() {
                    findings.push(RawFinding {
                        source_tool: "whatweb".to_string(),
                        severity: "INFO".to_string(),
                        title: format!("Technology Fingerprinted: {} {}", name, version),
                        description: format!("{} v{} detected on {}", name, version, target),
                        affected_url: target.to_string(),
                        affected_port: None,
                        cve_references: vec![],
                        cvss_score: None,
                        evidence: format!("{} version {} on {}", name, version, target),
                        remediation: "Suppress version disclosure headers (X-Powered-By, Server).".to_string(),
                        http_request: None,
                        http_response: None,
                    });
                }
            }
        }
        findings
    }
}

fn known_vuln_tech(name: &str, version: &str) -> Option<(&'static str, Vec<String>, &'static str)> {
    let name_lower = name.to_lowercase();
    let ver_major: u32 = version.split('.').next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let ver_minor: u32 = version.split('.').nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);

    match name_lower.as_str() {
        "wordpress" if ver_major < 6 => Some((
            "HIGH",
            vec!["CVE-2022-21663".to_string(), "CVE-2022-21664".to_string()],
            "Update WordPress to the latest version. Enable automatic background updates.",
        )),
        "php" if ver_major < 8 => Some((
            "HIGH",
            vec!["CVE-2022-31625".to_string()],
            "Upgrade PHP to 8.1+. PHP 7.x is end-of-life.",
        )),
        "jquery" if ver_major == 1 || (ver_major == 2 && ver_minor < 3) => Some((
            "MEDIUM",
            vec!["CVE-2020-11022".to_string()],
            "Upgrade jQuery to 3.7+.",
        )),
        "apache" if ver_major == 2 && ver_minor == 4 && version.contains("49") => Some((
            "CRITICAL",
            vec!["CVE-2021-41773".to_string()],
            "Update Apache immediately. 2.4.49 has path traversal RCE.",
        )),
        _ => None,
    }
}
