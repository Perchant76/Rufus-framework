// src-tauri/src/parsers/nuclei.rs
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct NucleiResult {
    #[serde(default)] name: String,
    #[serde(rename = "matched-at", default)] matched_at: String,
    #[serde(default)] severity: String,
    #[serde(default)] info: NucleiInfo,
    #[serde(default)] request: Option<String>,
    #[serde(default)] response: Option<String>,
    #[serde(rename = "extracted-results", default)] extracted_results: Vec<String>,
    #[serde(rename = "template-id", default)] template_id: String,
}

#[derive(Debug, Deserialize, Default)]
struct NucleiInfo {
    #[serde(default)] description: String,
    #[serde(default)] remediation: String,
    #[serde(default)] classification: NucleiClassification,
}

#[derive(Debug, Deserialize, Default)]
struct NucleiClassification {
    #[serde(rename = "cve-id", default)] cve_id: Option<Vec<String>>,
    #[serde(rename = "cvss-score", default)] cvss_score: Option<f64>,
}

pub struct NucleiParser;

impl ToolParser for NucleiParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str::<NucleiResult>(l).ok())
            .map(|r| {
                let severity = map_sev(&r.severity);
                let cves = r.info.classification.cve_id.unwrap_or_default();
                let evidence = if r.extracted_results.is_empty() {
                    format!("Template: {}\nMatched: {}", r.template_id, r.matched_at)
                } else {
                    format!("Template: {}\nMatched: {}\nExtracted: {}",
                        r.template_id, r.matched_at, r.extracted_results.join(", "))
                };
                let remediation = if r.info.remediation.is_empty() {
                    default_remediation(severity).to_string()
                } else {
                    r.info.remediation
                };
                RawFinding {
                    source_tool: "nuclei".to_string(),
                    severity: severity.to_string(),
                    title: r.name,
                    description: r.info.description,
                    affected_url: r.matched_at,
                    affected_port: None,
                    cve_references: cves,
                    cvss_score: r.info.classification.cvss_score,
                    evidence,
                    remediation,
                    http_request: r.request,
                    http_response: r.response,
                }
            })
            .collect()
    }
}

fn map_sev(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "critical" => "CRITICAL", "high" => "HIGH",
        "medium" => "MEDIUM", "low" => "LOW", _ => "INFO",
    }
}

fn default_remediation(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => "Immediate remediation required. Patch or isolate the affected component.",
        "HIGH" => "Remediate within 7 days. Apply vendor patches or configuration hardening.",
        _ => "Review finding and apply appropriate security controls.",
    }
}
