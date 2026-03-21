// src-tauri/src/parsers/nuclei.rs
//
// nuclei invoked with: nuclei -u target.com -json -o /tmp/nuclei_out.jsonl
// Each line is a JSON object:
// {"template-id":"...","name":"...","severity":"critical","host":"...","matched-at":"...","info":{...},"matcher-name":"...","extracted-results":[]}

use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct NucleiResult {
    #[serde(rename = "template-id", default)]
    template_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    host: String,
    #[serde(rename = "matched-at", default)]
    matched_at: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    info: NucleiInfo,
    #[serde(rename = "curl-command", default)]
    curl_command: Option<String>,
    #[serde(default)]
    request: Option<String>,
    #[serde(default)]
    response: Option<String>,
    #[serde(rename = "extracted-results", default)]
    extracted_results: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct NucleiInfo {
    #[serde(default)]
    description: String,
    #[serde(default)]
    remediation: String,
    #[serde(default)]
    classification: NucleiClassification,
    #[serde(default)]
    reference: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct NucleiClassification {
    #[serde(rename = "cve-id", default)]
    cve_id: Option<Vec<String>>,
    #[serde(rename = "cvss-score", default)]
    cvss_score: Option<f64>,
}

pub struct NucleiParser;

impl ToolParser for NucleiParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output
            .lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|line| serde_json::from_str::<NucleiResult>(line).ok())
            .map(|r| {
                let severity = map_severity(&r.severity);
                let cves = r.info.classification.cve_id.unwrap_or_default();
                let cvss = r.info.classification.cvss_score;

                let evidence = if r.extracted_results.is_empty() {
                    format!("Template: {}\nMatched at: {}", r.template_id, r.matched_at)
                } else {
                    format!(
                        "Template: {}\nMatched at: {}\nExtracted: {}",
                        r.template_id,
                        r.matched_at,
                        r.extracted_results.join(", ")
                    )
                };

                let remediation = if r.info.remediation.is_empty() {
                    default_remediation(severity)
                } else {
                    r.info.remediation.clone()
                };

                RawFinding {
                    source_tool: "nuclei".to_string(),
                    severity: severity.to_string(),
                    title: r.name,
                    description: r.info.description,
                    affected_url: r.matched_at,
                    affected_port: None,
                    cve_references: cves,
                    cvss_score: cvss,
                    evidence,
                    remediation,
                    http_request: r.request,
                    http_response: r.response,
                }
            })
            .collect()
    }
}

fn map_severity(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "critical" => "CRITICAL",
        "high" => "HIGH",
        "medium" => "MEDIUM",
        "low" => "LOW",
        _ => "INFO",
    }
}

fn default_remediation(severity: &str) -> String {
    match severity {
        "CRITICAL" => "Immediate remediation required. Patch, disable, or isolate the affected component.".to_string(),
        "HIGH" => "Remediate within 7 days. Review and apply vendor patches or configuration hardening.".to_string(),
        "MEDIUM" => "Remediate within 30 days. Apply security best practices and review configuration.".to_string(),
        _ => "Review finding and apply appropriate security controls.".to_string(),
    }
}
