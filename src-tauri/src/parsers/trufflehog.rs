// src-tauri/src/parsers/trufflehog.rs
// trufflehog git https://github.com/org/repo --json
// Output: { "SourceMetadata":{"Data":{"Git":{"file":"...","line":1}}}, "DetectorName":"AWS", "Raw":"AKIA...", "Redacted":"AKIA...XXXX" }
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct TruffleResult {
    #[serde(rename = "DetectorName", default)] detector: String,
    #[serde(rename = "DetectorType", default)] detector_type: String,
    #[serde(rename = "Redacted", default)] redacted: String,
    #[serde(rename = "Raw", default)] raw: String,
    #[serde(rename = "SourceMetadata")] metadata: Option<TruffleMetadata>,
    #[serde(rename = "Verified", default)] verified: bool,
}

#[derive(Debug, Deserialize)]
struct TruffleMetadata {
    #[serde(rename = "Data")] data: Option<serde_json::Value>,
}

pub struct TrufflehogParser;

impl ToolParser for TrufflehogParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str::<TruffleResult>(l).ok())
            .map(|r| {
                let severity = if r.verified { "CRITICAL" } else { "HIGH" };
                let location = r.metadata.as_ref()
                    .and_then(|m| m.data.as_ref())
                    .map(|d| d.to_string())
                    .unwrap_or_default();

                let redacted_display = if r.redacted.is_empty() {
                    format!("{}...REDACTED", &r.raw.chars().take(8).collect::<String>())
                } else {
                    r.redacted.clone()
                };

                RawFinding {
                    source_tool: "trufflehog".to_string(),
                    severity: severity.to_string(),
                    title: format!("Secret Leaked: {} ({})",
                        r.detector,
                        if r.verified { "VERIFIED VALID" } else { "unverified" }),
                    description: format!(
                        "{} secret found in source code{}.",
                        r.detector,
                        if r.verified { " — verified as a valid active credential" } else { "" }
                    ),
                    affected_url: location,
                    affected_port: None,
                    cve_references: vec![],
                    cvss_score: if r.verified { Some(9.8) } else { Some(7.5) },
                    evidence: format!("Detector: {}\nType: {}\nValue: {}\nVerified: {}",
                        r.detector, r.detector_type, redacted_display, r.verified),
                    remediation: format!(
                        "1. Revoke {} credential immediately.\n2. Rotate all secrets in the affected repository.\n3. Audit git history with `git log --all` for other exposures.\n4. Add pre-commit hooks to prevent future leaks (gitleaks, git-secrets).",
                        r.detector
                    ),
                    http_request: None,
                    http_response: None,
                }
            })
            .collect()
    }
}
