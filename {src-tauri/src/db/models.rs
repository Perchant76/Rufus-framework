// src-tauri/src/db/models.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Scan {
    pub id: String,
    pub target: String,
    pub target_type: String,
    pub scope: String,
    pub status: String,
    pub stealth_mode: bool,
    pub auth_config: Option<String>,
    pub rate_config: Option<String>,
    pub tools_used: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub duration_secs: Option<i64>,
    pub finding_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VulnFinding {
    pub id: String,
    pub scan_id: String,
    pub source_tool: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub affected_url: String,
    pub affected_port: Option<i64>,
    pub cve_references: String,
    pub cvss_score: Option<f64>,
    pub evidence: String,
    pub remediation: String,
    pub timestamp: String,
    pub in_scope: bool,
    pub http_request: Option<String>,
    pub http_response: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DiscoveredAsset {
    pub id: String,
    pub scan_id: String,
    pub asset_type: String,
    pub value: String,
    pub ip: Option<String>,
    pub http_status: Option<i64>,
    pub page_title: Option<String>,
    pub tech_stack: Option<String>,
    pub redirect_chain: Option<String>,
    pub parent: Option<String>,
    pub in_scope: bool,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawFinding {
    pub source_tool: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub affected_url: String,
    pub affected_port: Option<i64>,
    pub cve_references: Vec<String>,
    pub cvss_score: Option<f64>,
    pub evidence: String,
    pub remediation: String,
    pub http_request: Option<String>,
    pub http_response: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target: String,
    pub target_type: String,
    pub scope: Vec<String>,
    pub stealth_mode: bool,
    pub concurrency: u32,
    pub delay_min_ms: u64,
    pub delay_max_ms: u64,
    pub tools: Vec<String>,
    pub auth: Option<AuthConfig>,
    pub respect_robots: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub mode: String,
    pub login_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cookie_string: Option<String>,
    pub bearer_token: Option<String>,
    pub custom_headers: Option<Vec<(String, String)>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolStatus {
    pub name: String,
    pub available: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub install_cmd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub tool: String,
    pub percent: f32,
    pub message: String,
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComparison {
    pub scan_a: Scan,
    pub scan_b: Scan,
    pub new_findings: Vec<VulnFinding>,
    pub resolved_finding_titles: Vec<String>,
    pub persistent_findings: Vec<PersistentFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentFinding {
    pub title: String,
    pub severity: String,
    pub scan_count: i64,
    pub is_chronic: bool,
    pub first_seen: String,
    pub findings: Vec<VulnFinding>,
}
