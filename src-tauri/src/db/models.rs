// src-tauri/src/db/models.rs
use serde::{Deserialize, Serialize};

// ── Existing types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub target: String,
    pub target_type: String,
    pub scope: Vec<String>,
    pub status: String,
    pub stealth_mode: bool,
    pub tools_used: Vec<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub finding_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub id: String,
    pub scan_id: String,
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
    pub timestamp: String,
    pub in_scope: bool,
    pub http_request: Option<String>,
    pub http_response: Option<String>,
    // Triage fields (Feature 9)
    #[serde(default = "default_triage")]
    pub triage_status: String,
    #[serde(default)]
    pub priority_override: Option<String>,
    #[serde(default)]
    pub analyst_notes: String,
    #[serde(default)]
    pub reproduction_steps: String,
    #[serde(default)]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub reported_at: Option<String>,
}

fn default_triage() -> String { "new".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    pub id: String,
    pub scan_id: String,
    pub asset_type: String,
    pub value: String,
    pub ip: Option<String>,
    pub http_status: Option<i64>,
    pub page_title: Option<String>,
    pub tech_stack: Vec<String>,
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
    #[serde(default)]
    pub wordlist_id: Option<String>,
    #[serde(default)]
    pub nuclei_profile_id: Option<String>,
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

// ── Feature 1: Bug Bounty Programs ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugBountyProgram {
    pub id: String,
    pub name: String,
    pub program_type: String,   // "company" | "wildcard" | "url"
    pub platform: String,       // "hackerone" | "bugcrowd" | "intigriti" | "yeswehack" | "custom"
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub max_bounty: Option<u32>,
    pub notes: String,
    pub scan_ids: Vec<String>,
    pub created_at: String,
}

// ── Feature 3: Workflow Engine ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub id: String,
    pub workflow_type: String,  // "company" | "wildcard" | "single"
    pub target: String,
    pub current_stage: usize,
    pub stages: Vec<WorkflowStage>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStage {
    pub name: String,
    pub description: String,
    pub why: String,
    pub tools: Vec<String>,
    pub status: String,         // "locked" | "ready" | "running" | "complete" | "skipped"
    pub findings_count: usize,
    pub completed_at: Option<String>,
}

// ── Feature 4: Wordlists ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wordlist {
    pub id: String,
    pub name: String,
    pub tag: String,            // "directories" | "subdomains" | "parameters" | "passwords"
    pub word_count: usize,
    pub source: String,         // "imported" | "generated" | "builtin"
    pub created_at: String,
}

// ── Feature 5: Nuclei Profiles ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiProfile {
    pub id: String,
    pub name: String,
    pub selected_tags: Vec<String>,
    pub selected_severities: Vec<String>,
    pub exclude_tags: Vec<String>,
    pub created_at: String,
}

// ── Feature 6: HTTP Replay ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedRequest {
    pub id: String,
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub duration_ms: u64,
    pub redirect_chain: Vec<String>,
}

// ── Feature 7: OSINT ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintResult {
    pub id: String,
    pub scan_id: Option<String>,
    pub source: String,         // "github" | "google_dork" | "manual"
    pub query: String,
    pub result_count: Option<u32>,
    pub url: String,
    pub notes: String,
    pub severity: String,
    pub created_at: String,
}

// ── Feature 8: Cloud Assets ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAsset {
    pub id: String,
    pub scan_id: String,
    pub provider: String,
    pub url: String,
    pub status: u16,
    pub accessible: bool,
    pub takeover_candidate: bool,
    pub checked_at: String,
}

// ── Feature 10: Takeover Candidates ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverCandidate {
    pub subdomain: String,
    pub cname: Option<String>,
    pub service: String,
    pub fingerprint_matched: String,
    pub confidence: String,
}
