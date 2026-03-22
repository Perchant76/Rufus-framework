// src-tauri/src/commands/ptsync.rs
// Export Rufus findings directly to PenForge .ptsync format
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct PtsyncVuln {
    title: String,
    severity: String,          // Critical/High/Medium/Low/Info
    cvss_score: Option<f64>,
    cve_id: String,
    description: String,
    impact: String,
    steps_to_reproduce: String,
    proof_of_concept: String,
    remediation: String,
    references: Vec<String>,
    status: String,
    tags: Vec<String>,
    evidence_paths: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PtsyncFile {
    format: String,
    exported_at: String,
    exported_by: String,
    vulnerabilities: Vec<PtsyncVuln>,
}

fn map_severity(rufus_sev: &str) -> String {
    match rufus_sev.to_uppercase().as_str() {
        "CRITICAL" => "Critical".to_string(),
        "HIGH"     => "High".to_string(),
        "MEDIUM"   => "Medium".to_string(),
        "LOW"      => "Low".to_string(),
        _          => "Info".to_string(),
    }
}

#[tauri::command]
pub async fn export_to_ptsync(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    operator_name: String,
    output_path: String,
    severity_filter: Vec<String>, // empty = all
) -> Result<String, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let findings = store.get_findings_for_scan(&scan_id).map_err(|e| e.to_string())?;

    let vulns: Vec<PtsyncVuln> = findings.iter()
        .filter(|f| {
            if severity_filter.is_empty() { return true; }
            severity_filter.iter().any(|s| s.to_uppercase() == f.severity.to_uppercase())
        })
        .filter(|f| f.in_scope)
        .map(|f| PtsyncVuln {
            title: f.title.clone(),
            severity: map_severity(&f.severity),
            cvss_score: f.cvss_score,
            cve_id: f.cve_references.join(", "),
            description: f.description.clone(),
            impact: format!("Identified by {} against {}", f.source_tool, f.affected_url),
            steps_to_reproduce: format!("Affected URL: {}\nTool: {}\nPort: {}",
                f.affected_url,
                f.source_tool,
                f.affected_port.map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string())),
            proof_of_concept: f.evidence.clone(),
            remediation: f.remediation.clone(),
            references: f.cve_references.iter()
                .map(|c| format!("https://nvd.nist.gov/vuln/detail/{}", c))
                .collect(),
            status: "Open".to_string(),
            tags: vec!["rufus".to_string(), f.source_tool.clone()],
            evidence_paths: vec![],
        })
        .collect();

    let count = vulns.len();
    let ptsync = PtsyncFile {
        format: "ptsync-v1".to_string(),
        exported_at: chrono::Utc::now().to_rfc3339(),
        exported_by: if operator_name.is_empty() { "Rufus Framework".to_string() } else { operator_name },
        vulnerabilities: vulns,
    };

    let json = serde_json::to_string_pretty(&ptsync).map_err(|e| e.to_string())?;
    std::fs::write(&output_path, &json).map_err(|e| e.to_string())?;

    Ok(format!("Exported {} findings to {}", count, output_path))
}

#[tauri::command]
pub async fn get_ptsync_preview(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<serde_json::Value, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let findings = store.get_findings_for_scan(&scan_id).map_err(|e| e.to_string())?;

    let in_scope: Vec<_> = findings.iter().filter(|f| f.in_scope).collect();
    let by_sev = |s: &str| in_scope.iter().filter(|f| f.severity.to_uppercase() == s).count();

    Ok(serde_json::json!({
        "total": in_scope.len(),
        "critical": by_sev("CRITICAL"),
        "high": by_sev("HIGH"),
        "medium": by_sev("MEDIUM"),
        "low": by_sev("LOW"),
        "info": by_sev("INFO"),
        "out_of_scope": findings.len() - in_scope.len(),
    }))
}
