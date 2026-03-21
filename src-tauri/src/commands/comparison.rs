// src-tauri/src/commands/comparison.rs
use std::sync::Mutex;
use std::collections::HashSet;
use tauri::State;
use crate::AppState;
use crate::db::models::*;

#[tauri::command]
pub async fn compare_scans(
    state: State<'_, Mutex<AppState>>,
    scan_a_id: String,
    scan_b_id: String,
) -> Result<ScanComparison, String> {
    let store = { state.lock().unwrap().store.clone_ref() };

    let scan_a = store.get_scan(&scan_a_id).map_err(|e| e.to_string())?
        .ok_or_else(|| "Scan A not found".to_string())?;
    let scan_b = store.get_scan(&scan_b_id).map_err(|e| e.to_string())?
        .ok_or_else(|| "Scan B not found".to_string())?;

    let findings_a = store.list_findings(&scan_a_id).map_err(|e| e.to_string())?;
    let findings_b = store.list_findings(&scan_b_id).map_err(|e| e.to_string())?;

    let titles_a: HashSet<String> = findings_a.iter().map(|f| f.title.clone()).collect();
    let titles_b: HashSet<String> = findings_b.iter().map(|f| f.title.clone()).collect();

    let new_findings: Vec<VulnFinding> = findings_b.iter()
        .filter(|f| !titles_a.contains(&f.title)).cloned().collect();

    let resolved_finding_titles: Vec<String> = findings_a.iter()
        .filter(|f| !titles_b.contains(&f.title)).map(|f| f.title.clone()).collect();

    let mut persistent_findings: Vec<PersistentFinding> = titles_a.intersection(&titles_b)
        .map(|title| {
            let finding = findings_b.iter().find(|f| &f.title == title).cloned().unwrap();
            PersistentFinding {
                title: title.clone(),
                severity: finding.severity.clone(),
                scan_count: 2,
                is_chronic: false,
                first_seen: finding.timestamp.clone(),
                findings: vec![finding],
            }
        })
        .collect();

    persistent_findings.sort_by_key(|p| match p.severity.as_str() {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4,
    });

    Ok(ScanComparison { scan_a, scan_b, new_findings, resolved_finding_titles, persistent_findings })
}
