// src-tauri/src/commands/comparison.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::{self, models::*};

#[tauri::command]
pub async fn compare_scans(
    state: State<'_, Mutex<AppState>>,
    scan_a_id: String,
    scan_b_id: String,
) -> Result<ScanComparison, String> {
    let pool = { state.lock().unwrap().db.clone() };

    let scan_a = db::scans::get(&pool, &scan_a_id).await
        .map_err(|e| e.to_string())?
        .ok_or("Scan A not found")?;
    let scan_b = db::scans::get(&pool, &scan_b_id).await
        .map_err(|e| e.to_string())?
        .ok_or("Scan B not found")?;

    let findings_a = db::findings::list_for_scan(&pool, &scan_a_id).await.map_err(|e| e.to_string())?;
    let findings_b = db::findings::list_for_scan(&pool, &scan_b_id).await.map_err(|e| e.to_string())?;

    let titles_a: std::collections::HashSet<String> = findings_a.iter().map(|f| f.title.clone()).collect();
    let titles_b: std::collections::HashSet<String> = findings_b.iter().map(|f| f.title.clone()).collect();

    // New in B, not in A
    let new_findings: Vec<VulnFinding> = findings_b.iter()
        .filter(|f| !titles_a.contains(&f.title))
        .cloned()
        .collect();

    // Resolved (in A, not in B)
    let resolved_finding_titles: Vec<String> = findings_a.iter()
        .filter(|f| !titles_b.contains(&f.title))
        .map(|f| f.title.clone())
        .collect();

    // Persistent (in both) — just use B's version as current
    let persistent_titles: Vec<String> = titles_a.intersection(&titles_b).cloned().collect();
    let mut persistent_findings: Vec<PersistentFinding> = persistent_titles.iter().map(|title| {
        let finding = findings_b.iter().find(|f| &f.title == title).cloned().unwrap();
        // In a real multi-scan setup you'd query all scans for this target
        let scan_count = 2i64;
        PersistentFinding {
            title: title.clone(),
            severity: finding.severity.clone(),
            scan_count,
            is_chronic: scan_count >= 3,
            first_seen: finding.timestamp.clone(),
            findings: vec![finding],
        }
    }).collect();

    // Sort persistent by severity
    persistent_findings.sort_by_key(|p| match p.severity.as_str() {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4,
    });

    Ok(ScanComparison {
        scan_a,
        scan_b,
        new_findings,
        resolved_finding_titles,
        persistent_findings,
    })
}

