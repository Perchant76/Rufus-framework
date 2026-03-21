// src-tauri/src/commands/findings.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::models::VulnFinding;

#[tauri::command]
pub async fn get_findings(state: State<'_, Mutex<AppState>>) -> Result<Vec<VulnFinding>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_all_findings().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_finding(
    state: State<'_, Mutex<AppState>>,
    finding_id: String,
) -> Result<Option<VulnFinding>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let all = store.list_all_findings().map_err(|e| e.to_string())?;
    Ok(all.into_iter().find(|f| f.id == finding_id))
}

#[tauri::command]
pub async fn get_findings_for_scan(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<Vec<VulnFinding>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_findings(&scan_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_finding(
    state: State<'_, Mutex<AppState>>,
    finding_id: String,
) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_finding(&finding_id).map_err(|e| e.to_string())
}
