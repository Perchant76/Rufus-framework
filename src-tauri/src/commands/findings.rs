// src-tauri/src/commands/findings.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::{self, models::VulnFinding};

#[tauri::command]
pub async fn get_findings(state: State<'_, Mutex<AppState>>) -> Result<Vec<VulnFinding>, String> {
    let pool = { state.lock().unwrap().db.clone() };
    db::findings::list_all(&pool).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_finding(
    state: State<'_, Mutex<AppState>>,
    finding_id: String,
) -> Result<Option<VulnFinding>, String> {
    let pool = { state.lock().unwrap().db.clone() };
    db::findings::get(&pool, &finding_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_findings_for_scan(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<Vec<VulnFinding>, String> {
    let pool = { state.lock().unwrap().db.clone() };
    db::findings::list_for_scan(&pool, &scan_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_finding(
    state: State<'_, Mutex<AppState>>,
    finding_id: String,
) -> Result<(), String> {
    let pool = { state.lock().unwrap().db.clone() };
    db::findings::delete(&pool, &finding_id).await.map_err(|e| e.to_string())
}
