// src-tauri/src/commands/triage.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::models::VulnFinding;

#[tauri::command]
pub async fn update_finding_triage(
    state: State<'_, Mutex<AppState>>,
    finding: VulnFinding,
) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.update_finding(&finding).map_err(|e| e.to_string())
}
