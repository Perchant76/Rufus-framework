// src-tauri/src/commands/session.rs
// Session persistence — save/restore scan progress incrementally
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub scan_id: String,
    pub target: String,
    pub current_phase: u8,
    pub completed_phases: Vec<u8>,
    pub phase_results: std::collections::HashMap<String, String>, // phase -> raw output blob key
    pub saved_at: String,
    pub config_snapshot: serde_json::Value,
}

#[tauri::command]
pub async fn save_scan_session(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    current_phase: u8,
    completed_phases: Vec<u8>,
) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let session = ScanSession {
        scan_id: scan_id.clone(),
        target: String::new(),
        current_phase,
        completed_phases,
        phase_results: std::collections::HashMap::new(),
        saved_at: chrono::Utc::now().to_rfc3339(),
        config_snapshot: serde_json::Value::Null,
    };
    store.save_session(&scan_id, &serde_json::to_string(&session).unwrap_or_default())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn load_scan_session(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<Option<ScanSession>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let raw = store.load_session(&scan_id).map_err(|e| e.to_string())?;
    match raw {
        Some(s) => Ok(serde_json::from_str(&s).ok()),
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn list_interrupted_scans(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<ScanSession>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let sessions = store.list_sessions().map_err(|e| e.to_string())?;
    Ok(sessions.iter().filter_map(|s| serde_json::from_str(s).ok()).collect())
}

#[tauri::command]
pub async fn clear_scan_session(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_session(&scan_id).map_err(|e| e.to_string())
}
