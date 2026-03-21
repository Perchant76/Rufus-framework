// src-tauri/src/commands/programs.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::models::BugBountyProgram;

#[tauri::command]
pub async fn create_program(state: State<'_, Mutex<AppState>>, program: BugBountyProgram) -> Result<BugBountyProgram, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.create_program(program).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_programs(state: State<'_, Mutex<AppState>>) -> Result<Vec<BugBountyProgram>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_programs().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_program(state: State<'_, Mutex<AppState>>, program: BugBountyProgram) -> Result<BugBountyProgram, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.update_program(program).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_program(state: State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_program(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn link_scan_to_program(state: State<'_, Mutex<AppState>>, program_id: String, scan_id: String) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.link_scan_to_program(&program_id, &scan_id).map_err(|e| e.to_string())
}
