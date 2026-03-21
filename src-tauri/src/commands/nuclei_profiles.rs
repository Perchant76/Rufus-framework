// src-tauri/src/commands/nuclei_profiles.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::models::NucleiProfile;

#[tauri::command]
pub async fn list_nuclei_profiles(state: State<'_, Mutex<AppState>>) -> Result<Vec<NucleiProfile>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_nuclei_profiles().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_nuclei_profile(state: State<'_, Mutex<AppState>>, profile: NucleiProfile) -> Result<NucleiProfile, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.save_nuclei_profile(profile).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_nuclei_profile(state: State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_nuclei_profile(&id).map_err(|e| e.to_string())
}
