// src-tauri/src/commands/wordlists.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::models::Wordlist;

// Built-in wordlists bundled at compile time
const BUILTIN_DIRS: &str = include_str!("../../wordlists/directories.txt");
const BUILTIN_SUBS: &str = include_str!("../../wordlists/subdomains.txt");
const BUILTIN_PARAMS: &str = include_str!("../../wordlists/parameters.txt");

#[tauri::command]
pub async fn list_wordlists(state: State<'_, Mutex<AppState>>) -> Result<Vec<Wordlist>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let mut lists = store.list_wordlists().unwrap_or_default();
    // Always prepend built-ins if not already present
    let builtins = builtin_wordlists();
    for b in builtins {
        if !lists.iter().any(|w| w.id == b.id) {
            lists.insert(0, b);
        }
    }
    Ok(lists)
}

#[tauri::command]
pub async fn import_wordlist(state: State<'_, Mutex<AppState>>, name: String, tag: String, content: String) -> Result<Wordlist, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.import_wordlist(name, tag, content).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_wordlist(state: State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    // Don't delete builtins
    if id.starts_with("builtin_") { return Ok(()); }
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_wordlist(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_wordlist_content(state: State<'_, Mutex<AppState>>, id: String) -> Result<Vec<String>, String> {
    if id == "builtin_dirs"   { return Ok(BUILTIN_DIRS.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect()); }
    if id == "builtin_subs"   { return Ok(BUILTIN_SUBS.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect()); }
    if id == "builtin_params" { return Ok(BUILTIN_PARAMS.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect()); }
    let store = { state.lock().unwrap().store.clone_ref() };
    store.get_wordlist_content(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_wordlist_path(state: State<'_, Mutex<AppState>>, id: String) -> Result<String, String> {
    if id.starts_with("builtin_") {
        return Err("Built-in wordlists are embedded — write to a temp file first.".into());
    }
    let store = { state.lock().unwrap().store.clone_ref() };
    Ok(store.wordlist_file_path(&id).to_string_lossy().to_string())
}

fn builtin_wordlists() -> Vec<Wordlist> {
    vec![
        Wordlist { id: "builtin_dirs".into(), name: "Built-in Directories (500)".into(), tag: "directories".into(), word_count: BUILTIN_DIRS.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).count(), source: "builtin".into(), created_at: "2024-01-01T00:00:00Z".into() },
        Wordlist { id: "builtin_subs".into(), name: "Built-in Subdomains (200)".into(), tag: "subdomains".into(), word_count: BUILTIN_SUBS.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).count(), source: "builtin".into(), created_at: "2024-01-01T00:00:00Z".into() },
        Wordlist { id: "builtin_params".into(), name: "Built-in Parameters (100)".into(), tag: "parameters".into(), word_count: BUILTIN_PARAMS.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).count(), source: "builtin".into(), created_at: "2024-01-01T00:00:00Z".into() },
    ]
}
