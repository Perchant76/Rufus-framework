// src-tauri/src/commands/osint.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::models::OsintResult;

const DORK_TEMPLATES: &[(&str, &str)] = &[
    ("site:{target} filetype:pdf",              "PDF documents exposed"),
    ("site:{target} inurl:admin",               "Admin panel exposure"),
    ("site:{target} intitle:\"index of\"",      "Directory listing enabled"),
    ("inurl:{target} ext:env OR ext:config",    "Config/env files exposed"),
    ("\"@{target}\" password filetype:txt",     "Password files referencing domain"),
    ("site:{target} ext:sql OR ext:bak",        "Database/backup files exposed"),
    ("site:{target} inurl:login",               "Login pages discovered"),
    ("site:{target} inurl:api",                 "API endpoints exposed"),
    ("site:{target} inurl:swagger",             "Swagger/OpenAPI docs exposed"),
    ("site:{target} inurl:jenkins",             "Jenkins CI exposed"),
    ("site:{target} inurl:kibana",              "Kibana dashboard exposed"),
    ("site:{target} inurl:grafana",             "Grafana dashboard exposed"),
    ("site:{target} filetype:log",              "Log files exposed"),
    ("\"{target}\" \"api_key\" OR \"apikey\"",  "API keys in public sources"),
    ("\"{target}\" \"password\" site:github.com", "Credentials leaked on GitHub"),
    ("\"{target}\" \"secret\" site:github.com", "Secrets leaked on GitHub"),
    ("\"{target}\" \"BEGIN RSA PRIVATE KEY\"",  "Private keys exposed"),
    ("site:{target} filetype:yaml OR filetype:yml", "YAML config files exposed"),
];

#[tauri::command]
pub async fn get_dork_templates(target: String) -> Result<Vec<(String, String)>, String> {
    Ok(DORK_TEMPLATES.iter().map(|(template, desc)| {
        (template.replace("{target}", &target), desc.to_string())
    }).collect())
}

#[tauri::command]
pub async fn open_dork_in_browser(query: String) -> Result<(), String> {
    let encoded = query.chars().fold(String::new(), |mut s, c| {
        match c {
            ' ' => s.push('+'),
            '"' => s.push_str("%22"),
            ':' => s.push_str("%3A"),
            '(' => s.push_str("%28"),
            ')' => s.push_str("%29"),
            '/' => s.push_str("%2F"),
            _ => s.push(c),
        }
        s
    });
    let url = format!("https://www.google.com/search?q={}", encoded);

    // Open in default browser
    #[cfg(target_os = "windows")]
    std::process::Command::new("cmd").args(["/c", "start", "", &url]).spawn().ok();
    #[cfg(target_os = "macos")]
    std::process::Command::new("open").arg(&url).spawn().ok();
    #[cfg(target_os = "linux")]
    std::process::Command::new("xdg-open").arg(&url).spawn().ok();

    Ok(())
}

#[tauri::command]
pub async fn list_osint_results(state: State<'_, Mutex<AppState>>) -> Result<Vec<OsintResult>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_osint_results().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_osint_result(state: State<'_, Mutex<AppState>>, result: OsintResult) -> Result<OsintResult, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.add_osint_result(result).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_osint_notes(state: State<'_, Mutex<AppState>>, id: String, notes: String) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.update_osint_notes(&id, notes).map_err(|e| e.to_string())
}
