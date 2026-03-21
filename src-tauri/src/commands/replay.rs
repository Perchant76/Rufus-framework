// src-tauri/src/commands/replay.rs
use std::sync::Mutex;
use std::time::Instant;
use tauri::State;
use crate::AppState;
use crate::db::models::{SavedRequest, HttpResponse};

#[tauri::command]
pub async fn send_http_request(
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    follow_redirects: bool,
    timeout_secs: u64,
) -> Result<HttpResponse, String> {
    let start = Instant::now();
    let timeout_str = timeout_secs.to_string();

    let mut cmd_args: Vec<String> = vec![
        "-s".into(), "-i".into(),
        "-X".into(), method.clone(),
        "--max-time".into(), timeout_str,
    ];

    if follow_redirects {
        cmd_args.push("-L".into());
        cmd_args.push("--max-redirs".into());
        cmd_args.push("10".into());
    }

    for (k, v) in &headers {
        cmd_args.push("-H".into());
        cmd_args.push(format!("{}: {}", k, v));
    }

    if let Some(ref b) = body {
        cmd_args.push("-d".into());
        cmd_args.push(b.clone());
    }

    cmd_args.push(url.clone());

    let output = tokio::process::Command::new("curl")
        .args(&cmd_args)
        .output()
        .await
        .map_err(|e| format!("Failed to run curl: {}. Install curl and ensure it is on PATH.", e))?;

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let duration_ms = start.elapsed().as_millis() as u64;
    parse_curl_response(raw, duration_ms)
}

fn parse_curl_response(raw: String, duration_ms: u64) -> Result<HttpResponse, String> {
    let (header_section, body) = if let Some(pos) = raw.find("\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = raw.find("\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (raw.as_str(), "")
    };

    let mut lines = header_section.lines();
    let status_line = lines.next().unwrap_or("HTTP/1.1 200 OK");
    let (status, status_text) = parse_status_line(status_line);

    let resp_headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            let mut parts = l.splitn(2, ':');
            let k = parts.next()?.trim().to_string();
            let v = parts.next()?.trim().to_string();
            Some((k, v))
        })
        .collect();

    Ok(HttpResponse {
        status,
        status_text,
        headers: resp_headers,
        body: body.to_string(),
        duration_ms,
        redirect_chain: vec![],
    })
}

fn parse_status_line(line: &str) -> (u16, String) {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(200);
    let text = parts.get(2).map(str::to_string).unwrap_or_else(|| "OK".to_string());
    (status, text)
}

#[tauri::command]
pub async fn list_saved_requests(state: State<'_, Mutex<AppState>>) -> Result<Vec<SavedRequest>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_saved_requests().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_request(state: State<'_, Mutex<AppState>>, request: SavedRequest) -> Result<SavedRequest, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.save_request(request).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_saved_request(state: State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.delete_saved_request(&id).map_err(|e| e.to_string())
}
