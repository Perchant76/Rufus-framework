// src-tauri/src/commands/phase_control.rs
// Granular phase control: pause, resume, skip phase, re-run single phase
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};
use crate::AppState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PhaseState {
    Pending,
    Running,
    Complete,
    Skipped,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseStatus {
    pub phase_id: u8,
    pub name: String,
    pub tools: Vec<String>,
    pub state: PhaseState,
    pub findings_count: usize,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub duration_secs: Option<f64>,
}

// Stored in AppState — global scan phase tracker
pub struct PhaseTracker {
    pub scan_id: String,
    pub phases: Vec<PhaseStatus>,
    pub paused: bool,
    pub skip_to_phase: Option<u8>,
}

impl PhaseTracker {
    pub fn new(scan_id: &str) -> Self {
        PhaseTracker {
            scan_id: scan_id.to_string(),
            paused: false,
            skip_to_phase: None,
            phases: vec![
                PhaseStatus { phase_id:1, name:"Subdomain Enumeration".into(),   tools:vec!["subfinder".into(),"amass".into()],        state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
                PhaseStatus { phase_id:2, name:"DNS & Live Host Detection".into(), tools:vec!["dnsx".into(),"httpx".into()],             state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
                PhaseStatus { phase_id:3, name:"URL Discovery".into(),            tools:vec!["gau".into(),"katana".into()],             state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
                PhaseStatus { phase_id:4, name:"Content Discovery".into(),        tools:vec!["feroxbuster".into(),"ffuf".into()],        state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
                PhaseStatus { phase_id:5, name:"Port Scanning".into(),            tools:vec!["naabu".into(),"nmap".into()],             state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
                PhaseStatus { phase_id:6, name:"Vulnerability Scanning".into(),   tools:vec!["nuclei".into(),"nikto".into(),"sqlmap".into(),"wapiti3".into()], state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
                PhaseStatus { phase_id:7, name:"TLS & Tech Fingerprinting".into(),tools:vec!["testssl.sh".into(),"whatweb".into()],     state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
                PhaseStatus { phase_id:8, name:"JS Secret Scanning".into(),      tools:vec!["js-secrets".into()],                       state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
                PhaseStatus { phase_id:9, name:"Header & CORS Analysis".into(),  tools:vec!["headers".into()],                          state:PhaseState::Pending, findings_count:0, started_at:None, completed_at:None, duration_secs:None },
            ],
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PhaseControlState {
    pub phases: Vec<PhaseStatus>,
    pub paused: bool,
    pub scan_id: String,
}

// --- Tauri commands ---

#[tauri::command]
pub async fn get_phase_status(
    state: State<'_, Mutex<AppState>>,
) -> Result<PhaseControlState, String> {
    let s = state.lock().unwrap();
    if let Some(ref pt) = s.phase_tracker {
        Ok(PhaseControlState {
            phases: pt.phases.clone(),
            paused: pt.paused,
            scan_id: pt.scan_id.clone(),
        })
    } else {
        Err("No active scan".to_string())
    }
}

#[tauri::command]
pub async fn pause_scan(
    app_handle: AppHandle,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let mut s = state.lock().unwrap();
    if let Some(ref mut pt) = s.phase_tracker {
        pt.paused = true;
        let _ = app_handle.emit("scan_progress", serde_json::json!({
            "scan_id": pt.scan_id, "tool": "system",
            "percent": -1.0,
            "message": "Scan paused by operator — waiting to resume",
            "level": "warn"
        }));
    }
    Ok(())
}

#[tauri::command]
pub async fn resume_scan(
    app_handle: AppHandle,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let mut s = state.lock().unwrap();
    if let Some(ref mut pt) = s.phase_tracker {
        pt.paused = false;
        let _ = app_handle.emit("scan_progress", serde_json::json!({
            "scan_id": pt.scan_id, "tool": "system",
            "percent": -1.0,
            "message": "Scan resumed",
            "level": "info"
        }));
    }
    Ok(())
}

#[tauri::command]
pub async fn skip_phase(
    app_handle: AppHandle,
    state: State<'_, Mutex<AppState>>,
    phase_id: u8,
) -> Result<(), String> {
    let mut s = state.lock().unwrap();
    if let Some(ref mut pt) = s.phase_tracker {
        if let Some(phase) = pt.phases.iter_mut().find(|p| p.phase_id == phase_id) {
            phase.state = PhaseState::Skipped;
        }
        let _ = app_handle.emit("phase_update", serde_json::json!({
            "scan_id": pt.scan_id,
            "phase_id": phase_id,
            "state": "Skipped"
        }));
    }
    Ok(())
}

#[tauri::command]
pub async fn get_all_phase_statuses(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<PhaseStatus>, String> {
    let s = state.lock().unwrap();
    Ok(s.phase_tracker.as_ref().map(|pt| pt.phases.clone()).unwrap_or_default())
}
