// src-tauri/src/lib.rs
use std::sync::Mutex;
use tauri::Manager;

pub mod commands;
pub mod db;
pub mod parsers;
pub mod scanner;

pub use db::models::*;

pub struct AppState {
    pub store: db::Store,
    pub active_scan_id: Option<String>,
    pub scan_running: bool,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            tracing_subscriber::fmt::init();
            let data_dir = app.handle()
                .path()
                .app_data_dir()
                .expect("Failed to resolve app data dir")
                .join("scans");
            let store = db::Store::new(data_dir).expect("Failed to create data directory");
            app.manage(Mutex::new(AppState { store, active_scan_id: None, scan_running: false }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Scans
            commands::scan::create_scan,
            commands::scan::get_scans,
            commands::scan::get_scan,
            commands::scan::delete_scan,
            commands::scan::start_scan,
            commands::scan::stop_scan,
            // Findings
            commands::findings::get_findings,
            commands::findings::get_finding,
            commands::findings::get_findings_for_scan,
            commands::findings::delete_finding,
            // Tools
            commands::tools::check_tool_availability,
            commands::tools::check_all_tools,
            // Comparison
            commands::comparison::compare_scans,
            // Export
            commands::export::export_pdf,
            commands::export::export_csv,
            commands::export::export_burp,
            commands::export::export_caido,
            // Programs
            commands::programs::create_program,
            commands::programs::list_programs,
            commands::programs::update_program,
            commands::programs::delete_program,
            commands::programs::link_scan_to_program,
            // Workflows
            commands::workflows::create_workflow,
            commands::workflows::list_workflows,
            commands::workflows::update_workflow,
            commands::workflows::delete_workflow,
            // Wordlists
            commands::wordlists::list_wordlists,
            commands::wordlists::import_wordlist,
            commands::wordlists::delete_wordlist,
            commands::wordlists::get_wordlist_content,
            commands::wordlists::get_wordlist_path,
            // Nuclei Profiles
            commands::nuclei_profiles::list_nuclei_profiles,
            commands::nuclei_profiles::save_nuclei_profile,
            commands::nuclei_profiles::delete_nuclei_profile,
            // HTTP Replay
            commands::replay::send_http_request,
            commands::replay::list_saved_requests,
            commands::replay::save_request,
            commands::replay::delete_saved_request,
            // OSINT
            commands::osint::get_dork_templates,
            commands::osint::open_dork_in_browser,
            commands::osint::list_osint_results,
            commands::osint::add_osint_result,
            commands::osint::update_osint_notes,
            // Cloud / Takeover
            commands::cloud::enumerate_cloud_assets,
            commands::cloud::list_cloud_assets,
            commands::cloud::check_takeover,
            // Triage
            commands::triage::update_finding_triage,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
