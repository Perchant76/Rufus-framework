// src-tauri/src/lib.rs
use std::sync::Mutex;
use tauri::Manager;

pub mod commands;
pub mod db;
pub mod parsers;
pub mod scanner;

pub use db::models::*;

/// Global application state shared across Tauri commands
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub active_scan_id: Option<String>,
    pub scan_running: bool,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Initialize tracing
            tracing_subscriber::fmt::init();

            // Set up SQLite database (async block inside sync setup)
            let app_handle = app.handle().clone();
            let db_path = app_handle
                .path()
                .app_data_dir()
                .expect("Failed to get app data dir")
                .join("probescan.db");

            let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

            let pool = tauri::async_runtime::block_on(async {
                db::init_pool(&db_url).await.expect("Failed to init DB")
            });

            tauri::async_runtime::block_on(async {
                db::migrations::run(&pool).await.expect("Failed to run migrations");
            });

            app.manage(Mutex::new(AppState {
                db: pool,
                active_scan_id: None,
                scan_running: false,
            }));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Scan management
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
