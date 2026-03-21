// src-tauri/src/db/mod.rs
// Flat-file JSON storage — no database engine required.
// Data is stored in the app data directory:
//   scans/
//     <scan_id>.json          — Scan metadata
//     <scan_id>.findings.json — Vec<VulnFinding>
//     <scan_id>.assets.json   — Vec<DiscoveredAsset>

pub mod models;
pub mod store;

pub use store::Store;
