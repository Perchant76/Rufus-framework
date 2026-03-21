// src-tauri/src/parsers/mod.rs
pub mod subfinder;
pub mod feroxbuster;
pub mod katana;
pub mod nmap;
pub mod nuclei;
pub mod testssl;
pub mod whatweb;
pub mod wapiti;

use crate::db::models::RawFinding;

/// Shared trait all parsers implement
pub trait ToolParser {
    fn parse(&self, output: &str) -> Vec<RawFinding>;
}
