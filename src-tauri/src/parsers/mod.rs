// src-tauri/src/parsers/mod.rs
pub mod subfinder;
pub mod feroxbuster;
pub mod katana;
pub mod nmap;
pub mod nuclei;
pub mod testssl;
pub mod whatweb;
pub mod wapiti;
// New tools
pub mod httpx;
pub mod naabu;
pub mod dnsx;
pub mod gau;
pub mod sqlmap;
pub mod nikto;
pub mod ffuf;
pub mod amass;

use crate::db::models::RawFinding;

pub trait ToolParser {
    fn parse(&self, output: &str) -> Vec<RawFinding>;
}
