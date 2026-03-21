// src-tauri/src/scanner/tools.rs
use std::process::Command;
use crate::db::models::ToolStatus;

pub struct ToolDef {
    pub name: &'static str,
    pub category: &'static str,
    pub install_cmd: &'static str,
    pub version_flag: &'static str,
}

pub const ALL_TOOLS: &[ToolDef] = &[
    ToolDef { name: "subfinder",     category: "Subdomain Enum",    install_cmd: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", version_flag: "-version" },
    ToolDef { name: "feroxbuster",   category: "Dir Brute-force",   install_cmd: "cargo install feroxbuster", version_flag: "--version" },
    ToolDef { name: "katana",        category: "Web Crawler",       install_cmd: "go install github.com/projectdiscovery/katana/cmd/katana@latest", version_flag: "-version" },
    ToolDef { name: "nmap",          category: "Port Scanner",      install_cmd: "apt install nmap / brew install nmap", version_flag: "--version" },
    ToolDef { name: "nuclei",        category: "Vuln Scanner",      install_cmd: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", version_flag: "-version" },
    ToolDef { name: "testssl.sh",    category: "TLS Analyzer",      install_cmd: "brew install testssl / apt install testssl.sh", version_flag: "--version" },
    ToolDef { name: "wapiti3",       category: "Web Vuln Scanner",  install_cmd: "pip install wapiti3", version_flag: "--version" },
    ToolDef { name: "whatweb",       category: "Tech Fingerprint",  install_cmd: "apt install whatweb / gem install whatweb", version_flag: "--version" },
];

pub fn check_tool(def: &ToolDef) -> ToolStatus {
    let result = Command::new(def.name)
        .arg(def.version_flag)
        .output();

    match result {
        Ok(output) => {
            let raw = String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr);
            let version = extract_version(&raw);
            ToolStatus {
                name: def.name.to_string(),
                available: true,
                version,
                path: which_path(def.name),
                install_cmd: def.install_cmd.to_string(),
            }
        }
        Err(_) => ToolStatus {
            name: def.name.to_string(),
            available: false,
            version: None,
            path: None,
            install_cmd: def.install_cmd.to_string(),
        },
    }
}

pub fn check_all() -> Vec<ToolStatus> {
    ALL_TOOLS.iter().map(check_tool).collect()
}

fn extract_version(output: &str) -> Option<String> {
    // Look for patterns like "1.2.3" or "v1.2.3"
    let re = regex::Regex::new(r"v?(\d+\.\d+[\.\d]*)").ok()?;
    re.captures(output)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn which_path(name: &str) -> Option<String> {
    Command::new("which")
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
