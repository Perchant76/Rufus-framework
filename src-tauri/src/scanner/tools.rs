// src-tauri/src/scanner/tools.rs
use std::process::Command;
use crate::db::models::ToolStatus;

pub struct ToolDef {
    pub name: &'static str,
    pub install_cmd: &'static str,
    pub version_flag: &'static str,
}

pub const ALL_TOOLS: &[ToolDef] = &[
    ToolDef { name: "subfinder",   install_cmd: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", version_flag: "-version" },
    ToolDef { name: "feroxbuster", install_cmd: "cargo install feroxbuster",                                                   version_flag: "--version" },
    ToolDef { name: "katana",      install_cmd: "go install github.com/projectdiscovery/katana/cmd/katana@latest",             version_flag: "-version" },
    ToolDef { name: "nmap",        install_cmd: "apt install nmap / brew install nmap",                                        version_flag: "--version" },
    ToolDef { name: "nuclei",      install_cmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",          version_flag: "-version" },
    ToolDef { name: "testssl.sh",  install_cmd: "brew install testssl / apt install testssl.sh",                               version_flag: "--version" },
    ToolDef { name: "wapiti3",     install_cmd: "pip install wapiti3",                                                         version_flag: "--version" },
    ToolDef { name: "whatweb",     install_cmd: "apt install whatweb / gem install whatweb",                                   version_flag: "--version" },
];

pub fn check_tool(def: &ToolDef) -> ToolStatus {
    match Command::new(def.name).arg(def.version_flag).output() {
        Ok(output) => {
            let raw = String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr);
            ToolStatus {
                name: def.name.to_string(),
                available: true,
                version: extract_version(&raw),
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
    let re = regex::Regex::new(r"v?(\d+\.\d+[\.\d]*)").ok()?;
    re.captures(output)?.get(1).map(|m| m.as_str().to_string())
}

fn which_path(name: &str) -> Option<String> {
    Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
