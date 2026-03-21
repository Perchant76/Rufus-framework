// src-tauri/src/parsers/ffuf.rs
// ffuf: go install github.com/ffuf/ffuf/v2@latest
// Invocation: ffuf -u https://target.com/FUZZ -w wordlist.txt -o /tmp/ffuf.json -of json -mc 200,301,302,403
// Output: JSON with results array
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct FfufOutput {
    results: Vec<FfufResult>,
}

#[derive(Debug, Deserialize)]
struct FfufResult {
    input: FfufInput,
    #[serde(default)] url: String,
    #[serde(default)] status: u16,
    #[serde(default)] length: u64,
    #[serde(default)] words: u64,
    #[serde(default)] lines: u64,
    #[serde(rename = "content-type", default)] content_type: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct FfufInput {
    #[serde(rename = "FUZZ", default)] fuzz: Option<String>,
}

pub struct FfufParser;

impl ToolParser for FfufParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        let ffuf: FfufOutput = match serde_json::from_str(output) {
            Ok(f) => f,
            Err(_) => return vec![],
        };

        ffuf.results.iter().filter_map(|r| classify_result(r)).collect()
    }
}

fn classify_result(r: &FfufResult) -> Option<RawFinding> {
    let url_lower = r.url.to_lowercase();
    let fuzz = r.input.fuzz.as_deref().unwrap_or("");

    let (severity, title, remediation) = if is_backup(fuzz) && r.status == 200 {
        ("CRITICAL",
         format!("Backup/Config File Exposed: {}", r.url),
         "Remove backup and configuration files from the web root immediately.")
    } else if is_sensitive(fuzz) && r.status == 200 {
        ("HIGH",
         format!("Sensitive Path Exposed ({}): {}", r.status, r.url),
         "Restrict access to this path via authentication or remove it.")
    } else if r.status == 200 {
        ("INFO",
         format!("Directory/File Found (200): {}", r.url),
         "")
    } else if r.status == 403 {
        ("LOW",
         format!("Forbidden Resource (403): {}", r.url),
         "Verify access controls are correctly configured.")
    } else if r.status == 301 || r.status == 302 {
        ("INFO",
         format!("Redirect ({}) Found: {}", r.status, r.url),
         "")
    } else {
        return None;
    };

    if title.is_empty() { return None; }

    Some(RawFinding {
        source_tool: "ffuf".to_string(),
        severity: severity.to_string(),
        title,
        description: format!("ffuf discovered '{}' at {} (HTTP {})", fuzz, r.url, r.status),
        affected_url: r.url.clone(),
        affected_port: None,
        cve_references: vec![],
        cvss_score: None,
        evidence: format!("FUZZ: {}\nURL: {}\nStatus: {}\nLength: {}\nWords: {}\nLines: {}\nContent-Type: {}",
            fuzz, r.url, r.status, r.length, r.words, r.lines,
            r.content_type.as_deref().unwrap_or("")),
        remediation: remediation.to_string(),
        http_request: Some(format!("GET {} HTTP/1.1", r.url)),
        http_response: Some(format!("HTTP/1.1 {}", r.status)),
    })
}

fn is_backup(path: &str) -> bool {
    const EXT: &[&str] = &[".bak",".backup",".old",".sql",".dump",".tar.gz",".zip","~",".swp",".orig",".env",".config"];
    EXT.iter().any(|e| path.ends_with(e))
}

fn is_sensitive(path: &str) -> bool {
    const PATHS: &[&str] = &["admin","administrator","wp-admin","phpmyadmin",".git","actuator","swagger","console","dashboard","debug","panel","jenkins","kibana","grafana"];
    let p = path.to_lowercase();
    PATHS.iter().any(|s| p.contains(s))
}
