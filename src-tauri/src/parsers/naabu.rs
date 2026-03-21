// src-tauri/src/parsers/naabu.rs
// naabu -host target.com -json -silent
// Output: { "ip":"1.2.3.4", "port":443, "host":"example.com" }
use serde::Deserialize;
use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug, Deserialize)]
struct NaabuEntry {
    #[serde(default)] ip: String,
    port: u16,
    #[serde(default)] host: String,
}

pub struct NaabuParser;

impl ToolParser for NaabuParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        output.lines()
            .filter(|l| !l.is_empty() && l.starts_with('{'))
            .filter_map(|l| serde_json::from_str::<NaabuEntry>(l).ok())
            .map(|e| {
                let (severity, title, remediation) = classify_port(e.port);
                RawFinding {
                    source_tool: "naabu".to_string(),
                    severity: severity.to_string(),
                    title,
                    description: format!("Open port {}/tcp detected on {} ({})", e.port, e.host, e.ip),
                    affected_url: format!("{}:{}", if e.host.is_empty() { &e.ip } else { &e.host }, e.port),
                    affected_port: Some(e.port as i64),
                    cve_references: vec![],
                    cvss_score: None,
                    evidence: format!("naabu confirmed open: {}:{} (IP: {})", e.host, e.port, e.ip),
                    remediation,
                    http_request: None,
                    http_response: None,
                }
            })
            .collect()
    }
}

fn classify_port(port: u16) -> (&'static str, String, String) {
    match port {
        21   => ("HIGH",   "FTP (21) Open".into(), "Replace FTP with SFTP/FTPS. Disable anonymous access.".into()),
        22   => ("INFO",   "SSH (22) Open".into(), "Ensure key-based auth, disable root login, use fail2ban.".into()),
        23   => ("CRITICAL","Telnet (23) Open".into(), "Disable Telnet immediately — transmits plaintext. Replace with SSH.".into()),
        25   => ("MEDIUM", "SMTP (25) Open".into(), "Check for open relay. Enforce authentication on outbound mail.".into()),
        80   => ("INFO",   "HTTP (80) Open".into(), "Redirect all HTTP traffic to HTTPS.".into()),
        443  => ("INFO",   "HTTPS (443) Open".into(), "Standard HTTPS — check TLS configuration.".into()),
        445  => ("HIGH",   "SMB (445) Open".into(), "Block SMB at perimeter. Apply EternalBlue / PrintNightmare patches.".into()),
        1433 => ("HIGH",   "MSSQL (1433) Open".into(), "Restrict MSSQL to internal network. Never expose to internet.".into()),
        1521 => ("HIGH",   "Oracle DB (1521) Open".into(), "Restrict Oracle listener. Enforce strong authentication.".into()),
        2375 => ("CRITICAL","Docker API (2375) Open — Unauthenticated".into(), "Close immediately. Unauthenticated Docker API allows full host takeover.".into()),
        2376 => ("HIGH",   "Docker TLS API (2376) Open".into(), "Verify TLS certs are properly configured. Restrict to admin IPs.".into()),
        3000 => ("MEDIUM", "Dev Server (3000) Open".into(), "Verify this is not an exposed development server.".into()),
        3306 => ("HIGH",   "MySQL (3306) Open".into(), "Restrict MySQL to localhost or internal network. Never expose to internet.".into()),
        3389 => ("HIGH",   "RDP (3389) Open".into(), "Place behind VPN. Enable NLA. Restrict to known IPs.".into()),
        4444 => ("CRITICAL","Suspicious Port 4444 — Possible Backdoor".into(), "Port 4444 is commonly used by Metasploit. Investigate immediately.".into()),
        4848 => ("HIGH",   "GlassFish Admin (4848) Open".into(), "Restrict GlassFish admin console. Default credentials are common.".into()),
        5432 => ("HIGH",   "PostgreSQL (5432) Open".into(), "Restrict PostgreSQL to internal network. Enforce strong passwords.".into()),
        5900 => ("HIGH",   "VNC (5900) Open".into(), "Restrict VNC access. Many VNC implementations have weak/no auth.".into()),
        6379 => ("CRITICAL","Redis (6379) Open — Likely Unauthenticated".into(), "Redis with no auth allows data theft and RCE via config manipulation.".into()),
        7001 | 7002 => ("HIGH", format!("WebLogic ({})", port), "WebLogic often vulnerable to deserialization RCEs. Patch immediately.".into()),
        8080 | 8443 | 8888 => ("MEDIUM", format!("Alt Web Port ({}) Open", port), "Common dev/admin port. Check for exposed admin panels.".into()),
        8500 => ("HIGH",   "Consul (8500) Open — Unauthenticated API".into(), "Consul UI/API without auth allows cluster takeover.".into()),
        9200 | 9300 => ("CRITICAL", format!("Elasticsearch ({}) Open", port), "Unauthenticated Elasticsearch exposes all data. Restrict to internal network.".into()),
        27017 => ("HIGH",  "MongoDB (27017) Open".into(), "Many MongoDB instances have no auth by default. Restrict to localhost.".into()),
        _    => ("INFO",   format!("Open Port {}/tcp", port), "Verify this port is intentionally exposed and apply access controls.".into()),
    }
}
