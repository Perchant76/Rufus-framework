// src-tauri/src/parsers/nmap.rs
//
// nmap invoked with: nmap -sV -O -oX - target
// Output is XML which we parse with roxmltree

use crate::db::models::RawFinding;
use super::ToolParser;

#[derive(Debug)]
pub struct NmapPort {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub product: String,
    pub version: String,
    pub extra_info: String,
    pub os_guess: Option<String>,
}

pub struct NmapParser;

impl ToolParser for NmapParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        let ports = parse_ports(output);
        ports
            .iter()
            .filter(|p| p.state == "open")
            .flat_map(|p| findings_for_port(p))
            .collect()
    }
}

pub fn parse_ports(xml: &str) -> Vec<NmapPort> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(_) => return vec![],
    };

    let mut ports = vec![];
    let mut os_guess: Option<String> = None;

    // Extract OS guess
    if let Some(os_node) = doc.descendants().find(|n| n.has_tag_name("osmatch")) {
        os_guess = os_node.attribute("name").map(str::to_string);
    }

    for port_node in doc.descendants().filter(|n| n.has_tag_name("port")) {
        let portid: u16 = port_node
            .attribute("portid")
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let protocol = port_node.attribute("protocol").unwrap_or("tcp").to_string();

        let state = port_node
            .children()
            .find(|n| n.has_tag_name("state"))
            .and_then(|n| n.attribute("state"))
            .unwrap_or("unknown")
            .to_string();

        let service_node = port_node.children().find(|n| n.has_tag_name("service"));
        let service = service_node.and_then(|n| n.attribute("name")).unwrap_or("unknown").to_string();
        let product = service_node.and_then(|n| n.attribute("product")).unwrap_or("").to_string();
        let version = service_node.and_then(|n| n.attribute("version")).unwrap_or("").to_string();
        let extra_info = service_node.and_then(|n| n.attribute("extrainfo")).unwrap_or("").to_string();

        ports.push(NmapPort {
            port: portid,
            protocol,
            state,
            service,
            product,
            version,
            extra_info,
            os_guess: os_guess.clone(),
        });
    }

    ports
}

fn findings_for_port(port: &NmapPort) -> Vec<RawFinding> {
    let mut findings = vec![];

    // Base finding: open port
    let (severity, title, desc, remediation) = classify_service(port);

    findings.push(RawFinding {
        source_tool: "nmap".to_string(),
        severity: severity.to_string(),
        title,
        description: desc,
        affected_url: format!("{}://target:{}", port.service, port.port),
        affected_port: Some(port.port as i64),
        cve_references: cves_for_service(&port.service, &port.product, &port.version),
        cvss_score: None,
        evidence: format!(
            "Port {}/{} open\nService: {}\nProduct: {} {}\nExtra: {}",
            port.port, port.protocol, port.service, port.product, port.version, port.extra_info
        ),
        remediation,
        http_request: None,
        http_response: None,
    });

    findings
}

fn classify_service(port: &NmapPort) -> (&'static str, String, String, String) {
    match port.service.as_str() {
        "ssh" => (
            "INFO",
            format!("SSH Service on Port {}", port.port),
            "SSH service detected. Ensure key-based auth is enforced.".into(),
            "Disable password authentication. Use Ed25519 keys. Restrict to known IPs.".into(),
        ),
        "http" | "http-alt" => (
            "MEDIUM",
            format!("Unencrypted HTTP on Port {}", port.port),
            "Plain HTTP service detected — traffic is not encrypted.".into(),
            "Redirect all HTTP traffic to HTTPS. Enforce HSTS.".into(),
        ),
        "ftp" => (
            "HIGH",
            format!("FTP Service on Port {}", port.port),
            "FTP transmits credentials in plaintext.".into(),
            "Replace FTP with SFTP or FTPS. Disable anonymous access.".into(),
        ),
        "telnet" => (
            "CRITICAL",
            format!("Telnet on Port {}", port.port),
            "Telnet is completely unencrypted and must not be exposed.".into(),
            "Disable Telnet immediately. Replace with SSH.".into(),
        ),
        "smb" | "microsoft-ds" | "netbios-ssn" => (
            "HIGH",
            format!("SMB/NetBIOS on Port {}", port.port),
            "SMB exposed — common ransomware and lateral movement vector.".into(),
            "Block SMB at perimeter firewall. Apply latest Windows patches (EternalBlue, PrintNightmare).".into(),
        ),
        "rdp" | "ms-wbt-server" => (
            "HIGH",
            format!("RDP Exposed on Port {}", port.port),
            "Remote Desktop Protocol is directly internet-accessible.".into(),
            "Place RDP behind VPN. Enable NLA. Restrict to known IPs.".into(),
        ),
        _ => (
            "INFO",
            format!("Open Port {}/{} - {}", port.port, port.protocol, port.service),
            format!("Open port detected: {} running {} {} {}", port.port, port.service, port.product, port.version),
            "Verify this service is intentionally exposed. Apply patches and restrict access.".into(),
        ),
    }
}

fn cves_for_service(service: &str, product: &str, version: &str) -> Vec<String> {
    // Known CVEs for common service/version combos
    let combined = format!("{} {} {}", service, product, version).to_lowercase();
    let mut cves = vec![];

    if combined.contains("jenkins") && combined.contains("2.441") {
        cves.push("CVE-2024-23897".to_string());
    }
    if combined.contains("openssh") && combined.contains("7.") {
        cves.push("CVE-2023-38408".to_string());
    }
    if combined.contains("apache") && combined.contains("2.4.49") {
        cves.push("CVE-2021-41773".to_string());
    }
    if combined.contains("log4j") || combined.contains("log4shell") {
        cves.push("CVE-2021-44228".to_string());
    }

    cves
}
