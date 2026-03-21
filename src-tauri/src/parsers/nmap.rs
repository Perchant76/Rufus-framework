// src-tauri/src/parsers/nmap.rs
use crate::db::models::RawFinding;
use super::ToolParser;

pub struct NmapParser;

impl ToolParser for NmapParser {
    fn parse(&self, output: &str) -> Vec<RawFinding> {
        parse_ports(output)
            .into_iter()
            .filter(|p| p.state == "open")
            .flat_map(|p| findings_for_port(&p))
            .collect()
    }
}

struct NmapPort {
    port: u16,
    protocol: String,
    state: String,
    service: String,
    product: String,
    version: String,
    extra_info: String,
}

fn parse_ports(xml: &str) -> Vec<NmapPort> {
    let doc = match roxmltree::Document::parse(xml) {
        Ok(d) => d,
        Err(_) => return vec![],
    };

    doc.descendants()
        .filter(|n| n.has_tag_name("port"))
        .map(|port_node| {
            let portid = port_node.attribute("portid")
                .and_then(|p| p.parse().ok()).unwrap_or(0u16);
            let protocol = port_node.attribute("protocol").unwrap_or("tcp").to_string();
            let state = port_node.children()
                .find(|n| n.has_tag_name("state"))
                .and_then(|n| n.attribute("state"))
                .unwrap_or("unknown").to_string();
            let svc = port_node.children().find(|n| n.has_tag_name("service"));
            NmapPort {
                port: portid, protocol, state,
                service: svc.and_then(|n| n.attribute("name")).unwrap_or("unknown").to_string(),
                product: svc.and_then(|n| n.attribute("product")).unwrap_or("").to_string(),
                version: svc.and_then(|n| n.attribute("version")).unwrap_or("").to_string(),
                extra_info: svc.and_then(|n| n.attribute("extrainfo")).unwrap_or("").to_string(),
            }
        })
        .collect()
}

fn findings_for_port(port: &NmapPort) -> Vec<RawFinding> {
    let (severity, title, description, remediation) = classify_service(port);
    vec![RawFinding {
        source_tool: "nmap".to_string(),
        severity: severity.to_string(),
        title,
        description,
        affected_url: format!("{}:{}", port.service, port.port),
        affected_port: Some(port.port as i64),
        cve_references: cves_for_service(&port.service, &port.product, &port.version),
        cvss_score: None,
        evidence: format!("Port {}/{} open\nService: {}\nProduct: {} {}\nExtra: {}",
            port.port, port.protocol, port.service, port.product, port.version, port.extra_info),
        remediation,
        http_request: None,
        http_response: None,
    }]
}

fn classify_service(port: &NmapPort) -> (&'static str, String, String, String) {
    match port.service.as_str() {
        "ftp" => ("HIGH",
            format!("FTP on Port {}", port.port),
            "FTP transmits credentials in plaintext.".into(),
            "Replace with SFTP or FTPS. Disable anonymous access.".into()),
        "telnet" => ("CRITICAL",
            format!("Telnet on Port {}", port.port),
            "Telnet is completely unencrypted.".into(),
            "Disable immediately. Replace with SSH.".into()),
        "http" | "http-alt" => ("MEDIUM",
            format!("Unencrypted HTTP on Port {}", port.port),
            "Plain HTTP — traffic is not encrypted.".into(),
            "Redirect all HTTP to HTTPS. Enforce HSTS.".into()),
        "rdp" | "ms-wbt-server" => ("HIGH",
            format!("RDP Exposed on Port {}", port.port),
            "RDP is directly internet-accessible.".into(),
            "Place behind VPN. Enable NLA. Restrict to known IPs.".into()),
        "smb" | "microsoft-ds" => ("HIGH",
            format!("SMB on Port {}", port.port),
            "SMB exposed — ransomware and lateral movement vector.".into(),
            "Block at perimeter. Apply latest Windows patches.".into()),
        _ => ("INFO",
            format!("Open Port {}/{} — {}", port.port, port.protocol, port.service),
            format!("{} running {} {} on port {}", port.service, port.product, port.version, port.port),
            "Verify service is intentionally exposed. Apply patches.".into()),
    }
}

fn cves_for_service(service: &str, product: &str, version: &str) -> Vec<String> {
    let combined = format!("{} {} {}", service, product, version).to_lowercase();
    let mut cves = vec![];
    if combined.contains("jenkins") && combined.contains("2.441") {
        cves.push("CVE-2024-23897".to_string());
    }
    if combined.contains("apache") && combined.contains("2.4.49") {
        cves.push("CVE-2021-41773".to_string());
    }
    cves
}
