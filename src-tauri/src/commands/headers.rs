// src-tauri/src/commands/headers.rs
// CORS misconfiguration + Security header analyser
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};
use crate::AppState;
use crate::db::models::RawFinding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderFinding {
    pub url: String,
    pub check_name: String,
    pub severity: String,
    pub detail: String,
    pub remediation: String,
    pub header_value: Option<String>,
}

pub async fn check_headers_for_url(url: &str) -> Vec<HeaderFinding> {
    let mut findings = Vec::new();

    // Fetch headers via curl
    let stdout_bytes: Vec<u8> = match tokio::process::Command::new("curl")
        .args(["-sSIL", "--max-time", "10", "-A",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
               url])
        .output().await
    {
        Ok(out) => out.stdout,
        Err(_)  => return findings,
    };

    if stdout_bytes.is_empty() { return findings; }
    let raw = String::from_utf8_lossy(&stdout_bytes).to_lowercase();
    let raw_orig = String::from_utf8_lossy(&stdout_bytes).to_string();

    let get_header = |name: &str| -> Option<String> {
        for line in raw_orig.lines() {
            let ll = line.to_lowercase();
            if ll.starts_with(&format!("{}:", name.to_lowercase())) {
                return Some(line[name.len()+1..].trim().to_string());
            }
        }
        None
    };

    // ── Security headers ─────────────────────────────────────────────────────
    if get_header("Strict-Transport-Security").is_none() {
        findings.push(HeaderFinding {
            url: url.to_string(),
            check_name: "Missing HSTS".to_string(),
            severity: "MEDIUM".to_string(),
            detail: "Strict-Transport-Security header is absent, leaving users vulnerable to SSL stripping attacks.".to_string(),
            remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".to_string(),
            header_value: None,
        });
    }

    if get_header("Content-Security-Policy").is_none() {
        findings.push(HeaderFinding {
            url: url.to_string(),
            check_name: "Missing Content-Security-Policy".to_string(),
            severity: "MEDIUM".to_string(),
            detail: "No CSP header found. Successful XSS attacks can freely exfiltrate data to any origin.".to_string(),
            remediation: "Add: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'".to_string(),
            header_value: None,
        });
    }

    if get_header("X-Content-Type-Options").is_none() {
        findings.push(HeaderFinding {
            url: url.to_string(),
            check_name: "Missing X-Content-Type-Options".to_string(),
            severity: "LOW".to_string(),
            detail: "X-Content-Type-Options: nosniff is absent — browsers may MIME-sniff responses.".to_string(),
            remediation: "Add: X-Content-Type-Options: nosniff".to_string(),
            header_value: None,
        });
    }

    if get_header("X-Frame-Options").is_none() && !raw.contains("frame-ancestors") {
        findings.push(HeaderFinding {
            url: url.to_string(),
            check_name: "Missing Clickjacking Protection".to_string(),
            severity: "MEDIUM".to_string(),
            detail: "Neither X-Frame-Options nor CSP frame-ancestors is set — page can be embedded in an iframe for clickjacking.".to_string(),
            remediation: "Add: X-Frame-Options: DENY  or  Content-Security-Policy: frame-ancestors 'none'".to_string(),
            header_value: None,
        });
    }

    if get_header("Referrer-Policy").is_none() {
        findings.push(HeaderFinding {
            url: url.to_string(),
            check_name: "Missing Referrer-Policy".to_string(),
            severity: "LOW".to_string(),
            detail: "No Referrer-Policy — full URLs including sensitive query parameters leak to third-party resources via Referer header.".to_string(),
            remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin".to_string(),
            header_value: None,
        });
    }

    if get_header("Permissions-Policy").is_none() {
        findings.push(HeaderFinding {
            url: url.to_string(),
            check_name: "Missing Permissions-Policy".to_string(),
            severity: "LOW".to_string(),
            detail: "No Permissions-Policy — embedded scripts can access camera, microphone, and geolocation without restriction.".to_string(),
            remediation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()".to_string(),
            header_value: None,
        });
    }

    // Server header disclosure
    if let Some(server) = get_header("Server") {
        let lower = server.to_lowercase();
        if lower.contains('/') || lower.contains("apache") || lower.contains("nginx") || lower.contains("iis") {
            findings.push(HeaderFinding {
                url: url.to_string(),
                check_name: "Server Version Disclosure".to_string(),
                severity: "LOW".to_string(),
                detail: format!("Server header reveals software version: '{}'", server),
                remediation: "Configure server to suppress version info. Apache: ServerTokens Prod  Nginx: server_tokens off".to_string(),
                header_value: Some(server),
            });
        }
    }

    // ── CORS checks ──────────────────────────────────────────────────────────
    // Send with Origin: https://evil.attacker.com to check reflection
    let cors_stdout: Vec<u8> = match tokio::process::Command::new("curl")
        .args(["-sSIL", "--max-time", "10",
               "-H", "Origin: https://evil.attacker-penforge.com",
               "-H", "Access-Control-Request-Method: GET",
               url])
        .output().await
    {
        Ok(out) => out.stdout,
        Err(_)  => vec![],
    };

    let cors_raw = String::from_utf8_lossy(&cors_stdout).to_string();
    let cors_lower = cors_raw.to_lowercase();

    let acao = cors_raw.lines()
        .find(|l| l.to_lowercase().starts_with("access-control-allow-origin"))
        .map(|l| l[l.find(':').unwrap_or(0)+1..].trim().to_string());

    let acac = cors_lower.contains("access-control-allow-credentials: true");

    if let Some(ref origin) = acao {
        let origin_lower = origin.to_lowercase();
        if origin_lower == "*" && acac {
            findings.push(HeaderFinding {
                url: url.to_string(),
                check_name: "CORS: Wildcard with Credentials".to_string(),
                severity: "HIGH".to_string(),
                detail: "ACAO: * combined with ACAC: true — credentials will be sent cross-origin to any site.".to_string(),
                remediation: "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use explicit origin allowlist.".to_string(),
                header_value: Some(origin.clone()),
            });
        } else if origin_lower.contains("evil.attacker-penforge.com") {
            // Origin reflected
            if acac {
                findings.push(HeaderFinding {
                    url: url.to_string(),
                    check_name: "CORS: Reflected Origin with Credentials".to_string(),
                    severity: "CRITICAL".to_string(),
                    detail: "Server reflects the attacker-supplied Origin header with ACAC: true — any origin can make credentialled cross-origin requests.".to_string(),
                    remediation: "Implement strict CORS origin allowlist. Never reflect the Origin header. Validate against server-side whitelist.".to_string(),
                    header_value: Some(origin.clone()),
                });
            } else {
                findings.push(HeaderFinding {
                    url: url.to_string(),
                    check_name: "CORS: Reflected Origin (No Credentials)".to_string(),
                    severity: "MEDIUM".to_string(),
                    detail: "Server reflects arbitrary Origin without credential requirement — cross-origin reads of non-credentialled responses possible.".to_string(),
                    remediation: "Implement strict CORS allowlist. Validate Origin against whitelist server-side.".to_string(),
                    header_value: Some(origin.clone()),
                });
            }
        } else if origin_lower == "*" {
            findings.push(HeaderFinding {
                url: url.to_string(),
                check_name: "CORS: Wildcard Origin".to_string(),
                severity: "LOW".to_string(),
                detail: "ACAO: * — any website can read responses from this endpoint. Acceptable for fully public APIs; review if any authenticated content is returned.".to_string(),
                remediation: "If the endpoint serves any authenticated or sensitive content, replace wildcard with explicit allowlist.".to_string(),
                header_value: Some(origin.clone()),
            });
        }
    }

    findings
}

#[tauri::command]
pub async fn check_security_headers(
    app_handle: AppHandle,
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    urls: Vec<String>,
) -> Result<Vec<HeaderFinding>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let mut all_findings: Vec<HeaderFinding> = Vec::new();
    let total = urls.len() as f32;

    for (i, url) in urls.iter().enumerate() {
        if !state.lock().unwrap().scan_running { break; }

        let pct = (i as f32 / total) * 100.0;
        let _ = app_handle.emit("scan_progress", serde_json::json!({
            "scan_id": scan_id, "tool": "headers",
            "percent": pct,
            "message": format!("[headers] Checking {}", url),
            "level": "info"
        }));

        let header_findings = check_headers_for_url(url).await;
        for hf in &header_findings {
            let raw = RawFinding {
                source_tool: "headers".to_string(),
                severity: hf.severity.clone(),
                title: format!("{} — {}", hf.check_name, url.split('/').nth(2).unwrap_or(url)),
                description: hf.detail.clone(),
                affected_url: url.clone(),
                affected_port: None,
                cve_references: vec![],
                cvss_score: match hf.severity.as_str() {
                    "CRITICAL" => Some(9.1),
                    "HIGH"     => Some(7.5),
                    "MEDIUM"   => Some(5.4),
                    "LOW"      => Some(3.7),
                    _          => None,
                },
                evidence: hf.header_value.as_deref().unwrap_or("Header absent").to_string(),
                remediation: hf.remediation.clone(),
                http_request: None,
                http_response: None,
            };
            if let Ok(f) = store.add_finding(&scan_id, &raw, true) {
                let _ = app_handle.emit("scan_finding", &f);
            }
        }
        all_findings.extend(header_findings);

        // Rate limiting
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    let _ = app_handle.emit("scan_progress", serde_json::json!({
        "scan_id": scan_id, "tool": "headers",
        "percent": 100.0,
        "message": format!("[headers] Done — {} issues found across {} URLs", all_findings.len(), urls.len()),
        "level": "ok"
    }));

    Ok(all_findings)
}
