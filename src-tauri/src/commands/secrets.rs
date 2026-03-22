// src-tauri/src/commands/secrets.rs
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};
use crate::AppState;
use crate::db::models::RawFinding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub id: String,
    pub scan_id: String,
    pub js_url: String,
    pub rule_name: String,
    pub matched_text: String,
    pub full_match: String,
    pub severity: String,
    pub line_number: Option<usize>,
    pub context: String,
    pub found_at: String,
}

struct SecretRule {
    name: &'static str,
    severity: &'static str,
    patterns: &'static [&'static str],
}

const SECRET_RULES: &[SecretRule] = &[
    SecretRule { name:"AWS Access Key",          severity:"CRITICAL", patterns:&["AKIA","ASIA","ABIA","ACCA"] },
    SecretRule { name:"AWS Secret Key",          severity:"CRITICAL", patterns:&["aws_secret","AWS_SECRET","aws_secret_access_key"] },
    SecretRule { name:"GitHub Token",            severity:"CRITICAL", patterns:&["ghp_","gho_","ghu_","ghs_","ghr_","github_token","GITHUB_TOKEN"] },
    SecretRule { name:"GitLab Token",            severity:"HIGH",     patterns:&["glpat-","GITLAB_TOKEN","gitlab_token"] },
    SecretRule { name:"Stripe Secret Key",       severity:"CRITICAL", patterns:&["sk_live_","rk_live_"] },
    SecretRule { name:"Stripe Publishable Key",  severity:"MEDIUM",   patterns:&["pk_live_","pk_test_"] },
    SecretRule { name:"Slack Token",             severity:"HIGH",     patterns:&["xoxb-","xoxp-","xoxa-","xoxr-"] },
    SecretRule { name:"Slack Webhook",           severity:"HIGH",     patterns:&["hooks.slack.com/services/"] },
    SecretRule { name:"SendGrid API Key",        severity:"HIGH",     patterns:&["SG.","sendgrid_api","SENDGRID"] },
    SecretRule { name:"Firebase API Key",        severity:"MEDIUM",   patterns:&["AIza","firebase","FIREBASE"] },
    SecretRule { name:"Google API Key",          severity:"HIGH",     patterns:&["AIza"] },
    SecretRule { name:"Google OAuth",            severity:"HIGH",     patterns:&[".apps.googleusercontent.com","GOOGLE_CLIENT_SECRET"] },
    SecretRule { name:"Private Key (PEM)",       severity:"CRITICAL", patterns:&["-----BEGIN RSA PRIVATE KEY","-----BEGIN EC PRIVATE KEY","-----BEGIN PRIVATE KEY","-----BEGIN OPENSSH PRIVATE KEY"] },
    SecretRule { name:"JWT Token",               severity:"MEDIUM",   patterns:&["eyJhbGciOiJ","eyJ0eXAiOi"] },
    SecretRule { name:"Password in Code",        severity:"HIGH",     patterns:&["password=","passwd=","pwd=","secret=","api_key=","apikey=","api_secret="] },
    SecretRule { name:"Hardcoded Bearer Token",  severity:"HIGH",     patterns:&["Bearer ","bearer_token","BEARER_TOKEN"] },
    SecretRule { name:"Database Connection Str", severity:"CRITICAL", patterns:&["mongodb://","mysql://","postgresql://","postgres://","redis://","mssql://","jdbc:mysql"] },
    SecretRule { name:"Heroku API Key",          severity:"HIGH",     patterns:&["heroku","HEROKU_API_KEY"] },
    SecretRule { name:"Shopify Access Token",    severity:"HIGH",     patterns:&["shpat_","shpss_","shpca_","shppa_"] },
    SecretRule { name:"npm Token",               severity:"HIGH",     patterns:&["npm_","NPM_TOKEN"] },
    SecretRule { name:"Twilio API Key",          severity:"HIGH",     patterns:&["twilio_","TWILIO_","SK","AC"] },
    SecretRule { name:"Okta API Token",          severity:"HIGH",     patterns:&["okta_","OKTA_","ssws "] },
    SecretRule { name:"Telegram Bot Token",      severity:"MEDIUM",   patterns:&["api.telegram.org/bot"] },
    SecretRule { name:"HubSpot API Key",         severity:"MEDIUM",   patterns:&["hapikey"] },
];

fn redact(s: &str) -> String {
    if s.len() <= 8 { return "*".repeat(s.len()); }
    format!("{}...{}", &s[..4], "*".repeat(8))
}

fn context_around(line: &str, max_len: usize) -> String {
    if line.len() <= max_len { return line.to_string(); }
    format!("{}...", &line[..max_len])
}

pub fn scan_js_content(url: &str, content: &str, scan_id: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    let now = chrono::Utc::now().to_rfc3339();

    for (line_idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        let line_lower = line.to_lowercase();

        for rule in SECRET_RULES {
            let hit = rule.patterns.iter().any(|p| {
                line.contains(p) || line_lower.contains(&p.to_lowercase())
            });
            if !hit { continue; }

            let matched_val = rule.patterns.iter()
                .filter_map(|p| {
                    let pos = line.find(p)
                        .or_else(|| line_lower.find(&p.to_lowercase()))?;
                    let end = (pos + p.len() + 40).min(line.len());
                    Some(line[pos..end].to_string())
                })
                .next()
                .unwrap_or_else(|| context_around(line, 60));

            matches.push(SecretMatch {
                id: uuid::Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                js_url: url.to_string(),
                rule_name: rule.name.to_string(),
                matched_text: redact(&matched_val),
                full_match: matched_val,
                severity: rule.severity.to_string(),
                line_number: Some(line_idx + 1),
                context: context_around(line.trim(), 120),
                found_at: now.clone(),
            });
            break;
        }
    }
    matches
}

#[tauri::command]
pub async fn scan_js_for_secrets(
    app_handle: AppHandle,
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    js_urls: Vec<String>,
) -> Result<Vec<SecretMatch>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let mut all_secrets: Vec<SecretMatch> = Vec::new();

    for url in &js_urls {
        if !state.lock().unwrap().scan_running { break; }

        let _ = app_handle.emit("scan_progress", serde_json::json!({
            "scan_id": scan_id, "tool": "js-secrets", "percent": -1.0,
            "message": format!("[js-secrets] Scanning {}", url), "level": "info"
        }));

        // Fetch JS content — skip on error
        let stdout_bytes: Vec<u8> = match tokio::process::Command::new("curl")
            .args(["-sSL", "--max-time", "10", "--max-filesize", "5000000", url])
            .output()
            .await
        {
            Ok(out) => out.stdout,
            Err(_)  => vec![],
        };

        if !stdout_bytes.is_empty() {
            let content = String::from_utf8_lossy(&stdout_bytes);
            let secrets = scan_js_content(url, &content, &scan_id);

            for secret in &secrets {
                let raw = RawFinding {
                    source_tool: "js-secrets".to_string(),
                    severity: secret.severity.clone(),
                    title: format!("Secret Exposed in JS: {}", secret.rule_name),
                    description: format!(
                        "Potential {} found in JavaScript file.\nFile: {}\nLine: {}\nContext: {}",
                        secret.rule_name, url,
                        secret.line_number.unwrap_or(0),
                        secret.context
                    ),
                    affected_url: url.clone(),
                    affected_port: None,
                    cve_references: vec!["CWE-798".to_string()],
                    cvss_score: match secret.severity.as_str() {
                        "CRITICAL" => Some(9.8),
                        "HIGH"     => Some(7.5),
                        "MEDIUM"   => Some(5.3),
                        _          => Some(3.7),
                    },
                    evidence: format!("Rule: {}\nMatch: {}\nContext: {}",
                        secret.rule_name, secret.matched_text, secret.context),
                    remediation: "Move secrets to server-side environment variables. \
                        Rotate any exposed credentials immediately. Use a secrets manager. \
                        Implement pre-commit hooks to prevent accidental secret commits.".to_string(),
                    http_request: None,
                    http_response: None,
                };
                if let Ok(f) = store.add_finding(&scan_id, &raw, true) {
                    let _ = app_handle.emit("scan_finding", &f);
                }
            }
            all_secrets.extend(secrets);
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    let _ = app_handle.emit("scan_progress", serde_json::json!({
        "scan_id": scan_id, "tool": "js-secrets", "percent": 100.0,
        "message": format!("[js-secrets] Complete — {} secrets found", all_secrets.len()),
        "level": if all_secrets.is_empty() { "ok" } else { "warn" }
    }));

    Ok(all_secrets)
}
