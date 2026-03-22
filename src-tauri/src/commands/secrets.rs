// src-tauri/src/commands/secrets.rs
// JS Secret Scanner — finds API keys, tokens, credentials in JS files
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};
use crate::AppState;
use crate::db::models::{RawFinding, VulnFinding};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub id: String,
    pub scan_id: String,
    pub js_url: String,
    pub rule_name: String,
    pub matched_text: String,        // redacted after first 8 chars
    pub full_match: String,          // stored for report, shown in detail view
    pub severity: String,
    pub line_number: Option<usize>,
    pub context: String,             // surrounding line for context
    pub found_at: String,
}

struct SecretRule {
    name: &'static str,
    severity: &'static str,
    pattern: &'static str,          // simple substring patterns for portability
    patterns: &'static [&'static str],
}

const SECRET_RULES: &[SecretRule] = &[
    SecretRule { name:"AWS Access Key",          severity:"CRITICAL", pattern:"", patterns:&["AKIA","ASIA","ABIA","ACCA"] },
    SecretRule { name:"AWS Secret Key",          severity:"CRITICAL", pattern:"", patterns:&["aws_secret","AWS_SECRET","aws_secret_access_key"] },
    SecretRule { name:"GitHub Token",            severity:"CRITICAL", pattern:"", patterns:&["ghp_","gho_","ghu_","ghs_","ghr_","github_token","GITHUB_TOKEN"] },
    SecretRule { name:"GitLab Token",            severity:"HIGH",     pattern:"", patterns:&["glpat-","GITLAB_TOKEN","gitlab_token"] },
    SecretRule { name:"Stripe Secret Key",       severity:"CRITICAL", pattern:"", patterns:&["sk_live_","rk_live_"] },
    SecretRule { name:"Stripe Publishable Key",  severity:"MEDIUM",   pattern:"", patterns:&["pk_live_","pk_test_"] },
    SecretRule { name:"Slack Token",             severity:"HIGH",     pattern:"", patterns:&["xoxb-","xoxp-","xoxa-","xoxr-"] },
    SecretRule { name:"Slack Webhook",           severity:"HIGH",     pattern:"", patterns:&["hooks.slack.com/services/"] },
    SecretRule { name:"Twilio API Key",          severity:"HIGH",     pattern:"", patterns:&["SK","AC","twilio_","TWILIO_"] },
    SecretRule { name:"SendGrid API Key",        severity:"HIGH",     pattern:"", patterns:&["SG.","sendgrid_api","SENDGRID"] },
    SecretRule { name:"Mailgun API Key",         severity:"HIGH",     pattern:"", patterns:&["key-","mailgun","MAILGUN"] },
    SecretRule { name:"Firebase API Key",        severity:"MEDIUM",   pattern:"", patterns:&["AIza","firebase","FIREBASE"] },
    SecretRule { name:"Google API Key",          severity:"HIGH",     pattern:"", patterns:&["AIza"] },
    SecretRule { name:"Google OAuth",            severity:"HIGH",     pattern:"", patterns:&[".apps.googleusercontent.com","GOOGLE_CLIENT_SECRET"] },
    SecretRule { name:"Private Key (PEM)",       severity:"CRITICAL", pattern:"", patterns:&["-----BEGIN RSA PRIVATE KEY","-----BEGIN EC PRIVATE KEY","-----BEGIN PRIVATE KEY","-----BEGIN OPENSSH PRIVATE KEY"] },
    SecretRule { name:"JWT Token",               severity:"MEDIUM",   pattern:"", patterns:&["eyJhbGciOiJ","eyJ0eXAiOi"] },
    SecretRule { name:"Basic Auth in URL",       severity:"HIGH",     pattern:"", patterns:&["://","@"] },  // combined check in code
    SecretRule { name:"Password in Code",        severity:"HIGH",     pattern:"", patterns:&["password=","passwd=","pwd=","secret=","api_key=","apikey=","api_secret="] },
    SecretRule { name:"Hardcoded Bearer Token",  severity:"HIGH",     pattern:"", patterns:&["Bearer ","bearer_token","BEARER_TOKEN"] },
    SecretRule { name:"Database Connection Str", severity:"CRITICAL", pattern:"", patterns:&["mongodb://","mysql://","postgresql://","postgres://","redis://","mssql://","jdbc:mysql"] },
    SecretRule { name:"Heroku API Key",          severity:"HIGH",     pattern:"", patterns:&["heroku","HEROKU_API_KEY"] },
    SecretRule { name:"Cloudflare API Token",    severity:"HIGH",     pattern:"", patterns:&["cloudflare","CF_API_KEY","CLOUDFLARE_TOKEN"] },
    SecretRule { name:"Shopify Access Token",    severity:"HIGH",     pattern:"", patterns:&["shpat_","shpss_","shpca_","shppa_"] },
    SecretRule { name:"HubSpot API Key",         severity:"MEDIUM",   pattern:"", patterns:&["hubspot","HUBSPOT","hapikey"] },
    SecretRule { name:"Okta API Token",          severity:"HIGH",     pattern:"", patterns:&["okta_","OKTA_","ssws "] },
    SecretRule { name:"npm Token",               severity:"HIGH",     pattern:"", patterns:&["npm_","NPM_TOKEN"] },
    SecretRule { name:"Docker Registry Auth",    severity:"HIGH",     pattern:"", patterns:&["docker_auth","DOCKER_PASSWORD","registry-auth"] },
    SecretRule { name:"Telegram Bot Token",      severity:"MEDIUM",   pattern:"", patterns:&["bot","telegram","TELEGRAM_TOKEN",":AAE","api.telegram.org/bot"] },
    SecretRule { name:"Artifactory Token",       severity:"HIGH",     pattern:"", patterns:&["artifactory","ARTIFACTORY_API_KEY","X-JFrog-Art-Api"] },
    SecretRule { name:"Jira API Token",          severity:"MEDIUM",   pattern:"", patterns:&["jira","JIRA_API_TOKEN","jiraApiToken"] },
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
        let line_lower = line.to_lowercase();
        // Skip minified bundle comment lines and empty lines
        if line.trim().is_empty() || line.trim_start().starts_with("//") { continue; }

        for rule in SECRET_RULES {
            let hit = rule.patterns.iter().any(|p| line.contains(p) || line_lower.contains(&p.to_lowercase()));
            if !hit { continue; }

            // Special case: basic auth in URL needs both "://" and "@" with content between
            if rule.name == "Basic Auth in URL" {
                let has_at = line.contains("://") && line.contains('@');
                if !has_at { continue; }
            }

            // Extract the matched token value (rough extraction)
            let matched_val = rule.patterns.iter()
                .filter_map(|p| {
                    let pos = line.find(p).or_else(|| line_lower.find(&p.to_lowercase()))?;
                    let start = pos;
                    let end = (pos + p.len() + 40).min(line.len());
                    Some(line[start..end].to_string())
                })
                .next()
                .unwrap_or_else(|| context_around(line, 60));

            // Skip obvious false positives (variable declarations without values, comments)
            if matched_val.contains("//") && matched_val.trim_start().starts_with("//") { continue; }

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
            break; // one rule match per line is enough
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
        // Check running
        if !state.lock().unwrap().scan_running { break; }

        let _ = app_handle.emit("scan_progress", serde_json::json!({
            "scan_id": scan_id,
            "tool": "js-secrets",
            "percent": -1.0,
            "message": format!("[js-secrets] Scanning {}", url),
            "level": "info"
        }));

        // Fetch JS file via curl
        let output = tokio::process::Command::new("curl")
            .args(["-sSL", "--max-time", "10", "--max-filesize", "5000000", url])
            .output().await.unwrap_or_default();

        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout);
            let secrets = scan_js_content(url, &content, &scan_id);

            for secret in &secrets {
                // Save as a finding
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
                    evidence: format!("Rule: {}\nMatch: {}\nContext: {}", secret.rule_name, secret.matched_text, secret.context),
                    remediation: "Move secrets to server-side environment variables. Rotate any exposed credentials immediately. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault). Implement pre-commit hooks to prevent accidental secret commits.".to_string(),
                    http_request: None,
                    http_response: None,
                };
                let in_scope = true;
                if let Ok(f) = store.add_finding(&scan_id, &raw, in_scope) {
                    let _ = app_handle.emit("scan_finding", &f);
                }
            }
            all_secrets.extend(secrets);
        }

        // Brief delay between requests
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    let _ = app_handle.emit("scan_progress", serde_json::json!({
        "scan_id": scan_id,
        "tool": "js-secrets",
        "percent": 100.0,
        "message": format!("[js-secrets] Completed — {} secrets found", all_secrets.len()),
        "level": if all_secrets.is_empty() { "ok" } else { "warn" }
    }));

    Ok(all_secrets)
}
