// src-tauri/src/commands/cloud.rs
// Pure Rust cloud asset enumeration — no external tools required.
use std::sync::Mutex;
use tauri::State;
use uuid::Uuid;
use chrono::Utc;
use crate::AppState;
use crate::db::models::{CloudAsset, RawFinding};

const TAKEOVER_FINGERPRINTS: &[(&str, &str, &str)] = &[
    ("github.io",              "There isn't a GitHub Pages site here",         "GitHub Pages"),
    ("herokuapp.com",          "No such app",                                   "Heroku"),
    ("myshopify.com",          "Sorry, this shop is currently unavailable",     "Shopify"),
    ("fastly.net",             "Fastly error: unknown domain",                  "Fastly"),
    ("pantheon.io",            "The gods are wise",                             "Pantheon"),
    ("netlify.app",            "Not Found",                                     "Netlify"),
    ("s3.amazonaws.com",       "NoSuchBucket",                                  "AWS S3"),
    ("azurewebsites.net",      "404 Web Site not found",                        "Azure"),
    ("wpengine.com",           "The site you were looking for",                 "WP Engine"),
    ("ghost.io",               "Site not found",                                "Ghost"),
    ("surge.sh",               "project not found",                             "Surge"),
    ("readme.io",              "Project doesnt exist",                          "ReadMe"),
    ("fly.io",                 "404 Not Found",                                 "Fly.io"),
    ("render.com",             "not found",                                     "Render"),
];

fn cloud_permutations(name: &str) -> Vec<(String, String)> {
    let name_clean: String = name.chars().filter(|c| c.is_alphanumeric() || *c == '-').collect();
    let mut urls = vec![];

    // AWS S3
    for suffix in &["", "-backup", "-dev", "-staging", "-prod", "-assets", "-static", "-data", "-files", "-media"] {
        urls.push((format!("https://{}{}.s3.amazonaws.com", name_clean, suffix), "aws_s3".into()));
        urls.push((format!("https://s3.amazonaws.com/{}{}", name_clean, suffix), "aws_s3".into()));
    }

    // Azure Blob
    for suffix in &["", "backup", "dev", "prod", "assets"] {
        urls.push((format!("https://{}{}.blob.core.windows.net", name_clean, suffix), "azure_blob".into()));
    }

    // GCP Storage
    for suffix in &["", "-backup", "-dev", "-assets"] {
        urls.push((format!("https://storage.googleapis.com/{}{}", name_clean, suffix), "gcp_storage".into()));
        urls.push((format!("https://{}{}.storage.googleapis.com", name_clean, suffix), "gcp_storage".into()));
    }

    urls
}

#[tauri::command]
pub async fn enumerate_cloud_assets(
    state: State<'_, Mutex<AppState>>,
    target: String,
    scan_id: String,
) -> Result<Vec<CloudAsset>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };

    // Extract company name from domain (strip TLD)
    let name = target.split('.').next().unwrap_or(&target).to_string();
    let permutations = cloud_permutations(&name);

    let mut assets = Vec::new();

    for (url, provider) in permutations {
        let result = check_url(&url).await;
        let (status, body) = result.unwrap_or((0, String::new()));
        let accessible = status == 200 || status == 403;
        let takeover = body.contains("NoSuchBucket") || body.contains("404 Web Site not found")
            || body.contains("BucketNotFound");

        if accessible || takeover {
            let asset = CloudAsset {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.clone(),
                provider: provider.clone(),
                url: url.clone(),
                status,
                accessible: status == 200,
                takeover_candidate: takeover,
                checked_at: Utc::now().to_rfc3339(),
            };

            // Create finding for accessible buckets
            if accessible {
                let severity = if status == 200 { "HIGH" } else { "MEDIUM" };
                let raw = RawFinding {
                    source_tool: "cloud_enum".to_string(),
                    severity: severity.to_string(),
                    title: format!("Exposed Cloud Asset: {}", url),
                    description: format!("{} cloud storage asset found at {}", provider, url),
                    affected_url: url.clone(),
                    affected_port: Some(443),
                    cve_references: vec![],
                    cvss_score: if status == 200 { Some(7.5) } else { Some(5.3) },
                    evidence: format!("HTTP {} — provider: {}", status, provider),
                    remediation: "Review bucket permissions. Enforce private access unless public access is explicitly required. Enable access logging.".to_string(),
                    http_request: None, http_response: None,
                };
                store.add_finding(&scan_id, &raw, true).ok();
            }

            assets.push(asset);
        }
    }

    store.save_cloud_assets(&scan_id, &assets).map_err(|e| e.to_string())?;
    Ok(assets)
}

#[tauri::command]
pub async fn list_cloud_assets(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
) -> Result<Vec<CloudAsset>, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    store.list_cloud_assets(&scan_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn check_takeover(subdomains: Vec<String>) -> Result<Vec<serde_json::Value>, String> {
    let mut candidates = vec![];

    for subdomain in &subdomains {
        let result = check_url(&format!("https://{}", subdomain)).await;
        let body = result.map(|(_, b)| b).unwrap_or_default();

        for (pattern, fingerprint, service) in TAKEOVER_FINGERPRINTS {
            if subdomain.contains(pattern) && body.contains(fingerprint) {
                candidates.push(serde_json::json!({
                    "subdomain": subdomain,
                    "service": service,
                    "fingerprint_matched": fingerprint,
                    "confidence": "HIGH"
                }));
                break;
            }
            // Check even without CNAME match — body fingerprint alone is MEDIUM
            if body.contains(fingerprint) {
                candidates.push(serde_json::json!({
                    "subdomain": subdomain,
                    "service": service,
                    "fingerprint_matched": fingerprint,
                    "confidence": "MEDIUM"
                }));
                break;
            }
        }
    }

    Ok(candidates)
}

async fn check_url(url: &str) -> Option<(u16, String)> {
    let output = tokio::process::Command::new("curl")
        .args(["-s", "-o", "-", "-w", "\n__STATUS__%{http_code}",
               "--max-time", "8", "--connect-timeout", "4",
               "-L", "--max-redirs", "3", url])
        .output()
        .await
        .ok()?;

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    if let Some(pos) = raw.rfind("\n__STATUS__") {
        let body = raw[..pos].to_string();
        let status_str = &raw[pos + 11..];
        let status: u16 = status_str.trim().parse().unwrap_or(0);
        Some((status, body))
    } else {
        None
    }
}
