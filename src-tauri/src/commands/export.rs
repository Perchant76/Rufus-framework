// src-tauri/src/commands/export.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::models::{Scan, VulnFinding};

#[tauri::command]
pub async fn export_pdf(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    output_path: String,
) -> Result<String, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let scan = store.get_scan(&scan_id).map_err(|e| e.to_string())?
        .ok_or_else(|| "Scan not found".to_string())?;
    let findings = store.list_findings(&scan_id).map_err(|e| e.to_string())?;
    tokio::fs::write(&output_path, build_html_report(&scan, &findings))
        .await.map_err(|e| e.to_string())?;
    Ok(output_path)
}

#[tauri::command]
pub async fn export_csv(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    output_path: String,
) -> Result<String, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let findings = store.list_findings(&scan_id).map_err(|e| e.to_string())?;
    let mut csv = "ID,Severity,Title,URL,Port,CVEs,CVSS,Tool,InScope,Timestamp\n".to_string();
    for f in &findings {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            f.id, f.severity, csv_escape(&f.title), csv_escape(&f.affected_url),
            f.affected_port.map(|p| p.to_string()).unwrap_or_default(),
            f.cve_references.join(";"),
            f.cvss_score.map(|s| s.to_string()).unwrap_or_default(),
            f.source_tool, f.in_scope, f.timestamp,
        ));
    }
    tokio::fs::write(&output_path, csv).await.map_err(|e| e.to_string())?;
    Ok(output_path)
}

#[tauri::command]
pub async fn export_burp(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    output_path: String,
) -> Result<String, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let findings = store.list_findings(&scan_id).map_err(|e| e.to_string())?;
    let mut xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<issues>\n".to_string();
    for f in findings.iter().filter(|f| f.http_request.is_some()) {
        xml.push_str(&format!(
            "  <issue><serialNumber>{}</serialNumber><n>{}</n><host>{}</host>\
            <severity>{}</severity><issueDetail>{}</issueDetail>\
            <requestresponse><request>{}</request><response>{}</response></requestresponse></issue>\n",
            f.id, xe(&f.title), xe(&f.affected_url), xe(&f.severity), xe(&f.description),
            xe(f.http_request.as_deref().unwrap_or("")),
            xe(f.http_response.as_deref().unwrap_or(""))
        ));
    }
    xml.push_str("</issues>");
    tokio::fs::write(&output_path, xml).await.map_err(|e| e.to_string())?;
    Ok(output_path)
}

#[tauri::command]
pub async fn export_caido(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    output_path: String,
) -> Result<String, String> {
    let store = { state.lock().unwrap().store.clone_ref() };
    let findings = store.list_findings(&scan_id).map_err(|e| e.to_string())?;
    let targets: Vec<serde_json::Value> = findings.iter().map(|f| serde_json::json!({
        "url": f.affected_url, "severity": f.severity, "title": f.title,
        "request": f.http_request, "response": f.http_response,
    })).collect();
    let json = serde_json::to_string_pretty(&serde_json::json!({
        "version": "1.0", "export_type": "caido", "targets": targets
    })).map_err(|e| e.to_string())?;
    tokio::fs::write(&output_path, json).await.map_err(|e| e.to_string())?;
    Ok(output_path)
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) }
    else { s.to_string() }
}

fn xe(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn build_html_report(scan: &Scan, findings: &[VulnFinding]) -> String {
    let counts: std::collections::HashMap<&str, usize> = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        .iter().map(|s| (*s, findings.iter().filter(|f| f.severity == *s).count())).collect();
    let mut rows = String::new();
    for f in findings {
        let c = match f.severity.as_str() {
            "CRITICAL" => "#ff3b5c", "HIGH" => "#ff7b2c",
            "MEDIUM" => "#f5c518", "LOW" => "#22c55e", _ => "#00d4ff"
        };
        rows.push_str(&format!(
            "<tr><td style='color:{c}'>{}</td><td>{}</td><td style='font-size:11px'>{}</td><td>{}</td><td style='font-size:11px'>{}</td></tr>\n",
            f.severity, xe(&f.title), xe(&f.affected_url), xe(&f.source_tool),
            f.cve_references.join(", ")
        ));
    }
    format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<title>ProbeScan — {target}</title>
<style>
body{{font-family:monospace;background:#080b0f;color:#c9d6e3;padding:40px;margin:0}}
h1{{color:#00d4ff;margin-bottom:6px}} h2{{color:#5d7a96;font-size:13px;text-transform:uppercase;letter-spacing:2px;margin:28px 0 12px}}
.meta{{font-size:12px;color:#5d7a96;margin-bottom:24px}}
.stats{{display:flex;gap:16px;margin-bottom:24px}}
.stat{{background:#0d1117;border:1px solid #1e2d3d;border-radius:6px;padding:14px 20px}}
.stat-num{{font-size:28px;font-weight:800}} .stat-label{{font-size:10px;color:#5d7a96;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#111820;padding:9px 12px;text-align:left;color:#5d7a96;font-size:10px;text-transform:uppercase;letter-spacing:1px}}
td{{padding:9px 12px;border-bottom:1px solid #1e2d3d;vertical-align:top}}
</style></head><body>
<h1>ProbeScan Penetration Test Report</h1>
<div class="meta">Target: <strong style="color:#00d4ff">{target}</strong> &nbsp;·&nbsp; {date} &nbsp;·&nbsp; Stealth: {stealth} &nbsp;·&nbsp; {total} findings</div>
<div class="stats">
  <div class="stat"><div class="stat-num" style="color:#ff3b5c">{crit}</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-num" style="color:#ff7b2c">{high}</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-num" style="color:#f5c518">{med}</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-num" style="color:#22c55e">{low}</div><div class="stat-label">Low</div></div>
</div>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>URL</th><th>Tool</th><th>CVEs</th></tr>
{rows}</table>
</body></html>"#,
        target=scan.target, date=&scan.created_at[..10],
        stealth=if scan.stealth_mode{"ON"}else{"OFF"},
        total=findings.len(),
        crit=counts.get("CRITICAL").unwrap_or(&0),
        high=counts.get("HIGH").unwrap_or(&0),
        med=counts.get("MEDIUM").unwrap_or(&0),
        low=counts.get("LOW").unwrap_or(&0),
        rows=rows)
}
