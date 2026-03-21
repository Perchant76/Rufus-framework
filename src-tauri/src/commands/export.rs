// src-tauri/src/commands/export.rs
use std::sync::Mutex;
use tauri::State;
use crate::AppState;
use crate::db::{self, models::{Scan, VulnFinding}};

#[tauri::command]
pub async fn export_pdf(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    output_path: String,
) -> Result<String, String> {
    let pool = { state.lock().unwrap().db.clone() };
    let scan = db::scans::get(&pool, &scan_id).await.map_err(|e| e.to_string())?
        .ok_or("Scan not found")?;
    let findings = db::findings::list_for_scan(&pool, &scan_id).await.map_err(|e| e.to_string())?;
    let html = build_pdf_html(&scan, &findings);
    tokio::fs::write(&output_path, html).await.map_err(|e| e.to_string())?;
    Ok(output_path)
}

#[tauri::command]
pub async fn export_csv(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    output_path: String,
) -> Result<String, String> {
    let pool = { state.lock().unwrap().db.clone() };
    let findings = db::findings::list_for_scan(&pool, &scan_id).await.map_err(|e| e.to_string())?;
    let mut csv = String::from("ID,Severity,Title,Affected URL,Port,CVEs,CVSS,Tool,In-Scope,Timestamp\n");
    for f in &findings {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            f.id, f.severity,
            escape_csv(&f.title), escape_csv(&f.affected_url),
            f.affected_port.map(|p| p.to_string()).unwrap_or_default(),
            escape_csv(&f.cve_references),
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
    let pool = { state.lock().unwrap().db.clone() };
    let findings = db::findings::list_for_scan(&pool, &scan_id).await.map_err(|e| e.to_string())?;
    let xml = build_burp_xml(&findings);
    tokio::fs::write(&output_path, xml).await.map_err(|e| e.to_string())?;
    Ok(output_path)
}

#[tauri::command]
pub async fn export_caido(
    state: State<'_, Mutex<AppState>>,
    scan_id: String,
    output_path: String,
) -> Result<String, String> {
    let pool = { state.lock().unwrap().db.clone() };
    let findings = db::findings::list_for_scan(&pool, &scan_id).await.map_err(|e| e.to_string())?;
    let targets: Vec<serde_json::Value> = findings.iter().map(|f| {
        serde_json::json!({
            "url": f.affected_url,
            "severity": f.severity,
            "title": f.title,
            "request": f.http_request,
            "response": f.http_response,
        })
    }).collect();
    let json = serde_json::to_string_pretty(&serde_json::json!({
        "version": "1.0",
        "export_type": "caido",
        "targets": targets,
    })).map_err(|e| e.to_string())?;
    tokio::fs::write(&output_path, json).await.map_err(|e| e.to_string())?;
    Ok(output_path)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn build_burp_xml(findings: &[VulnFinding]) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<issues burpVersion=\"2024.0\">\n");
    for f in findings {
        if let (Some(req), Some(resp)) = (&f.http_request, &f.http_response) {
            xml.push_str(&format!(
                "  <issue>\n    <serialNumber>{}</serialNumber>\n    <type>134217728</type>\n    <n>{}</n>\n    <host>{}</host>\n    <path>/</path>\n    <severity>{}</severity>\n    <confidence>Certain</confidence>\n    <issueDetail>{}</issueDetail>\n    <requestresponse><request base64=\"false\">{}</request><response base64=\"false\">{}</response></requestresponse>\n  </issue>\n",
                f.id, xml_escape(&f.title), xml_escape(&f.affected_url),
                xml_escape(&f.severity), xml_escape(&f.description),
                xml_escape(req), xml_escape(resp)
            ));
        }
    }
    xml.push_str("</issues>");
    xml
}

fn build_pdf_html(scan: &Scan, findings: &[VulnFinding]) -> String {
    let critical = findings.iter().filter(|f| f.severity == "CRITICAL").count();
    let high = findings.iter().filter(|f| f.severity == "HIGH").count();
    let medium = findings.iter().filter(|f| f.severity == "MEDIUM").count();
    let low = findings.iter().filter(|f| f.severity == "LOW").count();

    let mut rows = String::new();
    for f in findings {
        let color = match f.severity.as_str() {
            "CRITICAL" => "#ff3b5c", "HIGH" => "#ff7b2c",
            "MEDIUM" => "#f5c518", "LOW" => "#22c55e", _ => "#00d4ff",
        };
        rows.push_str(&format!(
            "<tr><td style='color:{}'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            color, f.severity, html_escape(&f.title),
            html_escape(&f.affected_url), html_escape(&f.source_tool),
            f.cve_references.replace(['[', ']', '"'], "")
        ));
    }

    format!(
        r#"<!DOCTYPE html><html><head><title>ProbeScan — {target}</title>
<style>
  body {{ font-family: monospace; background: #080b0f; color: #c9d6e3; padding: 40px; }}
  h1 {{ color: #00d4ff; margin-bottom: 4px; }}
  h2 {{ color: #5d7a96; font-size: 13px; text-transform: uppercase; letter-spacing: 2px; margin: 24px 0 12px; }}
  p {{ font-size: 12px; color: #5d7a96; margin-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ background: #111820; padding: 8px 12px; text-align: left; color: #5d7a96; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #1e2d3d; vertical-align: top; }}
  .summary {{ display: flex; gap: 24px; margin: 16px 0; }}
  .stat {{ background: #0d1117; border: 1px solid #1e2d3d; border-radius: 6px; padding: 12px 20px; }}
  .stat-num {{ font-size: 28px; font-weight: 800; }}
  .stat-label {{ font-size: 10px; color: #5d7a96; text-transform: uppercase; }}
</style></head>
<body>
<h1>ProbeScan Penetration Test Report</h1>
<p>Target: <strong style="color:#00d4ff">{target}</strong> &nbsp;·&nbsp; Date: {date} &nbsp;·&nbsp; Stealth: {stealth} &nbsp;·&nbsp; Tools: {tools}</p>

<h2>Executive Summary</h2>
<div class="summary">
  <div class="stat"><div class="stat-num" style="color:#ff3b5c">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-num" style="color:#ff7b2c">{high}</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-num" style="color:#f5c518">{medium}</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-num" style="color:#22c55e">{low}</div><div class="stat-label">Low</div></div>
  <div class="stat"><div class="stat-num" style="color:#00d4ff">{total}</div><div class="stat-label">Total</div></div>
</div>

<h2>Findings</h2>
<table>
  <tr><th>Severity</th><th>Title</th><th>Affected URL</th><th>Tool</th><th>CVEs</th></tr>
  {rows}
</table>
</body></html>"#,
        target = scan.target,
        date = scan.created_at.get(..10).unwrap_or(&scan.created_at),
        stealth = if scan.stealth_mode { "ON" } else { "OFF" },
        tools = scan.tools_used.as_deref().unwrap_or("all"),
        critical = critical, high = high, medium = medium, low = low,
        total = findings.len(),
        rows = rows,
    )
}
