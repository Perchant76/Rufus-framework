// src-tauri/src/db/findings.rs
use sqlx::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;
use crate::db::models::{VulnFinding, RawFinding};

pub async fn insert(pool: &SqlitePool, scan_id: &str, raw: &RawFinding, in_scope: bool) -> Result<VulnFinding> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let cve_json = serde_json::to_string(&raw.cve_references)?;

    sqlx::query(
        "INSERT INTO vuln_findings
         (id, scan_id, source_tool, severity, title, description, affected_url,
          affected_port, cve_references, cvss_score, evidence, remediation,
          timestamp, in_scope, http_request, http_response)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    )
    .bind(&id)
    .bind(scan_id)
    .bind(&raw.source_tool)
    .bind(&raw.severity)
    .bind(&raw.title)
    .bind(&raw.description)
    .bind(&raw.affected_url)
    .bind(raw.affected_port)
    .bind(&cve_json)
    .bind(raw.cvss_score)
    .bind(&raw.evidence)
    .bind(&raw.remediation)
    .bind(&now)
    .bind(in_scope as i64)
    .bind(&raw.http_request)
    .bind(&raw.http_response)
    .execute(pool)
    .await?;

    get(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Finding not found after insert"))
}

pub async fn get(pool: &SqlitePool, id: &str) -> Result<Option<VulnFinding>> {
    Ok(sqlx::query_as::<_, VulnFinding>("SELECT * FROM vuln_findings WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?)
}

pub async fn list_for_scan(pool: &SqlitePool, scan_id: &str) -> Result<Vec<VulnFinding>> {
    Ok(sqlx::query_as::<_, VulnFinding>(
        "SELECT * FROM vuln_findings WHERE scan_id = ?
         ORDER BY CASE severity
           WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
           WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4
         END, title"
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?)
}

pub async fn list_all(pool: &SqlitePool) -> Result<Vec<VulnFinding>> {
    Ok(sqlx::query_as::<_, VulnFinding>(
        "SELECT * FROM vuln_findings ORDER BY timestamp DESC"
    )
    .fetch_all(pool)
    .await?)
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM vuln_findings WHERE id = ?")
        .bind(id).execute(pool).await?;
    Ok(())
}

pub async fn new_in_b(pool: &SqlitePool, scan_a: &str, scan_b: &str) -> Result<Vec<VulnFinding>> {
    Ok(sqlx::query_as::<_, VulnFinding>(
        "SELECT * FROM vuln_findings
         WHERE scan_id = ?
         AND title NOT IN (SELECT title FROM vuln_findings WHERE scan_id = ?)
         ORDER BY CASE severity
           WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
           WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
    )
    .bind(scan_b)
    .bind(scan_a)
    .fetch_all(pool)
    .await?)
}
