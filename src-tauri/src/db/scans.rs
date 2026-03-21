// src-tauri/src/db/scans.rs
use sqlx::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;
use crate::db::models::{Scan, ScanConfig};

pub async fn create(pool: &SqlitePool, config: &ScanConfig) -> Result<Scan> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let scope_json = serde_json::to_string(&config.scope)?;
    let auth_json = config.auth.as_ref()
        .map(|a| serde_json::to_string(a))
        .transpose()?;
    let rate_json = serde_json::to_string(&serde_json::json!({
        "concurrency": config.concurrency,
        "delay_min_ms": config.delay_min_ms,
        "delay_max_ms": config.delay_max_ms,
    }))?;
    let tools_json = serde_json::to_string(&config.tools)?;

    sqlx::query(
        "INSERT INTO scans
         (id, target, target_type, scope, status, stealth_mode, auth_config, rate_config, tools_used, created_at)
         VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&config.target)
    .bind(&config.target_type)
    .bind(&scope_json)
    .bind(config.stealth_mode as i64)
    .bind(&auth_json)
    .bind(&rate_json)
    .bind(&tools_json)
    .bind(&now)
    .execute(pool)
    .await?;

    get(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Scan not found after insert"))
}

pub async fn get(pool: &SqlitePool, id: &str) -> Result<Option<Scan>> {
    let scan = sqlx::query_as::<_, Scan>(
        "SELECT s.*, (SELECT COUNT(*) FROM vuln_findings f WHERE f.scan_id = s.id) as finding_count
         FROM scans s WHERE s.id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(scan)
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<Scan>> {
    let scans = sqlx::query_as::<_, Scan>(
        "SELECT s.*, (SELECT COUNT(*) FROM vuln_findings f WHERE f.scan_id = s.id) as finding_count
         FROM scans s ORDER BY s.created_at DESC"
    )
    .fetch_all(pool)
    .await?;
    Ok(scans)
}

pub async fn update_status(pool: &SqlitePool, id: &str, status: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    if status == "complete" || status == "stopped" {
        sqlx::query("UPDATE scans SET status = ?, completed_at = ? WHERE id = ?")
            .bind(status).bind(&now).bind(id)
            .execute(pool).await?;
    } else {
        sqlx::query("UPDATE scans SET status = ? WHERE id = ?")
            .bind(status).bind(id)
            .execute(pool).await?;
    }
    Ok(())
}

pub async fn delete(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scans WHERE id = ?")
        .bind(id).execute(pool).await?;
    Ok(())
}
