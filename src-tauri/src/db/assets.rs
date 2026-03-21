// src-tauri/src/db/assets.rs
use sqlx::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;
use crate::db::models::DiscoveredAsset;

#[allow(clippy::too_many_arguments)]
pub async fn insert(
    pool: &SqlitePool,
    scan_id: &str,
    asset_type: &str,
    value: &str,
    ip: Option<&str>,
    http_status: Option<i64>,
    page_title: Option<&str>,
    tech_stack: Option<Vec<String>>,
    redirect_chain: Option<Vec<String>>,
    parent: Option<&str>,
    in_scope: bool,
) -> Result<DiscoveredAsset> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let tech_json = tech_stack.as_ref().map(|t| serde_json::to_string(t)).transpose()?;
    let redir_json = redirect_chain.as_ref().map(|r| serde_json::to_string(r)).transpose()?;

    sqlx::query(
        "INSERT INTO discovered_assets
         (id, scan_id, asset_type, value, ip, http_status, page_title,
          tech_stack, redirect_chain, parent, in_scope, discovered_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
    )
    .bind(&id).bind(scan_id).bind(asset_type).bind(value)
    .bind(ip).bind(http_status).bind(page_title)
    .bind(&tech_json).bind(&redir_json).bind(parent)
    .bind(in_scope as i64).bind(&now)
    .execute(pool).await?;

    Ok(DiscoveredAsset {
        id, scan_id: scan_id.to_string(), asset_type: asset_type.to_string(),
        value: value.to_string(), ip: ip.map(str::to_string),
        http_status, page_title: page_title.map(str::to_string),
        tech_stack: tech_json, redirect_chain: redir_json,
        parent: parent.map(str::to_string), in_scope,
        discovered_at: now,
    })
}

pub async fn list_for_scan(pool: &SqlitePool, scan_id: &str) -> Result<Vec<DiscoveredAsset>> {
    Ok(sqlx::query_as::<_, DiscoveredAsset>(
        "SELECT * FROM discovered_assets WHERE scan_id = ? ORDER BY value"
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?)
}
