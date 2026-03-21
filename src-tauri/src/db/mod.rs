// src-tauri/src/db/mod.rs
pub mod models;
pub mod migrations;
pub mod scans;
pub mod findings;
pub mod assets;

use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use anyhow::Result;

pub async fn init_pool(url: &str) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await?;
    Ok(pool)
}
