// src-tauri/src/db/migrations.rs
use sqlx::SqlitePool;
use anyhow::Result;

pub async fn run(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scans (
            id              TEXT PRIMARY KEY,
            target          TEXT NOT NULL,
            target_type     TEXT NOT NULL,
            scope           TEXT NOT NULL DEFAULT '[]',
            status          TEXT NOT NULL DEFAULT 'pending',
            stealth_mode    INTEGER NOT NULL DEFAULT 0,
            auth_config     TEXT,
            rate_config     TEXT,
            tools_used      TEXT,
            created_at      TEXT NOT NULL,
            completed_at    TEXT,
            duration_secs   INTEGER,
            finding_count   INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS vuln_findings (
            id              TEXT PRIMARY KEY,
            scan_id         TEXT NOT NULL,
            source_tool     TEXT NOT NULL,
            severity        TEXT NOT NULL,
            title           TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            affected_url    TEXT NOT NULL,
            affected_port   INTEGER,
            cve_references  TEXT NOT NULL DEFAULT '[]',
            cvss_score      REAL,
            evidence        TEXT NOT NULL DEFAULT '',
            remediation     TEXT NOT NULL DEFAULT '',
            timestamp       TEXT NOT NULL,
            in_scope        INTEGER NOT NULL DEFAULT 1,
            http_request    TEXT,
            http_response   TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS discovered_assets (
            id              TEXT PRIMARY KEY,
            scan_id         TEXT NOT NULL,
            asset_type      TEXT NOT NULL,
            value           TEXT NOT NULL,
            ip              TEXT,
            http_status     INTEGER,
            page_title      TEXT,
            tech_stack      TEXT,
            redirect_chain  TEXT,
            parent          TEXT,
            in_scope        INTEGER NOT NULL DEFAULT 1,
            discovered_at   TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan ON vuln_findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON vuln_findings(severity);
        CREATE INDEX IF NOT EXISTS idx_assets_scan ON discovered_assets(scan_id);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
