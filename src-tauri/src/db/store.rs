// src-tauri/src/db/store.rs
// All data persisted as JSON files. Thread-safe via Mutex in AppState.

use std::path::{Path, PathBuf};
use anyhow::{Result, anyhow};
use chrono::Utc;
use uuid::Uuid;
use crate::db::models::*;

pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    /// Create store and ensure directory exists.
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    // ── Paths ────────────────────────────────────────────────────────────────

    fn scan_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.scan.json", id))
    }
    fn findings_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.findings.json", id))
    }
    fn assets_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{}.assets.json", id))
    }

    // ── Scans ────────────────────────────────────────────────────────────────

    pub fn create_scan(&self, config: &ScanConfig) -> Result<Scan> {
        let scan = Scan {
            id: Uuid::new_v4().to_string(),
            target: config.target.clone(),
            target_type: config.target_type.clone(),
            scope: config.scope.clone(),
            status: "pending".to_string(),
            stealth_mode: config.stealth_mode,
            tools_used: config.tools.clone(),
            created_at: Utc::now().to_rfc3339(),
            completed_at: None,
            finding_count: 0,
        };
        self.write_json(&self.scan_path(&scan.id), &scan)?;
        // Init empty findings and assets files
        self.write_json(&self.findings_path(&scan.id), &Vec::<VulnFinding>::new())?;
        self.write_json(&self.assets_path(&scan.id), &Vec::<DiscoveredAsset>::new())?;
        Ok(scan)
    }

    pub fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
        let path = self.scan_path(id);
        if !path.exists() { return Ok(None); }
        let mut scan: Scan = self.read_json(&path)?;
        scan.finding_count = self.list_findings(id).map(|f| f.len()).unwrap_or(0);
        Ok(Some(scan))
    }

    pub fn list_scans(&self) -> Result<Vec<Scan>> {
        let mut scans: Vec<Scan> = std::fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".scan.json"))
            .filter_map(|e| self.read_json::<Scan>(&e.path()).ok())
            .map(|mut s| {
                s.finding_count = self.list_findings(&s.id).map(|f| f.len()).unwrap_or(0);
                s
            })
            .collect();
        scans.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(scans)
    }

    pub fn update_scan_status(&self, id: &str, status: &str) -> Result<()> {
        if let Some(mut scan) = self.get_scan(id)? {
            scan.status = status.to_string();
            if status == "complete" || status == "stopped" {
                scan.completed_at = Some(Utc::now().to_rfc3339());
            }
            self.write_json(&self.scan_path(id), &scan)?;
        }
        Ok(())
    }

    pub fn delete_scan(&self, id: &str) -> Result<()> {
        for path in [self.scan_path(id), self.findings_path(id), self.assets_path(id)] {
            if path.exists() { std::fs::remove_file(path)?; }
        }
        Ok(())
    }

    // ── Findings ─────────────────────────────────────────────────────────────

    pub fn add_finding(&self, scan_id: &str, raw: &RawFinding, in_scope: bool) -> Result<VulnFinding> {
        let finding = VulnFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            source_tool: raw.source_tool.clone(),
            severity: raw.severity.clone(),
            title: raw.title.clone(),
            description: raw.description.clone(),
            affected_url: raw.affected_url.clone(),
            affected_port: raw.affected_port,
            cve_references: raw.cve_references.clone(),
            cvss_score: raw.cvss_score,
            evidence: raw.evidence.clone(),
            remediation: raw.remediation.clone(),
            timestamp: Utc::now().to_rfc3339(),
            in_scope,
            http_request: raw.http_request.clone(),
            http_response: raw.http_response.clone(),
        };

        let mut findings = self.list_findings(scan_id).unwrap_or_default();
        findings.push(finding.clone());
        self.write_json(&self.findings_path(scan_id), &findings)?;
        Ok(finding)
    }

    pub fn list_findings(&self, scan_id: &str) -> Result<Vec<VulnFinding>> {
        let path = self.findings_path(scan_id);
        if !path.exists() { return Ok(vec![]); }
        let mut findings: Vec<VulnFinding> = self.read_json(&path)?;
        findings.sort_by_key(|f| match f.severity.as_str() {
            "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4,
        });
        Ok(findings)
    }

    pub fn list_all_findings(&self) -> Result<Vec<VulnFinding>> {
        let scans = self.list_scans()?;
        let mut all = Vec::new();
        for scan in scans {
            if let Ok(findings) = self.list_findings(&scan.id) {
                all.extend(findings);
            }
        }
        Ok(all)
    }

    pub fn delete_finding(&self, finding_id: &str) -> Result<()> {
        // Search all scan finding files for this finding id
        for entry in std::fs::read_dir(&self.dir)?.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".findings.json") {
                let mut findings: Vec<VulnFinding> = self.read_json(&entry.path()).unwrap_or_default();
                let before = findings.len();
                findings.retain(|f| f.id != finding_id);
                if findings.len() != before {
                    self.write_json(&entry.path(), &findings)?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    // ── Assets ───────────────────────────────────────────────────────────────

    pub fn add_asset(
        &self, scan_id: &str, asset_type: &str, value: &str,
        ip: Option<&str>, http_status: Option<i64>,
        page_title: Option<&str>, tech_stack: Vec<String>,
        parent: Option<&str>, in_scope: bool,
    ) -> Result<DiscoveredAsset> {
        let asset = DiscoveredAsset {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            asset_type: asset_type.to_string(),
            value: value.to_string(),
            ip: ip.map(str::to_string),
            http_status,
            page_title: page_title.map(str::to_string),
            tech_stack,
            parent: parent.map(str::to_string),
            in_scope,
            discovered_at: Utc::now().to_rfc3339(),
        };

        let mut assets = self.list_assets(scan_id).unwrap_or_default();
        assets.push(asset.clone());
        self.write_json(&self.assets_path(scan_id), &assets)?;
        Ok(asset)
    }

    pub fn list_assets(&self, scan_id: &str) -> Result<Vec<DiscoveredAsset>> {
        let path = self.assets_path(scan_id);
        if !path.exists() { return Ok(vec![]); }
        self.read_json(&path)
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn write_json<T: serde::Serialize>(&self, path: &Path, data: &T) -> Result<()> {
        let json = serde_json::to_string_pretty(data)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn read_json<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read {}: {}", path.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse {}: {}", path.display(), e))
    }
}

impl Store {
    /// Return a lightweight handle pointing at the same directory.
    pub fn clone_ref(&self) -> Store {
        Store { dir: self.dir.clone() }
    }
}
