// src-tauri/src/db/store.rs
use std::path::{Path, PathBuf};
use anyhow::{Result, anyhow};
use chrono::Utc;
use uuid::Uuid;
use crate::db::models::*;

pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn clone_ref(&self) -> Store {
        Store { dir: self.dir.clone() }
    }

    // ── Internal path helpers ─────────────────────────────────────────────────

    fn scan_path(&self, id: &str) -> PathBuf         { self.dir.join(format!("{}.scan.json", id)) }
    fn findings_path(&self, id: &str) -> PathBuf     { self.dir.join(format!("{}.findings.json", id)) }
    fn assets_path(&self, id: &str) -> PathBuf       { self.dir.join(format!("{}.assets.json", id)) }
    fn programs_path(&self) -> PathBuf               { self.dir.join("programs.json") }
    fn workflows_path(&self) -> PathBuf              { self.dir.join("workflows.json") }
    fn wordlists_meta_path(&self) -> PathBuf         { self.dir.join("wordlists.json") }
    fn wordlist_path(&self, id: &str) -> PathBuf     { self.dir.join(format!("wl_{}.txt", id)) }
    fn nuclei_profiles_path(&self) -> PathBuf        { self.dir.join("nuclei_profiles.json") }
    fn saved_requests_path(&self) -> PathBuf         { self.dir.join("saved_requests.json") }
    fn osint_path(&self) -> PathBuf                  { self.dir.join("osint_results.json") }
    fn cloud_assets_path(&self, scan_id: &str) -> PathBuf {
        self.dir.join(format!("{}.cloud.json", scan_id))
    }

    // ── JSON helpers ──────────────────────────────────────────────────────────

    fn write_json<T: serde::Serialize + ?Sized>(&self, path: &Path, data: &T) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(data)?)?;
        Ok(())
    }

    fn read_json<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Read {}: {}", path.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow!("Parse {}: {}", path.display(), e))
    }

    fn read_json_or_default<T: serde::de::DeserializeOwned + Default>(&self, path: &Path) -> T {
        if !path.exists() { return T::default(); }
        self.read_json(path).unwrap_or_default()
    }

    // ── Scans ─────────────────────────────────────────────────────────────────

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
        for path in [
            self.scan_path(id), self.findings_path(id),
            self.assets_path(id), self.cloud_assets_path(id),
        ] {
            if path.exists() { std::fs::remove_file(path)?; }
        }
        Ok(())
    }

    // ── Findings ──────────────────────────────────────────────────────────────

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
            triage_status: "new".to_string(),
            priority_override: None,
            analyst_notes: String::new(),
            reproduction_steps: String::new(),
            cvss_vector: None,
            reported_at: None,
        };
        let mut findings = self.list_findings(scan_id).unwrap_or_default();
        findings.push(finding.clone());
        self.write_json(&self.findings_path(scan_id), &findings)?;
        Ok(finding)
    }

    pub fn update_finding(&self, finding: &VulnFinding) -> Result<()> {
        let mut findings = self.list_findings(&finding.scan_id).unwrap_or_default();
        if let Some(pos) = findings.iter().position(|f| f.id == finding.id) {
            findings[pos] = finding.clone();
            self.write_json(&self.findings_path(&finding.scan_id), &findings)?;
        }
        Ok(())
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
            if let Ok(f) = self.list_findings(&scan.id) { all.extend(f); }
        }
        Ok(all)
    }

    pub fn delete_finding(&self, finding_id: &str) -> Result<()> {
        for entry in std::fs::read_dir(&self.dir)?.filter_map(|e| e.ok()) {
            if !entry.file_name().to_string_lossy().ends_with(".findings.json") { continue; }
            let mut findings: Vec<VulnFinding> = self.read_json(&entry.path()).unwrap_or_default();
            let before = findings.len();
            findings.retain(|f| f.id != finding_id);
            if findings.len() != before {
                self.write_json(&entry.path(), &findings)?;
                return Ok(());
            }
        }
        Ok(())
    }

    // ── Assets ────────────────────────────────────────────────────────────────

    pub fn add_asset(
        &self, scan_id: &str, asset_type: &str, value: &str,
        ip: Option<&str>, http_status: Option<i64>, page_title: Option<&str>,
        tech_stack: Vec<String>, parent: Option<&str>, in_scope: bool,
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

    // ── Bug Bounty Programs ───────────────────────────────────────────────────

    pub fn create_program(&self, mut p: BugBountyProgram) -> Result<BugBountyProgram> {
        p.id = Uuid::new_v4().to_string();
        p.created_at = Utc::now().to_rfc3339();
        let mut programs = self.list_programs().unwrap_or_default();
        programs.push(p.clone());
        self.write_json(&self.programs_path(), &programs)?;
        Ok(p)
    }

    pub fn list_programs(&self) -> Result<Vec<BugBountyProgram>> {
        Ok(self.read_json_or_default(&self.programs_path()))
    }

    pub fn update_program(&self, updated: BugBountyProgram) -> Result<BugBountyProgram> {
        let mut programs = self.list_programs().unwrap_or_default();
        if let Some(pos) = programs.iter().position(|p| p.id == updated.id) {
            programs[pos] = updated.clone();
            self.write_json(&self.programs_path(), &programs)?;
        }
        Ok(updated)
    }

    pub fn delete_program(&self, id: &str) -> Result<()> {
        let mut programs = self.list_programs().unwrap_or_default();
        programs.retain(|p| p.id != id);
        self.write_json(&self.programs_path(), &programs)
    }

    pub fn link_scan_to_program(&self, program_id: &str, scan_id: &str) -> Result<()> {
        let mut programs = self.list_programs().unwrap_or_default();
        if let Some(p) = programs.iter_mut().find(|p| p.id == program_id) {
            if !p.scan_ids.contains(&scan_id.to_string()) {
                p.scan_ids.push(scan_id.to_string());
            }
        }
        self.write_json(&self.programs_path(), &programs)
    }

    // ── Workflows ─────────────────────────────────────────────────────────────

    pub fn create_workflow(&self, mut w: WorkflowRun) -> Result<WorkflowRun> {
        w.id = Uuid::new_v4().to_string();
        w.created_at = Utc::now().to_rfc3339();
        let mut workflows: Vec<WorkflowRun> = self.read_json_or_default(&self.workflows_path());
        workflows.push(w.clone());
        self.write_json(&self.workflows_path(), &workflows)?;
        Ok(w)
    }

    pub fn list_workflows(&self) -> Result<Vec<WorkflowRun>> {
        Ok(self.read_json_or_default(&self.workflows_path()))
    }

    pub fn update_workflow(&self, updated: WorkflowRun) -> Result<WorkflowRun> {
        let mut workflows: Vec<WorkflowRun> = self.read_json_or_default(&self.workflows_path());
        if let Some(pos) = workflows.iter().position(|w| w.id == updated.id) {
            workflows[pos] = updated.clone();
        }
        self.write_json(&self.workflows_path(), &workflows)?;
        Ok(updated)
    }

    pub fn delete_workflow(&self, id: &str) -> Result<()> {
        let mut workflows: Vec<WorkflowRun> = self.read_json_or_default(&self.workflows_path());
        workflows.retain(|w| w.id != id);
        self.write_json(&self.workflows_path(), &workflows)
    }

    // ── Wordlists ─────────────────────────────────────────────────────────────

    pub fn list_wordlists(&self) -> Result<Vec<Wordlist>> {
        Ok(self.read_json_or_default(&self.wordlists_meta_path()))
    }

    pub fn import_wordlist(&self, name: String, tag: String, content: String) -> Result<Wordlist> {
        let id = Uuid::new_v4().to_string();
        let word_count = content.lines().filter(|l| !l.is_empty()).count();
        std::fs::write(self.wordlist_path(&id), &content)?;
        let wl = Wordlist { id, name, tag, word_count, source: "imported".to_string(),
            created_at: Utc::now().to_rfc3339() };
        let mut list = self.list_wordlists().unwrap_or_default();
        list.push(wl.clone());
        self.write_json(&self.wordlists_meta_path(), &list)?;
        Ok(wl)
    }

    pub fn delete_wordlist(&self, id: &str) -> Result<()> {
        let p = self.wordlist_path(id);
        if p.exists() { std::fs::remove_file(p)?; }
        let mut list = self.list_wordlists().unwrap_or_default();
        list.retain(|w| w.id != id);
        self.write_json(&self.wordlists_meta_path(), &list)
    }

    pub fn get_wordlist_content(&self, id: &str) -> Result<Vec<String>> {
        let content = std::fs::read_to_string(self.wordlist_path(id))?;
        Ok(content.lines().filter(|l| !l.is_empty()).map(str::to_string).collect())
    }

    pub fn wordlist_file_path(&self, id: &str) -> PathBuf {
        self.wordlist_path(id)
    }

    // ── Nuclei Profiles ───────────────────────────────────────────────────────

    pub fn list_nuclei_profiles(&self) -> Result<Vec<NucleiProfile>> {
        Ok(self.read_json_or_default(&self.nuclei_profiles_path()))
    }

    pub fn save_nuclei_profile(&self, mut p: NucleiProfile) -> Result<NucleiProfile> {
        if p.id.is_empty() { p.id = Uuid::new_v4().to_string(); }
        if p.created_at.is_empty() { p.created_at = Utc::now().to_rfc3339(); }
        let mut profiles = self.list_nuclei_profiles().unwrap_or_default();
        if let Some(pos) = profiles.iter().position(|x| x.id == p.id) {
            profiles[pos] = p.clone();
        } else {
            profiles.push(p.clone());
        }
        self.write_json(&self.nuclei_profiles_path(), &profiles)?;
        Ok(p)
    }

    pub fn delete_nuclei_profile(&self, id: &str) -> Result<()> {
        let mut profiles = self.list_nuclei_profiles().unwrap_or_default();
        profiles.retain(|p| p.id != id);
        self.write_json(&self.nuclei_profiles_path(), &profiles)
    }

    // ── Saved HTTP Requests ───────────────────────────────────────────────────

    pub fn list_saved_requests(&self) -> Result<Vec<SavedRequest>> {
        Ok(self.read_json_or_default(&self.saved_requests_path()))
    }

    pub fn save_request(&self, mut r: SavedRequest) -> Result<SavedRequest> {
        if r.id.is_empty() { r.id = Uuid::new_v4().to_string(); }
        if r.created_at.is_empty() { r.created_at = Utc::now().to_rfc3339(); }
        let mut list = self.list_saved_requests().unwrap_or_default();
        if let Some(pos) = list.iter().position(|x| x.id == r.id) {
            list[pos] = r.clone();
        } else {
            list.push(r.clone());
        }
        self.write_json(&self.saved_requests_path(), &list)?;
        Ok(r)
    }

    pub fn delete_saved_request(&self, id: &str) -> Result<()> {
        let mut list = self.list_saved_requests().unwrap_or_default();
        list.retain(|r| r.id != id);
        self.write_json(&self.saved_requests_path(), &list)
    }

    // ── OSINT Results ─────────────────────────────────────────────────────────

    pub fn list_osint_results(&self) -> Result<Vec<OsintResult>> {
        Ok(self.read_json_or_default(&self.osint_path()))
    }

    pub fn add_osint_result(&self, mut r: OsintResult) -> Result<OsintResult> {
        r.id = Uuid::new_v4().to_string();
        r.created_at = Utc::now().to_rfc3339();
        let mut list = self.list_osint_results().unwrap_or_default();
        list.push(r.clone());
        self.write_json(&self.osint_path(), &list)?;
        Ok(r)
    }

    pub fn update_osint_notes(&self, id: &str, notes: String) -> Result<()> {
        let mut list = self.list_osint_results().unwrap_or_default();
        if let Some(r) = list.iter_mut().find(|r| r.id == id) {
            r.notes = notes;
        }
        self.write_json(&self.osint_path(), &list)
    }

    // ── Cloud Assets ──────────────────────────────────────────────────────────

    pub fn save_cloud_assets(&self, scan_id: &str, assets: &[CloudAsset]) -> Result<()> {
        self.write_json(&self.cloud_assets_path(scan_id), assets)
    }

    pub fn list_cloud_assets(&self, scan_id: &str) -> Result<Vec<CloudAsset>> {
        let path = self.cloud_assets_path(scan_id);
        if !path.exists() { return Ok(vec![]); }
        self.read_json(&path)
    }
}
