// src-tauri/src/scanner/runner.rs
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use anyhow::{Result, anyhow};
use tauri::{AppHandle, Emitter};
use crate::db::models::ScanProgress;

pub struct SubprocessRunner {
    app_handle: AppHandle,
    scan_id: String,
}

impl SubprocessRunner {
    pub fn new(app_handle: AppHandle, scan_id: String) -> Self {
        Self { app_handle, scan_id }
    }

    /// Run a command and stream stdout/stderr lines back via Tauri events.
    /// Returns the full concatenated stdout when the process exits.
    pub async fn run(
        &self,
        tool: &str,
        args: &[&str],
        working_dir: Option<&str>,
    ) -> Result<String> {
        tracing::info!("Spawning {} {:?}", tool, args);

        self.emit_progress(tool, 0.0, &format!("[{}] Starting...", tool), "info");

        let mut cmd = Command::new(tool);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }

        let mut child = cmd.spawn()
            .map_err(|e| anyhow!("Failed to spawn {}: {}", tool, e))?;

        let stdout = child.stdout.take()
            .ok_or_else(|| anyhow!("No stdout from {}", tool))?;
        let stderr = child.stderr.take()
            .ok_or_else(|| anyhow!("No stderr from {}", tool))?;

        let mut stdout_lines = BufReader::new(stdout).lines();
        let mut stderr_lines = BufReader::new(stderr).lines();
        let mut full_output = String::new();

        // Drain stdout and stderr concurrently
        loop {
            tokio::select! {
                line = stdout_lines.next_line() => {
                    match line {
                        Ok(Some(l)) => {
                            full_output.push_str(&l);
                            full_output.push('\n');
                            self.emit_progress(tool, -1.0, &format!("[{}] {}", tool, l), "info");
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::warn!("stdout read error: {}", e);
                            break;
                        }
                    }
                }
                line = stderr_lines.next_line() => {
                    match line {
                        Ok(Some(l)) if !l.is_empty() => {
                            self.emit_progress(tool, -1.0, &format!("[{}] {}", tool, l), "warn");
                        }
                        _ => {}
                    }
                }
            }
        }

        let status = child.wait().await?;

        if status.success() {
            self.emit_progress(tool, 100.0, &format!("[{}] Completed", tool), "ok");
        } else {
            let code = status.code().unwrap_or(-1);
            self.emit_progress(
                tool, 100.0,
                &format!("[{}] Exited with code {}", tool, code),
                "warn",
            );
        }

        Ok(full_output)
    }

    pub fn emit_progress(&self, tool: &str, percent: f32, message: &str, level: &str) {
        let _ = self.app_handle.emit(
            "scan_progress",
            ScanProgress {
                scan_id: self.scan_id.clone(),
                tool: tool.to_string(),
                percent,
                message: message.to_string(),
                level: level.to_string(),
            },
        );
    }

    pub fn emit_finding(&self, finding: &crate::db::models::VulnFinding) {
        let _ = self.app_handle.emit("scan_finding", finding);
    }

    pub fn emit_asset(&self, asset: &crate::db::models::DiscoveredAsset) {
        let _ = self.app_handle.emit("scan_asset", asset);
    }
}
