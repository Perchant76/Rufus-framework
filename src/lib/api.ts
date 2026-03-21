// src/lib/api.ts
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  Scan, ScanConfig, VulnFinding, ToolStatus,
  ScanProgress, ScanComparison, DiscoveredAsset,
} from "../types";

// ── Scans ─────────────────────────────────────────────────────────────────────
export const createScan = (config: ScanConfig): Promise<Scan> =>
  invoke("create_scan", { config });

export const getScans = (): Promise<Scan[]> =>
  invoke("get_scans");

export const getScan = (scanId: string): Promise<Scan | null> =>
  invoke("get_scan", { scanId });

export const deleteScan = (scanId: string): Promise<void> =>
  invoke("delete_scan", { scanId });

export const startScan = (config: ScanConfig): Promise<string> =>
  invoke("start_scan", { config });

export const stopScan = (): Promise<void> =>
  invoke("stop_scan");

// ── Findings ──────────────────────────────────────────────────────────────────
export const getFindings = (): Promise<VulnFinding[]> =>
  invoke("get_findings");

export const getFindingsForScan = (scanId: string): Promise<VulnFinding[]> =>
  invoke("get_findings_for_scan", { scanId });

export const getFinding = (findingId: string): Promise<VulnFinding | null> =>
  invoke("get_finding", { findingId });

export const deleteFinding = (findingId: string): Promise<void> =>
  invoke("delete_finding", { findingId });

// ── Tools ─────────────────────────────────────────────────────────────────────
export const checkAllTools = (): Promise<ToolStatus[]> =>
  invoke("check_all_tools");

export const checkTool = (name: string): Promise<ToolStatus> =>
  invoke("check_tool_availability", { name });

// ── Comparison ────────────────────────────────────────────────────────────────
export const compareScans = (scanAId: string, scanBId: string): Promise<ScanComparison> =>
  invoke("compare_scans", { scanAId, scanBId });

// ── Export ────────────────────────────────────────────────────────────────────
export const exportPdf = (scanId: string, outputPath: string): Promise<string> =>
  invoke("export_pdf", { scanId, outputPath });

export const exportCsv = (scanId: string, outputPath: string): Promise<string> =>
  invoke("export_csv", { scanId, outputPath });

export const exportBurp = (scanId: string, outputPath: string): Promise<string> =>
  invoke("export_burp", { scanId, outputPath });

export const exportCaido = (scanId: string, outputPath: string): Promise<string> =>
  invoke("export_caido", { scanId, outputPath });

// ── Event listeners ───────────────────────────────────────────────────────────
export const onScanProgress = (cb: (p: ScanProgress) => void): Promise<UnlistenFn> =>
  listen<ScanProgress>("scan_progress", (e) => cb(e.payload));

export const onScanFinding = (cb: (f: VulnFinding) => void): Promise<UnlistenFn> =>
  listen<VulnFinding>("scan_finding", (e) => cb(e.payload));

export const onScanAsset = (cb: (a: DiscoveredAsset) => void): Promise<UnlistenFn> =>
  listen<DiscoveredAsset>("scan_asset", (e) => cb(e.payload));
