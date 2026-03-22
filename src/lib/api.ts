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

// ── Programs ──────────────────────────────────────────────────────────────────
export const createProgram = (program: any): Promise<any> => invoke("create_program", { program });
export const listPrograms = (): Promise<any[]> => invoke("list_programs");
export const updateProgram = (program: any): Promise<any> => invoke("update_program", { program });
export const deleteProgram = (id: string): Promise<void> => invoke("delete_program", { id });
export const linkScanToProgram = (programId: string, scanId: string): Promise<void> => invoke("link_scan_to_program", { programId, scanId });

// ── Workflows ─────────────────────────────────────────────────────────────────
export const createWorkflow = (workflowType: string, target: string): Promise<any> => invoke("create_workflow", { workflowType, target });
export const listWorkflows = (): Promise<any[]> => invoke("list_workflows");
export const updateWorkflow = (workflow: any): Promise<any> => invoke("update_workflow", { workflow });
export const deleteWorkflow = (id: string): Promise<void> => invoke("delete_workflow", { id });

// ── Wordlists ─────────────────────────────────────────────────────────────────
export const listWordlists = (): Promise<any[]> => invoke("list_wordlists");
export const importWordlist = (name: string, tag: string, content: string): Promise<any> => invoke("import_wordlist", { name, tag, content });
export const deleteWordlist = (id: string): Promise<void> => invoke("delete_wordlist", { id });
export const getWordlistContent = (id: string): Promise<string[]> => invoke("get_wordlist_content", { id });

// ── Nuclei Profiles ───────────────────────────────────────────────────────────
export const listNucleiProfiles = (): Promise<any[]> => invoke("list_nuclei_profiles");
export const saveNucleiProfile = (profile: any): Promise<any> => invoke("save_nuclei_profile", { profile });
export const deleteNucleiProfile = (id: string): Promise<void> => invoke("delete_nuclei_profile", { id });

// ── HTTP Replay ───────────────────────────────────────────────────────────────
export const sendHttpRequest = (method: string, url: string, headers: [string,string][], body: string|null, followRedirects: boolean, timeoutSecs: number): Promise<any> =>
  invoke("send_http_request", { method, url, headers, body, followRedirects, timeoutSecs });
export const listSavedRequests = (): Promise<any[]> => invoke("list_saved_requests");
export const saveRequest = (request: any): Promise<any> => invoke("save_request", { request });
export const deleteSavedRequest = (id: string): Promise<void> => invoke("delete_saved_request", { id });

// ── OSINT ─────────────────────────────────────────────────────────────────────
export const getDorkTemplates = (target: string): Promise<[string,string][]> => invoke("get_dork_templates", { target });
export const openDorkInBrowser = (query: string): Promise<void> => invoke("open_dork_in_browser", { query });
export const listOsintResults = (): Promise<any[]> => invoke("list_osint_results");
export const addOsintResult = (result: any): Promise<any> => invoke("add_osint_result", { result });
export const updateOsintNotes = (id: string, notes: string): Promise<void> => invoke("update_osint_notes", { id, notes });

// ── Cloud ─────────────────────────────────────────────────────────────────────
export const enumerateCloudAssets = (target: string, scanId: string): Promise<any[]> => invoke("enumerate_cloud_assets", { target, scanId });
export const listCloudAssets = (scanId: string): Promise<any[]> => invoke("list_cloud_assets", { scanId });
export const checkTakeover = (subdomains: string[]): Promise<any[]> => invoke("check_takeover", { subdomains });

// ── Triage ────────────────────────────────────────────────────────────────────
export const updateFindingTriage = (finding: any): Promise<void> => invoke("update_finding_triage", { finding });

// ── JS Secret Scanner ─────────────────────────────────────────────────────────
export const scanJsForSecrets = (scanId: string, jsUrls: string[]) =>
  invoke("scan_js_for_secrets", { scanId, jsUrls });

// ── Header & CORS ─────────────────────────────────────────────────────────────
export const checkSecurityHeaders = (scanId: string, urls: string[]) =>
  invoke("check_security_headers", { scanId, urls });

// ── Phase Control ─────────────────────────────────────────────────────────────
export const getPhaseStatus = () => invoke("get_phase_status");
export const pauseScan      = () => invoke("pause_scan");
export const resumeScan     = () => invoke("resume_scan");
export const skipPhase      = (phaseId: number) => invoke("skip_phase", { phaseId });
export const getAllPhaseStatuses = () => invoke("get_all_phase_statuses");

// ── Session Persistence ───────────────────────────────────────────────────────
export const saveScanSession      = (scanId: string, currentPhase: number, completedPhases: number[]) =>
  invoke("save_scan_session", { scanId, currentPhase, completedPhases });
export const loadScanSession      = (scanId: string) => invoke("load_scan_session", { scanId });
export const listInterruptedScans = () => invoke("list_interrupted_scans");
export const clearScanSession     = (scanId: string) => invoke("clear_scan_session", { scanId });

// ── PenForge Export ───────────────────────────────────────────────────────────
export const exportToPtsync = (scanId: string, operatorName: string, outputPath: string, severityFilter: string[]) =>
  invoke("export_to_ptsync", { scanId, operatorName, outputPath, severityFilter });
export const getPtsyncPreview = (scanId: string) =>
  invoke("get_ptsync_preview", { scanId });
