// src/types/index.ts

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScanStatus = "pending" | "running" | "complete" | "stopped";
export type TargetType = "DOMAIN" | "IP";
export type AuthMode = "none" | "form" | "cookie" | "bearer" | "basic";

export interface VulnFinding {
  id: string;
  scan_id: string;
  source_tool: string;
  severity: Severity;
  title: string;
  description: string;
  affected_url: string;
  affected_port: number | null;
  cve_references: string[];   // native array — no JSON parsing needed
  cvss_score: number | null;
  evidence: string;
  remediation: string;
  timestamp: string;
  in_scope: boolean;
  http_request: string | null;
  http_response: string | null;
}

export interface Scan {
  id: string;
  target: string;
  target_type: TargetType;
  scope: string[];            // native array
  status: ScanStatus;
  stealth_mode: boolean;
  tools_used: string[];       // native array
  created_at: string;
  completed_at: string | null;
  finding_count: number;
}

export interface DiscoveredAsset {
  id: string;
  scan_id: string;
  asset_type: "subdomain" | "endpoint" | "port" | "form";
  value: string;
  ip: string | null;
  http_status: number | null;
  page_title: string | null;
  tech_stack: string[];       // native array
  parent: string | null;
  in_scope: boolean;
  discovered_at: string;
}

export interface ToolStatus {
  name: string;
  available: boolean;
  version: string | null;
  path: string | null;
  install_cmd: string;
}

export interface ScanProgress {
  scan_id: string;
  tool: string;
  percent: number;
  message: string;
  level: "info" | "warn" | "error" | "ok";
}

export interface AuthConfig {
  mode: AuthMode;
  login_url?: string;
  username?: string;
  password?: string;
  cookie_string?: string;
  bearer_token?: string;
  custom_headers?: [string, string][];
}

export interface ScanConfig {
  target: string;
  target_type: TargetType;
  scope: string[];
  stealth_mode: boolean;
  concurrency: number;
  delay_min_ms: number;
  delay_max_ms: number;
  tools: string[];
  auth: AuthConfig | null;
  respect_robots: boolean;
  wordlist_id?: string | null;
  nuclei_profile_id?: string | null;
}

export interface PersistentFinding {
  title: string;
  severity: Severity;
  scan_count: number;
  is_chronic: boolean;
  first_seen: string;
  findings: VulnFinding[];
}

export interface ScanComparison {
  scan_a: Scan;
  scan_b: Scan;
  new_findings: VulnFinding[];
  resolved_finding_titles: string[];
  persistent_findings: PersistentFinding[];
}

export const SEV_ORDER: Record<Severity, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

// No longer needed — cve_references is now a native array from Rust
export function parseCVEs(raw: string | string[]): string[] {
  if (Array.isArray(raw)) return raw;
  try { return JSON.parse(raw) ?? []; } catch { return []; }
}

export function parseTechStack(raw: string | string[] | null): string[] {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try { return JSON.parse(raw) ?? []; } catch { return []; }
}

export const ALL_TOOLS = [
  { name: "subfinder",   category: "Subdomain Enum",  install: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", domain: true,  ip: false },
  { name: "feroxbuster", category: "Dir Brute-force",  install: "cargo install feroxbuster",                                                  domain: true,  ip: false },
  { name: "katana",      category: "Web Crawler",      install: "go install github.com/projectdiscovery/katana/cmd/katana@latest",            domain: true,  ip: false },
  { name: "nmap",        category: "Port Scanner",     install: "apt install nmap / brew install nmap",                                       domain: true,  ip: true  },
  { name: "nuclei",      category: "Vuln Scanner",     install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",         domain: true,  ip: true  },
  { name: "testssl.sh",  category: "TLS Analyzer",     install: "brew install testssl / apt install testssl.sh",                              domain: true,  ip: false },
  { name: "wapiti3",     category: "Web Vuln Scanner", install: "pip install wapiti3",                                                        domain: true,  ip: false },
  { name: "whatweb",     category: "Tech Fingerprint", install: "apt install whatweb / gem install whatweb",                                  domain: true,  ip: true  },
] as const;

// ── New types ─────────────────────────────────────────────────────────────────

export interface BugBountyProgram {
  id: string;
  name: string;
  program_type: "company" | "wildcard" | "url";
  platform: string;
  in_scope: string[];
  out_of_scope: string[];
  max_bounty?: number;
  notes: string;
  scan_ids: string[];
  created_at: string;
}

export interface WorkflowStage {
  name: string;
  description: string;
  why: string;
  tools: string[];
  status: "locked" | "ready" | "running" | "complete" | "skipped";
  findings_count: number;
  completed_at: string | null;
}

export interface WorkflowRun {
  id: string;
  workflow_type: string;
  target: string;
  current_stage: number;
  stages: WorkflowStage[];
  created_at: string;
}

export interface Wordlist {
  id: string;
  name: string;
  tag: string;
  word_count: number;
  source: string;
  created_at: string;
}

export interface NucleiProfile {
  id: string;
  name: string;
  selected_tags: string[];
  selected_severities: string[];
  exclude_tags: string[];
  created_at: string;
}

export interface SavedRequest {
  id: string;
  name: string;
  method: string;
  url: string;
  headers: [string, string][];
  body?: string;
  created_at: string;
}

export interface HttpResponse {
  status: number;
  status_text: string;
  headers: [string, string][];
  body: string;
  duration_ms: number;
  redirect_chain: string[];
}

export interface OsintResult {
  id: string;
  scan_id: string | null;
  source: string;
  query: string;
  result_count: number | null;
  url: string;
  notes: string;
  severity: string;
  created_at: string;
}

export interface CloudAsset {
  id: string;
  scan_id: string;
  provider: string;
  url: string;
  status: number;
  accessible: boolean;
  takeover_candidate: boolean;
  checked_at: string;
}
