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
  cve_references: string; // JSON string from DB — parse before use
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
  scope: string; // JSON string
  status: ScanStatus;
  stealth_mode: boolean;
  auth_config: string | null;
  rate_config: string | null;
  tools_used: string | null;
  created_at: string;
  completed_at: string | null;
  duration_secs: number | null;
  finding_count: number | null;
}

export interface DiscoveredAsset {
  id: string;
  scan_id: string;
  asset_type: "subdomain" | "endpoint" | "port" | "form";
  value: string;
  ip: string | null;
  http_status: number | null;
  page_title: string | null;
  tech_stack: string | null; // JSON string
  redirect_chain: string | null;
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

export interface RateConfig {
  concurrency: number;
  delay_min_ms: number;
  delay_max_ms: number;
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

// Helper to parse cve_references from DB string to array
export function parseCVEs(raw: string): string[] {
  try { return JSON.parse(raw) ?? []; } catch { return []; }
}

// Helper to parse tech_stack
export function parseTechStack(raw: string | null): string[] {
  if (!raw) return [];
  try { return JSON.parse(raw) ?? []; } catch { return []; }
}

export const SEV_ORDER: Record<Severity, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

export const ALL_TOOLS = [
  { name: "subfinder",   category: "Subdomain Enum",   install: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", domain: true,  ip: false },
  { name: "feroxbuster", category: "Dir Brute-force",   install: "cargo install feroxbuster", domain: true,  ip: false },
  { name: "katana",      category: "Web Crawler",       install: "go install github.com/projectdiscovery/katana/cmd/katana@latest", domain: true,  ip: false },
  { name: "nmap",        category: "Port Scanner",      install: "apt install nmap", domain: true,  ip: true  },
  { name: "nuclei",      category: "Vuln Scanner",      install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", domain: true,  ip: true  },
  { name: "testssl.sh",  category: "TLS Analyzer",      install: "brew install testssl", domain: true,  ip: false },
  { name: "wapiti3",     category: "Web Vuln Scanner",  install: "pip install wapiti3", domain: true,  ip: false },
  { name: "whatweb",     category: "Tech Fingerprint",  install: "apt install whatweb", domain: true,  ip: true  },
] as const;
