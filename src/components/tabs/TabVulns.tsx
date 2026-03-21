// src/components/tabs/TabVulns.tsx
import React, { useState, useMemo } from "react";
import {
  Card, SectionHdr, SevBadge, ScopeTag, FilterChip,
  CVEChip, Divider, Btn, StatCard,
} from "../ui";
import type { VulnFinding, Severity } from "../../types";
import { parseCVEs, SEV_ORDER } from "../../types";

interface Props {
  findings: VulnFinding[];
  scanId: string | null;
  onDelete?: (id: string) => void;
}

const SEV_ACCENTS: Record<Severity, string> = {
  CRITICAL: "var(--red)",
  HIGH: "var(--orange)",
  MEDIUM: "var(--yellow)",
  LOW: "var(--green)",
  INFO: "var(--accent)",
};

export default function TabVulns({ findings, scanId, onDelete }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(
    new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
  );
  const [scopeFilter, setScopeFilter] = useState<"all" | "in" | "out">("all");
  const [toolFilter, setToolFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"severity" | "title" | "cvss">("severity");
  const [search, setSearch] = useState("");

  const toggleSev = (s: Severity) => {
    setSevFilter(f => {
      const n = new Set(f);
      n.has(s) ? n.delete(s) : n.add(s);
      return n;
    });
  };

  const tools = useMemo(() => {
    const set = new Set(findings.map(f => f.source_tool));
    return ["all", ...Array.from(set)];
  }, [findings]);

  const counts = useMemo(() => {
    const c: Partial<Record<Severity, number>> = {};
    findings.forEach(f => { c[f.severity] = (c[f.severity] ?? 0) + 1; });
    return c;
  }, [findings]);

  const filtered = useMemo(() => {
    return findings
      .filter(f => sevFilter.has(f.severity))
      .filter(f => scopeFilter === "all" ? true : scopeFilter === "in" ? f.in_scope : !f.in_scope)
      .filter(f => toolFilter === "all" ? true : f.source_tool === toolFilter)
      .filter(f => !search || f.title.toLowerCase().includes(search.toLowerCase()) || f.affected_url.toLowerCase().includes(search.toLowerCase()))
      .sort((a, b) => {
        if (sortBy === "severity") return SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
        if (sortBy === "title") return a.title.localeCompare(b.title);
        if (sortBy === "cvss") return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
        return 0;
      });
  }, [findings, sevFilter, scopeFilter, toolFilter, sortBy, search]);

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>

      {/* Stat row */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {(["CRITICAL","HIGH","MEDIUM","LOW","INFO"] as Severity[]).map(s => (
          <div key={s} style={{ flex: 1 }} onClick={() => toggleSev(s)}>
            <StatCard
              num={counts[s] ?? 0}
              label={s}
              color={sevFilter.has(s) ? SEV_ACCENTS[s] : "var(--text-dim)"}
            />
          </div>
        ))}
      </div>

      {/* Filter bar */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
        <span style={{ fontSize: 10, color: "var(--text-dim)" }}>SEV:</span>
        {(["CRITICAL","HIGH","MEDIUM","LOW","INFO"] as Severity[]).map(s => (
          <FilterChip key={s} label={s} active={sevFilter.has(s)}
            onClick={() => toggleSev(s)} accentColor={SEV_ACCENTS[s]} />
        ))}
        <Divider />
        {(["all","in","out"] as const).map(v => (
          <FilterChip key={v} label={v === "all" ? "All" : v === "in" ? "In-Scope" : "OOS"}
            active={scopeFilter === v} onClick={() => setScopeFilter(v)} />
        ))}
        <Divider />
        <span style={{ fontSize: 10, color: "var(--text-dim)" }}>Tool:</span>
        <select
          value={toolFilter}
          onChange={e => setToolFilter(e.target.value)}
          style={{
            background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)",
            fontFamily: "var(--font-mono)", fontSize: 11, borderRadius: "var(--r)",
            padding: "4px 8px", outline: "none",
          }}
        >
          {tools.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <Divider />
        <span style={{ fontSize: 10, color: "var(--text-dim)" }}>Sort:</span>
        {(["severity","title","cvss"] as const).map(s => (
          <FilterChip key={s} label={s} active={sortBy === s} onClick={() => setSortBy(s)} />
        ))}
        <div style={{ marginLeft: "auto" }}>
          <input
            placeholder="Search…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)",
              fontFamily: "var(--font-mono)", fontSize: 11, borderRadius: "var(--r)",
              padding: "4px 10px", outline: "none", width: 180,
            }}
          />
        </div>
        <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{filtered.length} findings</span>
      </div>

      {/* Table */}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        {/* Header */}
        <div style={{
          display: "grid", gridTemplateColumns: "96px 1fr 130px 60px 120px 32px",
          gap: 12, padding: "8px 14px",
          borderBottom: "1px solid var(--border)",
          fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px",
        }}>
          <span>Severity</span><span>Title</span><span>Tool</span><span>CVSS</span><span>Scope</span><span/>
        </div>

        {filtered.length === 0 && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: 200, color: "var(--text-dim)", gap: 8 }}>
            <span style={{ fontSize: 36, opacity: .3 }}>🔍</span>
            <span style={{ fontSize: 12 }}>No findings match current filters</span>
          </div>
        )}

        {filtered.map(f => {
          const cves = Array.isArray(f.cve_references) ? f.cve_references : parseCVEs(f.cve_references as unknown as string);
          const isExp = expanded === f.id;
          return (
            <React.Fragment key={f.id}>
              {/* Row */}
              <div
                onClick={() => setExpanded(isExp ? null : f.id)}
                style={{
                  display: "grid", gridTemplateColumns: "96px 1fr 130px 60px 120px 32px",
                  alignItems: "center", gap: 12,
                  padding: "10px 14px",
                  borderBottom: "1px solid var(--border)",
                  cursor: "pointer", transition: "background .1s",
                  background: isExp ? "var(--bg2)" : undefined,
                  animation: "fade-in .2s ease",
                }}
                onMouseEnter={e => { if (!isExp) (e.currentTarget as HTMLDivElement).style.background = "var(--bg2)"; }}
                onMouseLeave={e => { if (!isExp) (e.currentTarget as HTMLDivElement).style.background = ""; }}
              >
                <SevBadge sev={f.severity} />
                <div>
                  <div style={{ fontSize: 12, color: "var(--text-hi)", marginBottom: 2 }}>{f.title}</div>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>{f.affected_url}</div>
                </div>
                <span style={{ fontSize: 11, color: "var(--purple)" }}>{f.source_tool}</span>
                <span style={{
                  fontSize: 12, fontWeight: 700,
                  color: (f.cvss_score ?? 0) >= 9 ? "var(--red)" : (f.cvss_score ?? 0) >= 7 ? "var(--orange)" : "var(--text-dim)"
                }}>
                  {f.cvss_score?.toFixed(1) ?? "—"}
                </span>
                <ScopeTag inScope={f.in_scope} />
                <span style={{ color: "var(--text-dim)", fontSize: 12 }}>{isExp ? "▲" : "▼"}</span>
              </div>

              {/* Expanded detail */}
              {isExp && (
                <div style={{
                  padding: "16px 16px", background: "var(--bg0)",
                  borderBottom: "1px solid var(--border)",
                  animation: "slide-in .15s ease",
                }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
                    {/* Left */}
                    <div>
                      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 6 }}>Description</div>
                      <p style={{ fontSize: 12, color: "var(--text)", lineHeight: 1.6, marginBottom: 14 }}>{f.description || "No description provided."}</p>

                      {cves.length > 0 && (
                        <>
                          <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 6 }}>CVE References</div>
                          <div style={{ marginBottom: 14 }}>{cves.map(c => <CVEChip key={c} cve={c} />)}</div>
                        </>
                      )}

                      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 6 }}>Evidence</div>
                      <pre style={{
                        background: "var(--bg1)", border: "1px solid var(--border)",
                        borderRadius: "var(--r)", padding: "8px 10px",
                        fontSize: 11, color: "var(--green)", overflowX: "auto",
                        whiteSpace: "pre-wrap", wordBreak: "break-all",
                      }}>{f.evidence || "No evidence captured."}</pre>
                    </div>

                    {/* Right */}
                    <div>
                      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 6 }}>Remediation</div>
                      <div style={{
                        color: "var(--yellow)", fontSize: 12, padding: "10px 12px",
                        background: "rgba(245,197,24,.06)", border: "1px solid rgba(245,197,24,.15)",
                        borderRadius: "var(--r)", lineHeight: 1.6, marginBottom: 14,
                      }}>{f.remediation || "No remediation guidance available."}</div>

                      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 6 }}>CVSS Score</div>
                      <div style={{
                        fontSize: 36, fontFamily: "var(--font-ui)", fontWeight: 800,
                        color: (f.cvss_score ?? 0) >= 9 ? "var(--red)" : (f.cvss_score ?? 0) >= 7 ? "var(--orange)" : "var(--yellow)",
                        marginBottom: 14,
                      }}>{f.cvss_score?.toFixed(1) ?? "N/A"}</div>

                      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 4 }}>Port</div>
                      <div style={{ fontSize: 12, color: "var(--text)", marginBottom: 14 }}>
                        {f.affected_port ?? "N/A"}
                      </div>

                      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 4 }}>Discovered</div>
                      <div style={{ fontSize: 11, color: "var(--text-dim)" }}>{f.timestamp}</div>

                      {onDelete && (
                        <Btn variant="danger" size="sm" style={{ marginTop: 16 }}
                          onClick={e => { e.stopPropagation(); onDelete(f.id); }}>
                          Delete Finding
                        </Btn>
                      )}
                    </div>
                  </div>

                  {/* HTTP request/response pair */}
                  {(f.http_request || f.http_response) && (
                    <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                      {f.http_request && (
                        <div>
                          <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 6 }}>HTTP Request</div>
                          <pre style={{
                            background: "var(--bg1)", border: "1px solid var(--border)",
                            borderRadius: "var(--r)", padding: "8px 10px",
                            fontSize: 10, color: "var(--accent)", overflowX: "auto",
                            maxHeight: 160, whiteSpace: "pre-wrap",
                          }}>{f.http_request}</pre>
                        </div>
                      )}
                      {f.http_response && (
                        <div>
                          <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: ".8px", marginBottom: 6 }}>HTTP Response</div>
                          <pre style={{
                            background: "var(--bg1)", border: "1px solid var(--border)",
                            borderRadius: "var(--r)", padding: "8px 10px",
                            fontSize: 10, color: "var(--text)", overflowX: "auto",
                            maxHeight: 160, whiteSpace: "pre-wrap",
                          }}>{f.http_response}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </React.Fragment>
          );
        })}
      </Card>
    </div>
  );
}
