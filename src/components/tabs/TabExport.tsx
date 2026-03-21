// src/components/tabs/TabExport.tsx
import React, { useState } from "react";
import { Card, SectionHdr, Btn, SevBadge } from "../ui";
import type { Scan, VulnFinding, Severity } from "../../types";
import { exportPdf, exportCsv, exportBurp, exportCaido } from "../../lib/api";
import { save } from "@tauri-apps/plugin-dialog";

interface Props {
  scans: Scan[];
  findings: VulnFinding[];
  currentScanId: string | null;
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "var(--red)", HIGH: "var(--orange)",
  MEDIUM: "var(--yellow)", LOW: "var(--green)", INFO: "var(--accent)",
};

export default function TabExport({ scans, findings, currentScanId }: Props) {
  const [selectedScanId, setSelectedScanId] = useState(currentScanId ?? scans[0]?.id ?? "");
  const [status, setStatus] = useState<Record<string, string>>({});

  const scan = scans.find(s => s.id === selectedScanId);
  const scanFindings = findings.filter(f => f.scan_id === selectedScanId);

  const counts: Partial<Record<Severity, number>> = {};
  scanFindings.forEach(f => {
    counts[f.severity as Severity] = (counts[f.severity as Severity] ?? 0) + 1;
  });

  const doExport = async (type: string, fn: (scanId: string, path: string) => Promise<string>, ext: string, name: string) => {
    try {
      setStatus(s => ({ ...s, [type]: "saving…" }));
      const path = await save({
        defaultPath: `probescan_${scan?.target ?? "export"}_${new Date().toISOString().slice(0, 10)}.${ext}`,
        filters: [{ name, extensions: [ext] }],
      });
      if (!path) { setStatus(s => ({ ...s, [type]: "" })); return; }
      await fn(selectedScanId, path);
      setStatus(s => ({ ...s, [type]: "✓ Saved" }));
      setTimeout(() => setStatus(s => ({ ...s, [type]: "" })), 3000);
    } catch (e) {
      setStatus(s => ({ ...s, [type]: `Error: ${e}` }));
    }
  };

  const EXPORTS = [
    {
      id: "pdf", icon: "📄", bg: "rgba(255,59,92,.1)",
      title: "PDF Pentest Report",
      desc: "Executive summary, full vulnerability list sorted by severity, per-finding detail with CVE refs, remediation, scan metadata and tool inventory.",
      action: () => doExport("pdf", exportPdf, "html", "HTML Report"),
    },
    {
      id: "burp", icon: "🔴", bg: "rgba(255,123,44,.1)",
      title: "Burp Suite XML Export",
      desc: "Export findings and captured HTTP request/response pairs in Burp Suite XML format for direct import into Burp Suite Professional.",
      action: () => doExport("burp", exportBurp, "xml", "Burp Suite XML"),
    },
    {
      id: "caido", icon: "⚡", bg: "rgba(124,58,237,.12)",
      title: "Caido Export",
      desc: "Export target list and HTTP replay data in Caido-compatible JSON format. Continue manual testing where automated scanning left off.",
      action: () => doExport("caido", exportCaido, "json", "Caido JSON"),
    },
    {
      id: "csv", icon: "📊", bg: "rgba(0,212,255,.08)",
      title: "CSV Export",
      desc: "Export the full vulnerability schema as CSV for ingestion into SIEM, ticketing systems, or custom tooling.",
      action: () => doExport("csv", exportCsv, "csv", "CSV"),
    },
  ];

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 720, paddingBottom: 40 }}>

        {/* Scan selector */}
        <SectionHdr title="Select Scan" />
        <Card style={{ marginBottom: 16 }}>
          {scans.length === 0 ? (
            <p style={{ fontSize: 12, color: "var(--text-dim)" }}>No completed scans yet.</p>
          ) : (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {scans.map(s => (
                <button key={s.id} onClick={() => setSelectedScanId(s.id)}
                  style={{
                    padding: "6px 14px", borderRadius: "var(--r)", fontSize: 12, cursor: "pointer",
                    fontFamily: "var(--font-mono)", transition: "all .15s",
                    background: selectedScanId === s.id ? "var(--accent-dim)" : "var(--bg2)",
                    border: `1px solid ${selectedScanId === s.id ? "var(--accent)" : "var(--border)"}`,
                    color: selectedScanId === s.id ? "var(--accent)" : "var(--text-dim)",
                  }}>
                  {s.target} — {s.created_at.slice(0, 10)} ({s.finding_count ?? 0} findings)
                </button>
              ))}
            </div>
          )}
        </Card>

        {/* Export options */}
        <SectionHdr title="Export Format" />
        {EXPORTS.map(o => (
          <div key={o.id} style={{
            display: "flex", alignItems: "flex-start", gap: 14, padding: 16,
            background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: "var(--r-lg)",
            marginBottom: 10, cursor: "pointer", transition: "border .15s",
          }}
            onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--accent)")}
            onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--border)")}>
            <div style={{
              width: 44, height: 44, borderRadius: "var(--r)", flexShrink: 0,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 22, background: o.bg,
            }}>{o.icon}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontFamily: "var(--font-ui)", fontSize: 14, fontWeight: 700, color: "var(--text-hi)", marginBottom: 4 }}>{o.title}</div>
              <div style={{ fontSize: 11, color: "var(--text-dim)", lineHeight: 1.6 }}>{o.desc}</div>
            </div>
            {status[o.id] ? (
              <span style={{ fontSize: 12, color: status[o.id].startsWith("Error") ? "var(--red)" : "var(--green)", flexShrink: 0, alignSelf: "center" }}>
                {status[o.id]}
              </span>
            ) : (
              <Btn size="sm" onClick={o.action} style={{ alignSelf: "center", flexShrink: 0 }}
                disabled={!selectedScanId || scans.length === 0}>
                Export
              </Btn>
            )}
          </div>
        ))}

        {/* Report preview */}
        {scan && (
          <>
            <SectionHdr title="Report Preview" />
            <Card style={{ fontFamily: "var(--font-mono)" }}>
              <div style={{ borderBottom: "1px solid var(--border)", paddingBottom: 12, marginBottom: 12 }}>
                <div style={{ fontFamily: "var(--font-ui)", fontWeight: 800, fontSize: 17, color: "var(--text-hi)", marginBottom: 4 }}>
                  Penetration Test Report — {scan.target}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
                  Generated: {new Date().toISOString().slice(0, 10)}
                  {" · "}Duration: {scan.duration_secs ? `${scan.duration_secs}s` : "N/A"}
                  {" · "}Stealth: {scan.stealth_mode ? "ON" : "OFF"}
                  {" · "}Tools: {scan.tools_used?.join(", ") ?? "all"}
                </div>
              </div>

              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>
                  Executive Summary
                </div>
                <div style={{ fontSize: 12, color: "var(--text)", lineHeight: 1.8 }}>
                  Active scan of <span style={{ color: "var(--accent)" }}>{scan.target}</span> identified{" "}
                  {(["CRITICAL","HIGH","MEDIUM","LOW","INFO"] as Severity[]).map(s => (
                    counts[s] ? (
                      <span key={s}><span style={{ color: SEV_COLORS[s], fontWeight: 700 }}>{counts[s]} {s}</span>{" "}</span>
                    ) : null
                  ))}
                  {" "}findings across {scanFindings.filter(f => f.in_scope).length} in-scope assets.
                </div>
              </div>

              <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>
                Top Findings
              </div>
              {scanFindings.slice(0, 5).map(f => (
                <div key={f.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", borderBottom: "1px solid var(--border)", fontSize: 11 }}>
                  <SevBadge sev={f.severity as Severity} />
                  <span style={{ color: "var(--text-hi)", flex: 1 }}>{f.title}</span>
                  <span style={{ color: "var(--text-dim)" }}>{f.source_tool}</span>
                </div>
              ))}
              {scanFindings.length > 5 && (
                <p style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
                  +{scanFindings.length - 5} more findings in full report…
                </p>
              )}
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
