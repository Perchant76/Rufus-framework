// src/components/tabs/TabComparison.tsx
import React, { useState, useEffect } from "react";
import { Card, SectionHdr, SevBadge, Btn, StatCard } from "../ui";
import type { Scan, ScanComparison, VulnFinding, Severity } from "../../types";
import { compareScans } from "../../lib/api";

interface Props {
  scans: Scan[];
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "var(--red)", HIGH: "var(--orange)",
  MEDIUM: "var(--yellow)", LOW: "var(--green)", INFO: "var(--accent)",
};

export default function TabComparison({ scans }: Props) {
  const [selA, setSelA] = useState<string>("");
  const [selB, setSelB] = useState<string>("");
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-select two most recent scans
  useEffect(() => {
    if (scans.length >= 2) {
      setSelA(scans[1].id);
      setSelB(scans[0].id);
    }
  }, [scans]);

  const runComparison = async () => {
    if (!selA || !selB) return;
    setLoading(true);
    setError(null);
    try {
      const result = await compareScans(selA, selB);
      setComparison(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 960, paddingBottom: 40 }}>

        {/* Scan selector */}
        <SectionHdr title="Select Scans to Compare" />
        <Card style={{ marginBottom: 16 }}>
          {scans.length < 2 ? (
            <p style={{ color: "var(--text-dim)", fontSize: 12 }}>
              At least 2 completed scans are needed for comparison.
            </p>
          ) : (
            <div style={{ display: "flex", alignItems: "flex-end", gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Baseline Scan (A)</div>
                <select value={selA} onChange={e => setSelA(e.target.value)}
                  style={{ width: "100%", background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)", fontFamily: "var(--font-mono)", fontSize: 12, borderRadius: "var(--r)", padding: "8px 12px" }}>
                  {scans.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.target} — {s.created_at.slice(0, 10)} ({s.finding_count ?? 0} findings)
                    </option>
                  ))}
                </select>
              </div>
              <span style={{ color: "var(--accent)", fontSize: 20, paddingBottom: 8 }}>→</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Latest Scan (B)</div>
                <select value={selB} onChange={e => setSelB(e.target.value)}
                  style={{ width: "100%", background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)", fontFamily: "var(--font-mono)", fontSize: 12, borderRadius: "var(--r)", padding: "8px 12px" }}>
                  {scans.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.target} — {s.created_at.slice(0, 10)} ({s.finding_count ?? 0} findings)
                    </option>
                  ))}
                </select>
              </div>
              <Btn variant="primary" onClick={runComparison} style={{ flexShrink: 0 }}>
                {loading ? "Comparing…" : "Compare"}
              </Btn>
            </div>
          )}
          {error && <p style={{ color: "var(--red)", fontSize: 12, marginTop: 8 }}>{error}</p>}
        </Card>

        {comparison && (
          <>
            {/* Summary stats */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginBottom: 16 }}>
              <StatCard num={comparison.new_findings.length} label="New Findings" color="var(--red)" />
              <StatCard num={comparison.resolved_finding_titles.length} label="Resolved" color="var(--green)" />
              <StatCard num={comparison.persistent_findings.length} label="Persistent" color="var(--orange)" />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
              {/* New findings */}
              <div>
                <SectionHdr title="New Findings"
                  right={<span style={{ background: "var(--red)", color: "#fff", fontSize: 10, fontWeight: 700, borderRadius: 8, padding: "1px 7px" }}>{comparison.new_findings.length}</span>}
                />
                <Card style={{ padding: 0, overflow: "hidden" }}>
                  {comparison.new_findings.length === 0 ? (
                    <div style={{ padding: "16px", color: "var(--text-dim)", fontSize: 12 }}>No new findings — great!</div>
                  ) : (
                    comparison.new_findings.map(f => (
                      <div key={f.id} style={{
                        display: "flex", alignItems: "center", gap: 10, padding: "10px 14px",
                        borderBottom: "1px solid var(--border)",
                        background: "rgba(255,59,92,.04)",
                      }}>
                        <span style={{ fontSize: 16 }}>🆕</span>
                        <SevBadge sev={f.severity as Severity} />
                        <span style={{ fontSize: 12, color: "var(--text-hi)", flex: 1 }}>{f.title}</span>
                      </div>
                    ))
                  )}
                </Card>
              </div>

              {/* Resolved */}
              <div>
                <SectionHdr title="Resolved Since Last Scan"
                  right={<span style={{ background: "var(--green)", color: "#fff", fontSize: 10, fontWeight: 700, borderRadius: 8, padding: "1px 7px" }}>{comparison.resolved_finding_titles.length}</span>}
                />
                <Card style={{ padding: 0, overflow: "hidden" }}>
                  {comparison.resolved_finding_titles.length === 0 ? (
                    <div style={{ padding: "16px", color: "var(--text-dim)", fontSize: 12 }}>None resolved between these scans.</div>
                  ) : (
                    comparison.resolved_finding_titles.map((title, i) => (
                      <div key={i} style={{
                        display: "flex", alignItems: "center", gap: 10, padding: "10px 14px",
                        borderBottom: "1px solid var(--border)",
                        background: "rgba(34,197,94,.04)",
                      }}>
                        <span style={{ fontSize: 16 }}>✅</span>
                        <span style={{ fontSize: 12, color: "var(--green)", flex: 1 }}>{title}</span>
                      </div>
                    ))
                  )}
                </Card>
              </div>
            </div>

            {/* Persistent findings */}
            <SectionHdr title="Persistent Findings"
              right={<span style={{ fontSize: 11, color: "var(--text-dim)" }}>ranked by scan count</span>}
            />
            <Card style={{ padding: 0, overflow: "hidden", marginBottom: 16 }}>
              {comparison.persistent_findings.length === 0 ? (
                <div style={{ padding: "16px", color: "var(--text-dim)", fontSize: 12 }}>No persistent findings.</div>
              ) : (
                comparison.persistent_findings.map((p, i) => (
                  <div key={i} style={{
                    display: "flex", alignItems: "center", gap: 10, padding: "12px 14px",
                    borderBottom: "1px solid var(--border)",
                    background: p.is_chronic ? "rgba(255,59,92,.06)" : "rgba(255,123,44,.04)",
                    borderLeft: `3px solid ${p.is_chronic ? "var(--red)" : "var(--orange)"}`,
                  }}>
                    {p.is_chronic && (
                      <span style={{
                        fontSize: 9, fontWeight: 700, padding: "2px 6px",
                        background: "var(--red)", color: "#fff", borderRadius: 3,
                        textTransform: "uppercase", letterSpacing: ".6px",
                        animation: "blink 2s infinite", flexShrink: 0,
                      }}>Chronic</span>
                    )}
                    <SevBadge sev={p.severity as Severity} />
                    <span style={{ fontSize: 12, color: "var(--text-hi)", flex: 1 }}>{p.title}</span>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4, flexShrink: 0 }}>
                      <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{p.scan_count} scans</span>
                      <span style={{ fontSize: 10, color: "var(--text-dim)" }}>First: {p.first_seen.slice(0, 10)}</span>
                    </div>

                    {/* Mini timeline */}
                    <div style={{ display: "flex", alignItems: "center", gap: 2, marginLeft: 8 }}>
                      {[0, 1, 2].map(idx => (
                        <React.Fragment key={idx}>
                          {idx > 0 && <div style={{ width: 12, height: 1, background: "var(--border)" }} />}
                          <div style={{
                            width: 8, height: 8, borderRadius: "50%",
                            background: idx < p.scan_count
                              ? (idx === 0 ? "var(--orange)" : p.is_chronic ? "var(--red)" : "var(--orange)")
                              : "var(--bg3)",
                            border: `1px solid ${idx < p.scan_count ? "transparent" : "var(--border)"}`,
                          }} />
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </Card>
          </>
        )}

        {!comparison && !loading && scans.length >= 2 && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: 200, gap: 8, color: "var(--text-dim)" }}>
            <span style={{ fontSize: 40, opacity: .3 }}>⇌</span>
            <span style={{ fontSize: 12 }}>Select two scans above and click Compare</span>
          </div>
        )}
      </div>
    </div>
  );
}
