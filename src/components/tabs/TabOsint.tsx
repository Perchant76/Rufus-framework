// src/components/tabs/TabOsint.tsx
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Card, SectionHdr, Btn } from "../ui";
import type { OsintResult } from "../../types";

export default function TabOsint() {
  const [target, setTarget] = useState("");
  const [dorks, setDorks] = useState<[string, string][]>([]);
  const [results, setResults] = useState<OsintResult[]>([]);
  const [editNotes, setEditNotes] = useState<Record<string, string>>({});

  useEffect(() => { invoke<OsintResult[]>("list_osint_results").then(setResults).catch(() => {}); }, []);

  const loadDorks = async () => {
    if (!target) return;
    const d = await invoke<[string, string][]>("get_dork_templates", { target });
    setDorks(d);
  };

  const openDork = (query: string) => invoke("open_dork_in_browser", { query });

  const addManual = async (query: string, desc: string) => {
    const r = await invoke<OsintResult>("add_osint_result", {
      result: { id: "", scan_id: null, source: "google_dork", query, result_count: null, url: `https://google.com/search?q=${encodeURIComponent(query)}`, notes: "", severity: "INFO", created_at: "" }
    });
    setResults(x => [...x, r]);
  };

  const saveNotes = async (id: string) => {
    await invoke("update_osint_notes", { id, notes: editNotes[id] ?? "" });
    setResults(x => x.map(r => r.id === id ? { ...r, notes: editNotes[id] ?? "" } : r));
  };

  const exportMd = () => {
    const md = `# OSINT Report — ${target}\n\n${results.map(r =>
      `## ${r.query}\n- **Source:** ${r.source}\n- **Severity:** ${r.severity}\n- **Notes:** ${r.notes || "—"}\n`
    ).join("\n")}`;
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `osint-${target}-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
  };

  const inp = (style?: React.CSSProperties) => ({
    style: { background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)", fontFamily: "var(--font-mono)", fontSize: 12, borderRadius: "var(--r)", padding: "7px 10px", outline: "none", ...style }
  });

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 960, paddingBottom: 60 }}>
        <SectionHdr title="OSINT & Google Dorking" right={
          results.length > 0 ? <Btn size="sm" onClick={exportMd}>Export MD</Btn> : undefined
        } />
        <Card style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", gap: 8 }}>
            <input {...inp({ flex: 1 })} value={target} onChange={e => setTarget(e.target.value)} placeholder="target.com" />
            <Btn variant="primary" onClick={loadDorks} disabled={!target}>Generate Dorks</Btn>
          </div>
        </Card>

        {dorks.length > 0 && (
          <>
            <SectionHdr title="Google Dork Templates" />
            <Card style={{ marginBottom: 16, padding: 0, overflow: "hidden" }}>
              {dorks.map(([query, desc], i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", borderBottom: "1px solid var(--border)" }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 11, color: "var(--accent)", fontFamily: "var(--font-mono)" }}>{query}</div>
                    <div style={{ fontSize: 10, color: "var(--text-dim)", marginTop: 2 }}>{desc}</div>
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <Btn size="sm" onClick={() => openDork(query)}>Open 🔍</Btn>
                    <Btn size="sm" variant="ghost" onClick={() => addManual(query, desc)}>Track</Btn>
                  </div>
                </div>
              ))}
            </Card>
          </>
        )}

        {results.length > 0 && (
          <>
            <SectionHdr title="Tracked Results" />
            {results.map(r => (
              <Card key={r.id} style={{ marginBottom: 8 }}>
                <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                  <span style={{ fontSize: 10, padding: "2px 7px", borderRadius: 3, fontWeight: 700, textTransform: "uppercase", flexShrink: 0, marginTop: 2, background: "rgba(232,0,26,.12)", color: "var(--accent)", border: "1px solid rgba(232,0,26,.2)" }}>
                    {r.source}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 11, color: "var(--accent)", fontFamily: "var(--font-mono)", marginBottom: 4 }}>{r.query}</div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <textarea {...inp({ flex: 1, height: 50, resize: "vertical", fontSize: 11 })}
                        value={editNotes[r.id] ?? r.notes} onChange={e => setEditNotes(x => ({ ...x, [r.id]: e.target.value }))}
                        placeholder="Add notes…" />
                      <Btn size="sm" onClick={() => saveNotes(r.id)}>Save</Btn>
                    </div>
                  </div>
                </div>
              </Card>
            ))}
          </>
        )}

        {dorks.length === 0 && results.length === 0 && (
          <div style={{ textAlign: "center", padding: "60px 0", color: "var(--text-dim)" }}>
            <div style={{ fontSize: 40, opacity: .2, marginBottom: 12 }}>🔍</div>
            <div style={{ fontSize: 12 }}>Enter a target domain to generate Google dorks and GitHub search queries.</div>
          </div>
        )}
        <div style={{ textAlign: "center", marginTop: 40, fontSize: 11, color: "var(--text-dim)", opacity: .5 }}>
          Build with ❤️ by Perchant
        </div>
      </div>
    </div>
  );
}
