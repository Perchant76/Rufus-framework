// src/components/tabs/TabPrograms.tsx
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Card, SectionHdr, Btn, SevBadge , FooterBrand } from "../ui"; // FooterBrand inline
import type { BugBountyProgram, ScanConfig } from "../../types";

const PLATFORM_COLORS: Record<string, string> = {
  hackerone: "#25a162", bugcrowd: "#f26722",
  intigriti: "#e8001a", yeswehack: "#7c3aed", custom: "#7a4a52",
};
const PLATFORM_LABELS: Record<string, string> = {
  hackerone: "HackerOne", bugcrowd: "Bugcrowd",
  intigriti: "Intigriti", yeswehack: "YesWeHack", custom: "Custom",
};

const EMPTY: BugBountyProgram = {
  id: "", name: "", program_type: "wildcard", platform: "hackerone",
  in_scope: [], out_of_scope: [], max_bounty: undefined,
  notes: "", scan_ids: [], created_at: "",
};

export default function TabPrograms({ onStartScan }: { onStartScan?: (config: Partial<ScanConfig>) => void }) {
  const [programs, setPrograms] = useState<BugBountyProgram[]>([]);
  const [editing, setEditing] = useState<BugBountyProgram | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => { load(); }, []);
  const load = () => invoke<BugBountyProgram[]>("list_programs").then(setPrograms).catch(console.error);

  const save = async () => {
    if (!editing) return;
    if (editing.id) { await invoke("update_program", { program: editing }); }
    else { await invoke("create_program", { program: editing }); }
    setEditing(null); load();
  };

  const del = async (id: string) => {
    await invoke("delete_program", { id });
    load();
  };

  const inp = (style?: React.CSSProperties) => ({
    style: { background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)",
      fontFamily: "var(--font-mono)", fontSize: 12, borderRadius: "var(--r)", padding: "7px 10px",
      outline: "none", width: "100%", ...style }
  });

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 960, paddingBottom: 60 }}>
        <SectionHdr title="Bug Bounty Programs"
          right={<Btn variant="primary" size="sm" onClick={() => setEditing({ ...EMPTY })}>+ Add Program</Btn>} />

        {/* Editor modal */}
        {editing && (
          <Card style={{ marginBottom: 20, border: "1px solid var(--accent)", background: "var(--bg2)" }}>
            <div style={{ fontFamily: "var(--font-ui)", fontWeight: 700, color: "var(--text-hi)", marginBottom: 14, fontSize: 13 }}>
              {editing.id ? "Edit Program" : "New Program"}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
              <div><label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>Name</label>
                <input {...inp()} value={editing.name} onChange={e => setEditing(x => x && ({ ...x, name: e.target.value }))} placeholder="Google VRP" /></div>
              <div><label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>Platform</label>
                <select {...inp()} value={editing.platform} onChange={e => setEditing(x => x && ({ ...x, platform: e.target.value }))}>
                  {Object.entries(PLATFORM_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select></div>
              <div><label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>Type</label>
                <select {...inp()} value={editing.program_type} onChange={e => setEditing(x => x && ({ ...x, program_type: e.target.value as BugBountyProgram["program_type"] }))}>
                  <option value="wildcard">Wildcard (*.example.com)</option>
                  <option value="company">Company (Google, Tesla…)</option>
                  <option value="url">Single URL</option>
                </select></div>
              <div><label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>Max Bounty ($)</label>
                <input {...inp()} type="number" value={editing.max_bounty ?? ""} onChange={e => setEditing(x => x && ({ ...x, max_bounty: e.target.value ? Number(e.target.value) : undefined }))} placeholder="10000" /></div>
            </div>
            <div style={{ marginBottom: 10 }}>
              <label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>In-Scope (one per line)</label>
              <textarea {...inp({ height: 80, resize: "vertical" })} value={editing.in_scope.join("\n")} onChange={e => setEditing(x => x && ({ ...x, in_scope: e.target.value.split("\n").filter(Boolean) }))} placeholder="*.example.com&#10;example.com&#10;93.184.0.0/16" />
            </div>
            <div style={{ marginBottom: 10 }}>
              <label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>Out-of-Scope (one per line)</label>
              <textarea {...inp({ height: 60, resize: "vertical" })} value={editing.out_of_scope.join("\n")} onChange={e => setEditing(x => x && ({ ...x, out_of_scope: e.target.value.split("\n").filter(Boolean) }))} placeholder="api.example.com&#10;payments.example.com" />
            </div>
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>Notes</label>
              <textarea {...inp({ height: 60, resize: "vertical" })} value={editing.notes} onChange={e => setEditing(x => x && ({ ...x, notes: e.target.value }))} />
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <Btn variant="primary" size="sm" onClick={save}>Save</Btn>
              <Btn variant="ghost" size="sm" onClick={() => setEditing(null)}>Cancel</Btn>
            </div>
          </Card>
        )}

        {/* Program cards */}
        {programs.length === 0 && !editing && (
          <div style={{ textAlign: "center", padding: "60px 0", color: "var(--text-dim)" }}>
            <div style={{ fontSize: 40, opacity: .2, marginBottom: 12 }}>🎯</div>
            <div style={{ fontSize: 12 }}>No programs yet. Add your first bug bounty program.</div>
          </div>
        )}
        {programs.map(p => {
          const pc = PLATFORM_COLORS[p.platform] ?? "var(--text-dim)";
          const isExp = expanded === p.id;
          return (
            <Card key={p.id} style={{ marginBottom: 10, cursor: "pointer",
              borderColor: isExp ? "var(--accent)" : "var(--border)" }}>
              <div onClick={() => setExpanded(isExp ? null : p.id)}
                style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ width: 10, height: 10, borderRadius: "50%", background: pc, flexShrink: 0 }} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: "var(--font-ui)", fontWeight: 700, color: "var(--text-hi)", fontSize: 14 }}>{p.name}</div>
                  <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
                    <span style={{ color: pc }}>{PLATFORM_LABELS[p.platform]}</span>
                    {" · "}{p.program_type}
                    {p.max_bounty && <span style={{ color: "var(--green)", marginLeft: 8 }}>${p.max_bounty.toLocaleString()}</span>}
                    {" · "}{p.in_scope.length} in-scope · {p.scan_ids.length} scan{p.scan_ids.length !== 1 ? "s" : ""}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  {onStartScan && (
                    <Btn size="sm" variant="primary" onClick={e => { e.stopPropagation(); onStartScan({ target: p.in_scope[0] ?? "", scope: p.in_scope }); }}>
                      ▶ Scan
                    </Btn>
                  )}
                  <Btn size="sm" onClick={e => { e.stopPropagation(); setEditing({ ...p }); }}>Edit</Btn>
                  <Btn size="sm" variant="danger" onClick={e => { e.stopPropagation(); del(p.id); }}>Del</Btn>
                </div>
              </div>
              {isExp && (
                <div style={{ marginTop: 14, paddingTop: 14, borderTop: "1px solid var(--border)", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                  <div>
                    <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>In-Scope</div>
                    {p.in_scope.map(s => <div key={s} style={{ fontSize: 11, color: "var(--green)", padding: "2px 0" }}>✓ {s}</div>)}
                    {p.out_of_scope.length > 0 && <>
                      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6, marginTop: 10 }}>Out-of-Scope</div>
                      {p.out_of_scope.map(s => <div key={s} style={{ fontSize: 11, color: "var(--red)", padding: "2px 0" }}>✗ {s}</div>)}
                    </>}
                  </div>
                  {p.notes && <div>
                    <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Notes</div>
                    <div style={{ fontSize: 11, color: "var(--text)", lineHeight: 1.6 }}>{p.notes}</div>
                  </div>}
                </div>
              )}
            </Card>
          );
        })}
        <FooterBrand />
      </div>
    </div>
  );
}
