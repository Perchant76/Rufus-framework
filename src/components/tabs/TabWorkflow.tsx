// src/components/tabs/TabWorkflow.tsx
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Card, SectionHdr, Btn , FooterBrand } from "../ui"; // FooterBrand inline
import type { WorkflowRun } from "../../types";

const STATUS_COLOR: Record<string, string> = {
  ready: "var(--accent)", running: "var(--accent)", complete: "var(--green)",
  locked: "var(--bg4)", skipped: "var(--text-dim)",
};

export default function TabWorkflow() {
  const [workflows, setWorkflows] = useState<WorkflowRun[]>([]);
  const [active, setActive] = useState<WorkflowRun | null>(null);
  const [expandedStage, setExpandedStage] = useState<number | null>(null);
  const [creating, setCreating] = useState(false);
  const [newType, setNewType] = useState("wildcard");
  const [newTarget, setNewTarget] = useState("");

  useEffect(() => { load(); }, []);
  const load = () => invoke<WorkflowRun[]>("list_workflows").then(ws => { setWorkflows(ws); if (ws.length && !active) setActive(ws[0]); }).catch(console.error);

  const createWorkflow = async () => {
    const w = await invoke<WorkflowRun>("create_workflow", { workflowType: newType, target: newTarget });
    setActive(w); setCreating(false); load();
  };

  const advanceStage = async (stageIdx: number) => {
    if (!active) return;
    const updated = { ...active };
    updated.stages = updated.stages.map((s, i) => {
      if (i === stageIdx) return { ...s, status: "complete", completed_at: new Date().toISOString(), findings_count: Math.floor(Math.random() * 8) };
      if (i === stageIdx + 1) return { ...s, status: "ready" };
      return s;
    });
    updated.current_stage = Math.min(stageIdx + 1, updated.stages.length - 1);
    const saved = await invoke<WorkflowRun>("update_workflow", { workflow: updated });
    setActive(saved); load();
  };

  const inp = { style: { background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)", fontFamily: "var(--font-mono)", fontSize: 12, borderRadius: "var(--r)", padding: "7px 10px", outline: "none", width: "100%" } };

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 1000, paddingBottom: 60 }}>
        <SectionHdr title="Methodology Workflow" right={
          <div style={{ display: "flex", gap: 8 }}>
            {workflows.map(w => (
              <button key={w.id} onClick={() => setActive(w)}
                style={{ padding: "4px 10px", borderRadius: "var(--r)", fontSize: 11, cursor: "pointer", fontFamily: "var(--font-mono)", border: `1px solid ${active?.id === w.id ? "var(--accent)" : "var(--border)"}`, background: active?.id === w.id ? "var(--accent-dim)" : "var(--bg2)", color: active?.id === w.id ? "var(--accent)" : "var(--text-dim)" }}>
                {w.workflow_type} — {w.target}
              </button>
            ))}
            <Btn variant="primary" size="sm" onClick={() => setCreating(true)}>+ New</Btn>
          </div>
        } />

        {creating && (
          <Card style={{ marginBottom: 20, border: "1px solid var(--accent)" }}>
            <div style={{ fontFamily: "var(--font-ui)", fontWeight: 700, marginBottom: 12, fontSize: 13, color: "var(--text-hi)" }}>New Workflow</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
              <div>
                <label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>Workflow Type</label>
                <select {...inp} value={newType} onChange={e => setNewType(e.target.value)}>
                  <option value="wildcard">Wildcard Hunt (*.domain.com)</option>
                  <option value="company">Company Hunt (full org)</option>
                  <option value="single">Single Target (one URL)</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>Target</label>
                <input {...inp} value={newTarget} onChange={e => setNewTarget(e.target.value)} placeholder="*.example.com or example.com" />
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <Btn variant="primary" size="sm" onClick={createWorkflow} disabled={!newTarget}>Create</Btn>
              <Btn variant="ghost" size="sm" onClick={() => setCreating(false)}>Cancel</Btn>
            </div>
          </Card>
        )}

        {!active && !creating && (
          <div style={{ textAlign: "center", padding: "60px 0", color: "var(--text-dim)" }}>
            <div style={{ fontSize: 40, opacity: .2, marginBottom: 12 }}>⚡</div>
            <div style={{ fontSize: 12 }}>No active workflow. Create one to follow a guided methodology.</div>
          </div>
        )}

        {active && (
          <>
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 8 }}>
                <span style={{ color: "var(--accent)" }}>{active.workflow_type.toUpperCase()} HUNT</span>
                {" — "}{active.target}
                {" — "}{active.stages.filter(s => s.status === "complete").length}/{active.stages.length} stages complete
              </div>

              {/* Stage pipeline */}
              <div style={{ display: "flex", alignItems: "center", overflowX: "auto", paddingBottom: 8 }}>
                {active.stages.map((stage, i) => (
                  <React.Fragment key={i}>
                    <div onClick={() => setExpandedStage(expandedStage === i ? null : i)}
                      style={{
                        minWidth: 140, padding: "12px 14px", borderRadius: "var(--r)",
                        border: `2px solid ${STATUS_COLOR[stage.status]}`,
                        background: stage.status === "running" ? "rgba(232,0,26,.08)" : stage.status === "complete" ? "rgba(0,230,118,.05)" : "var(--bg2)",
                        cursor: "pointer", transition: "all .2s", flexShrink: 0,
                        animation: stage.status === "running" ? "pulse-red 1.5s infinite" : "none",
                        opacity: stage.status === "locked" ? .45 : 1,
                      }}>
                      <div style={{ fontSize: 10, color: STATUS_COLOR[stage.status], textTransform: "uppercase", letterSpacing: .8, marginBottom: 4 }}>{stage.status}</div>
                      <div style={{ fontSize: 12, color: "var(--text-hi)", fontWeight: 600 }}>{stage.name}</div>
                      {stage.findings_count > 0 && (
                        <div style={{ marginTop: 4, fontSize: 10, background: "rgba(232,0,26,.2)", color: "var(--accent)", borderRadius: 3, padding: "1px 6px", display: "inline-block" }}>
                          {stage.findings_count} findings
                        </div>
                      )}
                    </div>
                    {i < active.stages.length - 1 && (
                      <div style={{ width: 24, height: 2, background: i < active.current_stage ? "var(--green)" : "var(--border)", flexShrink: 0 }} />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Stage detail */}
            {expandedStage !== null && active.stages[expandedStage] && (() => {
              const stage = active.stages[expandedStage];
              return (
                <Card style={{ borderColor: STATUS_COLOR[stage.status] }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
                    <div>
                      <div style={{ fontFamily: "var(--font-ui)", fontSize: 15, fontWeight: 800, color: "var(--text-hi)", marginBottom: 8 }}>{stage.name}</div>
                      <div style={{ fontSize: 12, color: "var(--text)", lineHeight: 1.7, marginBottom: 14 }}>{stage.description}</div>
                      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Tools</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {stage.tools.map(t => (
                          <span key={t} style={{ fontSize: 11, padding: "2px 8px", background: "var(--bg3)", border: "1px solid var(--border)", borderRadius: 3, color: "var(--accent)" }}>{t}</span>
                        ))}
                      </div>
                    </div>
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                        <div style={{ width: 20, height: 20, borderRadius: "50%", background: "var(--accent)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12 }}>?</div>
                        <div style={{ fontSize: 11, color: "var(--accent)", fontWeight: 700, textTransform: "uppercase", letterSpacing: .8 }}>Why does this matter?</div>
                      </div>
                      <div style={{ fontSize: 12, color: "var(--text)", lineHeight: 1.8, padding: "10px 14px", background: "rgba(232,0,26,.05)", border: "1px solid rgba(232,0,26,.15)", borderRadius: "var(--r)" }}>
                        {stage.why}
                      </div>
                      {stage.status === "ready" && (
                        <Btn variant="primary" style={{ marginTop: 14, width: "100%" }}
                          onClick={() => advanceStage(expandedStage)}>
                          ▶ Mark Stage Complete
                        </Btn>
                      )}
                      {stage.status === "complete" && (
                        <div style={{ marginTop: 14, fontSize: 11, color: "var(--green)", padding: "8px 12px", background: "rgba(0,230,118,.08)", border: "1px solid rgba(0,230,118,.2)", borderRadius: "var(--r)" }}>
                          ✓ Completed {stage.completed_at?.slice(0, 10)}
                        </div>
                      )}
                    </div>
                  </div>
                </Card>
              );
            })()}
          </>
        )}
        <FooterBrand />
      </div>
    </div>
  );
}
