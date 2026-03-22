// src/components/tabs/TabPhaseControl.tsx
// Granular scan phase control — pause, resume, skip, re-run phases
import React, { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface PhaseStatus {
  phase_id: number; name: string; tools: string[];
  state: string; findings_count: number;
  started_at?: string; completed_at?: string; duration_secs?: number;
}

interface Props { isRunning: boolean; currentScanId: string | null; }

const STATE_COLOR: Record<string,string> = {
  Pending:"#52525b", Running:"#f59e0b", Complete:"#22c55e",
  Skipped:"#3b82f6", "Error(...)":"#ef4444",
};
const STATE_ICON: Record<string,string> = {
  Pending:"○", Running:"◉", Complete:"✓", Skipped:"⊘",
};

export default function TabPhaseControl({ isRunning, currentScanId }: Props) {
  const [phases, setPhases] = useState<PhaseStatus[]>([]);
  const [paused, setPaused] = useState(false);
  const [status, setStatus] = useState("");
  const unlistenRef = useRef<(()=>void)|null>(null);

  useEffect(() => {
    if (!currentScanId) return;
    loadPhases();

    // Listen for phase updates
    listen("phase_update", (e: any) => {
      const { phase_id, state } = e.payload ?? {};
      setPhases(prev => prev.map(p =>
        p.phase_id === phase_id ? { ...p, state } : p
      ));
    }).then(fn => { unlistenRef.current = fn; });

    return () => { unlistenRef.current?.(); };
  }, [currentScanId]);

  const loadPhases = async () => {
    try {
      const result = await invoke<PhaseStatus[]>("get_all_phase_statuses");
      setPhases(result);
    } catch { /* no active scan */ }
  };

  const handlePause = async () => {
    try { await invoke("pause_scan"); setPaused(true); setStatus("Scan paused — current tool will finish then hold."); }
    catch(e) { setStatus(`Error: ${e}`); }
  };

  const handleResume = async () => {
    try { await invoke("resume_scan"); setPaused(false); setStatus("Scan resumed."); }
    catch(e) { setStatus(`Error: ${e}`); }
  };

  const handleSkip = async (phaseId: number) => {
    try { await invoke("skip_phase", { phaseId }); setStatus(`Phase ${phaseId} will be skipped.`); loadPhases(); }
    catch(e) { setStatus(`Error: ${e}`); }
  };

  const runningPhase = phases.find(p => p.state === "Running");
  const completedCount = phases.filter(p => p.state === "Complete").length;
  const totalCount = phases.length;

  return (
    <div style={{ display:"flex", height:"100%", overflow:"hidden", fontFamily:"var(--font-ui)" }}>
      <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
        {/* Control bar */}
        <div style={{ padding:16, borderBottom:"1px solid var(--border)", display:"flex", alignItems:"center", gap:12, flexWrap:"wrap" }}>
          <div style={{ fontSize:12, color:"var(--accent)", letterSpacing:2, fontWeight:700 }}>⚙ PHASE CONTROL</div>
          <div style={{ flex:1 }} />
          {isRunning && !paused && (
            <button onClick={handlePause} style={{ padding:"7px 16px", background:"rgba(245,158,11,0.1)", border:"1px solid rgba(245,158,11,0.4)", color:"#f59e0b", borderRadius:"var(--r)", fontSize:11, cursor:"pointer", fontFamily:"var(--font-ui)", fontWeight:700, letterSpacing:1 }}>
              ⏸ PAUSE
            </button>
          )}
          {isRunning && paused && (
            <button onClick={handleResume} style={{ padding:"7px 16px", background:"rgba(34,197,94,0.1)", border:"1px solid rgba(34,197,94,0.4)", color:"#22c55e", borderRadius:"var(--r)", fontSize:11, cursor:"pointer", fontFamily:"var(--font-ui)", fontWeight:700, letterSpacing:1 }}>
              ▶ RESUME
            </button>
          )}
          {status && <div style={{ fontSize:11, color:"var(--text-dim)" }}>{status}</div>}
        </div>

        {/* Progress overview */}
        {phases.length > 0 && (
          <div style={{ padding:"12px 20px", borderBottom:"1px solid var(--border)" }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
              <span style={{ fontSize:11, color:"var(--text-dim)" }}>Overall Progress</span>
              <span style={{ fontSize:11, color:"#f0f0f0", fontWeight:700 }}>{completedCount}/{totalCount} phases</span>
            </div>
            <div style={{ height:6, background:"var(--bg3)", borderRadius:3, overflow:"hidden" }}>
              <div style={{ height:"100%", width:`${(completedCount/totalCount)*100}%`, background:"var(--accent)", borderRadius:3, transition:"width 0.5s ease", boxShadow:"0 0 8px rgba(232,0,26,0.5)" }}/>
            </div>
            {runningPhase && (
              <div style={{ marginTop:8, fontSize:11, color:"#f59e0b", display:"flex", alignItems:"center", gap:8 }}>
                <span style={{ display:"inline-block", width:8, height:8, borderRadius:"50%", background:"#f59e0b", animation:"pulse-red 1s infinite" }}/>
                Currently running: {runningPhase.name}
                {paused && <span style={{ color:"#f97316", fontWeight:700 }}> [PAUSED]</span>}
              </div>
            )}
          </div>
        )}

        {/* Phase list */}
        <div style={{ flex:1, overflowY:"auto", padding:20 }}>
          {phases.length === 0 ? (
            <div style={{ textAlign:"center", padding:48, color:"var(--text-dim)" }}>
              <div style={{ fontSize:40, marginBottom:12, opacity:0.2 }}>⚙</div>
              <div style={{ fontSize:14, color:"#f0f0f0", marginBottom:8 }}>Phase Control</div>
              <div style={{ fontSize:12, lineHeight:1.7, maxWidth:380, margin:"0 auto" }}>
                When a scan is running, phases will appear here. You can pause the scan between phases, skip upcoming phases, or monitor per-phase findings counts.
              </div>
            </div>
          ) : (
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              {phases.map(phase => {
                const stateKey = typeof phase.state === "string" && phase.state.startsWith("Error") ? "Error(...)" : phase.state;
                const color = STATE_COLOR[stateKey] ?? "#71717a";
                const icon = STATE_ICON[stateKey] ?? "○";
                const isPending = phase.state === "Pending";
                const isRunningPhase = phase.state === "Running";
                const isComplete = phase.state === "Complete";
                const isSkipped = phase.state === "Skipped";

                return (
                  <div key={phase.phase_id} style={{
                    background:"var(--bg2)", border:`1px solid ${isRunningPhase?"rgba(245,158,11,0.4)":isComplete?"rgba(34,197,94,0.2)":"var(--border)"}`,
                    borderRadius:10, padding:16,
                    opacity: isSkipped ? 0.5 : 1,
                    boxShadow: isRunningPhase ? "0 0 16px rgba(245,158,11,0.15)" : "none",
                    transition:"all 0.3s",
                  }}>
                    <div style={{ display:"flex", alignItems:"center", gap:14 }}>
                      {/* Phase number */}
                      <div style={{ width:36, height:36, borderRadius:"50%", background:`${color}22`, border:`2px solid ${color}`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:16, color, flexShrink:0 }}>
                        {isRunningPhase ? <span style={{ animation:"pulse-red 1s infinite" }}>◉</span> : icon}
                      </div>

                      {/* Info */}
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:4 }}>
                          <span style={{ fontSize:11, fontWeight:700, color:"#f0f0f0" }}>Phase {phase.phase_id}</span>
                          <span style={{ fontSize:11, color:"#f0f0f0" }}>{phase.name}</span>
                          <span style={{ fontSize:9, color, background:`${color}18`, border:`1px solid ${color}44`, padding:"1px 7px", borderRadius:3, letterSpacing:1, fontWeight:700, textTransform:"uppercase" }}>{typeof phase.state === "string" ? phase.state : "Error"}</span>
                        </div>
                        <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                          {phase.tools.map(t => (
                            <span key={t} style={{ fontSize:10, color:"var(--text-dim)", background:"var(--bg3)", border:"1px solid var(--border)", padding:"1px 7px", borderRadius:3, fontFamily:"var(--font-mono)" }}>{t}</span>
                          ))}
                        </div>
                        {phase.duration_secs && (
                          <div style={{ fontSize:10, color:"var(--text-dim)", marginTop:4 }}>
                            Duration: {phase.duration_secs.toFixed(1)}s
                            {phase.findings_count > 0 && ` · ${phase.findings_count} findings`}
                          </div>
                        )}
                      </div>

                      {/* Actions */}
                      <div style={{ display:"flex", gap:8, flexShrink:0 }}>
                        {phase.findings_count > 0 && (
                          <div style={{ fontSize:12, fontWeight:800, color:"var(--accent)", background:"rgba(232,0,26,0.1)", border:"1px solid rgba(232,0,26,0.3)", borderRadius:6, padding:"4px 10px" }}>
                            {phase.findings_count}
                          </div>
                        )}
                        {isPending && isRunning && (
                          <button onClick={() => handleSkip(phase.phase_id)}
                            style={{ padding:"5px 12px", background:"rgba(59,130,246,0.1)", border:"1px solid rgba(59,130,246,0.3)", color:"#3b82f6", borderRadius:6, fontSize:10, cursor:"pointer", fontFamily:"var(--font-ui)", letterSpacing:1 }}>
                            SKIP
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
