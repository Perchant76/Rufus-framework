// src/components/tabs/TabScope.tsx
// Scope enforcement — define in/out of scope, rate limiting, session resume
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ScanSession { scan_id: string; target: string; current_phase: number; completed_phases: number[]; saved_at: string; }
interface Props {
  scope: string[]; onScopeChange: (s: string[]) => void;
  rateLimitMs: number; onRateLimitChange: (ms: number) => void;
  excludePatterns: string[]; onExcludeChange: (p: string[]) => void;
}

export default function TabScope({ scope, onScopeChange, rateLimitMs, onRateLimitChange, excludePatterns, onExcludeChange }: Props) {
  const [scopeInput, setScopeInput] = useState("");
  const [excludeInput, setExcludeInput] = useState("");
  const [sessions, setSessions] = useState<ScanSession[]>([]);
  const [sessionStatus, setSessionStatus] = useState("");
  const [activePreset, setActivePreset] = useState<string>("custom");

  useEffect(() => { loadSessions(); }, []);

  const loadSessions = async () => {
    try {
      const s = await invoke<ScanSession[]>("list_interrupted_scans");
      setSessions(s);
    } catch { /* none */ }
  };

  const addScope = () => {
    const entries = scopeInput.split("\n").map(s => s.trim()).filter(s => s && !scope.includes(s));
    if (entries.length) { onScopeChange([...scope, ...entries]); setScopeInput(""); }
  };

  const addExclude = () => {
    const entries = excludeInput.split("\n").map(s => s.trim()).filter(s => s && !excludePatterns.includes(s));
    if (entries.length) { onExcludeChange([...excludePatterns, ...entries]); setExcludeInput(""); }
  };

  const clearSession = async (scanId: string) => {
    await invoke("clear_scan_session", { scanId });
    await loadSessions();
    setSessionStatus(`Session for ${scanId.slice(0,8)}... cleared.`);
  };

  const RATE_PRESETS = [
    { label:"Aggressive",   ms:0,    desc:"No delay — maximum speed, high noise", color:"#ef4444" },
    { label:"Normal",       ms:200,  desc:"200ms delay — typical recon speed",    color:"#f59e0b" },
    { label:"Careful",      ms:1000, desc:"1s delay — less likely to trigger WAF",color:"#3b82f6" },
    { label:"Stealth",      ms:3000, desc:"3s delay — very low noise profile",    color:"#22c55e" },
  ];

  const SCOPE_EXAMPLES = [
    { label:"Single domain",  ex:"target.com" },
    { label:"Wildcard",       ex:"*.target.com" },
    { label:"CIDR range",     ex:"10.0.0.0/24" },
    { label:"Exact IP",       ex:"192.168.1.50" },
    { label:"Subdomain",      ex:"api.target.com" },
  ];

  return (
    <div style={{ height:"100%", overflowY:"auto", fontFamily:"var(--font-ui)" }}>
      <div style={{ padding:24, maxWidth:900, display:"flex", flexDirection:"column", gap:24 }}>
        <div>
          <div style={{ fontSize:14, color:"var(--accent)", letterSpacing:2, fontWeight:700, marginBottom:4 }}>🎯 SCOPE & RATE CONTROL</div>
          <div style={{ fontSize:12, color:"var(--text-dim)", lineHeight:1.7 }}>
            Define what is in scope, block out-of-scope assets from being tested or reported, set per-request rate limiting, and resume interrupted scans.
          </div>
        </div>

        {/* Scope definition */}
        <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:10, padding:20 }}>
          <div style={{ fontSize:12, color:"#f0f0f0", fontWeight:700, letterSpacing:1, marginBottom:4 }}>IN-SCOPE TARGETS</div>
          <div style={{ fontSize:11, color:"var(--text-dim)", marginBottom:14 }}>Findings outside this scope are flagged but excluded from exports and reports.</div>

          <div style={{ display:"flex", gap:10, flexWrap:"wrap", marginBottom:14 }}>
            {SCOPE_EXAMPLES.map(e => (
              <button key={e.label} onClick={()=>setScopeInput(v=>v?v+"\n"+e.ex:e.ex)}
                style={{ padding:"5px 10px", background:"var(--bg3)", border:"1px solid var(--border)", color:"var(--text-dim)", borderRadius:6, fontSize:10, cursor:"pointer", fontFamily:"var(--font-mono)", letterSpacing:0.5 }}
                title={`Add example: ${e.ex}`}>{e.label}</button>
            ))}
          </div>

          <div style={{ display:"flex", gap:10, marginBottom:14 }}>
            <textarea value={scopeInput} onChange={e=>setScopeInput(e.target.value)} rows={4}
              placeholder={"target.com\n*.target.com\n10.0.0.0/24"}
              style={{ flex:1, background:"var(--bg3)", border:"1px solid var(--border)", color:"#f0f0f0", borderRadius:8, padding:"10px 12px", fontSize:12, outline:"none", resize:"vertical", fontFamily:"var(--font-mono)", boxSizing:"border-box" }}
              onFocus={e=>(e.target.style.borderColor="var(--accent)")} onBlur={e=>(e.target.style.borderColor="var(--border)")}/>
            <button onClick={addScope} style={{ alignSelf:"flex-start", padding:"9px 16px", background:"var(--accent)", color:"#fff", border:"none", borderRadius:8, fontSize:11, fontWeight:700, letterSpacing:1, cursor:"pointer", fontFamily:"var(--font-ui)", flexShrink:0 }}>ADD</button>
          </div>

          {scope.length > 0 ? (
            <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
              {scope.map(s => (
                <div key={s} style={{ display:"flex", alignItems:"center", gap:6, background:"rgba(34,197,94,0.08)", border:"1px solid rgba(34,197,94,0.25)", borderRadius:6, padding:"4px 10px" }}>
                  <span style={{ fontSize:11, color:"var(--green)", fontFamily:"var(--font-mono)" }}>{s}</span>
                  <button onClick={()=>onScopeChange(scope.filter(x=>x!==s))} style={{ background:"none", border:"none", color:"rgba(34,197,94,0.5)", cursor:"pointer", fontSize:14, lineHeight:1, padding:0 }} onMouseEnter={e=>(e.currentTarget.style.color="#22c55e")} onMouseLeave={e=>(e.currentTarget.style.color="rgba(34,197,94,0.5)")}>×</button>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ fontSize:11, color:"var(--text-dim)" }}>⚠ No scope defined — all findings will be marked in-scope by default</div>
          )}
        </div>

        {/* Out-of-scope exclude patterns */}
        <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:10, padding:20 }}>
          <div style={{ fontSize:12, color:"#f0f0f0", fontWeight:700, letterSpacing:1, marginBottom:4 }}>OUT-OF-SCOPE EXCLUSIONS</div>
          <div style={{ fontSize:11, color:"var(--text-dim)", marginBottom:14 }}>These patterns are explicitly excluded — tools will not test them and findings will be suppressed.</div>

          <div style={{ display:"flex", gap:10, marginBottom:14 }}>
            <textarea value={excludeInput} onChange={e=>setExcludeInput(e.target.value)} rows={3}
              placeholder={"staging.target.com\n*.cdn.target.com\n203.0.113.0/24"}
              style={{ flex:1, background:"var(--bg3)", border:"1px solid var(--border)", color:"#f0f0f0", borderRadius:8, padding:"10px 12px", fontSize:12, outline:"none", resize:"vertical", fontFamily:"var(--font-mono)", boxSizing:"border-box" }}
              onFocus={e=>(e.target.style.borderColor="var(--accent)")} onBlur={e=>(e.target.style.borderColor="var(--border)")}/>
            <button onClick={addExclude} style={{ alignSelf:"flex-start", padding:"9px 16px", background:"rgba(239,68,68,0.15)", border:"1px solid rgba(239,68,68,0.35)", color:"#ef4444", borderRadius:8, fontSize:11, fontWeight:700, letterSpacing:1, cursor:"pointer", fontFamily:"var(--font-ui)", flexShrink:0 }}>EXCLUDE</button>
          </div>

          {excludePatterns.length > 0 && (
            <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
              {excludePatterns.map(p => (
                <div key={p} style={{ display:"flex", alignItems:"center", gap:6, background:"rgba(239,68,68,0.08)", border:"1px solid rgba(239,68,68,0.25)", borderRadius:6, padding:"4px 10px" }}>
                  <span style={{ fontSize:11, color:"#ef4444", fontFamily:"var(--font-mono)" }}>✗ {p}</span>
                  <button onClick={()=>onExcludeChange(excludePatterns.filter(x=>x!==p))} style={{ background:"none", border:"none", color:"rgba(239,68,68,0.4)", cursor:"pointer", fontSize:14, lineHeight:1, padding:0 }}>×</button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Rate limiting */}
        <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:10, padding:20 }}>
          <div style={{ fontSize:12, color:"#f0f0f0", fontWeight:700, letterSpacing:1, marginBottom:4 }}>RATE LIMITING</div>
          <div style={{ fontSize:11, color:"var(--text-dim)", marginBottom:16 }}>
            Controls the delay between requests globally. Lower values are faster but more likely to trigger WAF/IDS alerts or get your IP blocked.
          </div>

          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:10, marginBottom:16 }}>
            {RATE_PRESETS.map(p => (
              <button key={p.label} onClick={()=>{ setActivePreset(p.label); onRateLimitChange(p.ms); }}
                style={{ padding:"12px 8px", border:`2px solid ${rateLimitMs===p.ms?p.color:"var(--border)"}`, background:rateLimitMs===p.ms?`${p.color}15`:"var(--bg3)", borderRadius:8, cursor:"pointer", textAlign:"center", transition:"all 0.15s" }}>
                <div style={{ fontSize:13, fontWeight:700, color: rateLimitMs===p.ms?p.color:"#f0f0f0", marginBottom:4, fontFamily:"var(--font-ui)", letterSpacing:1 }}>{p.label}</div>
                <div style={{ fontSize:10, color:"var(--text-dim)", lineHeight:1.4 }}>{p.desc}</div>
              </button>
            ))}
          </div>

          <div style={{ display:"flex", alignItems:"center", gap:12 }}>
            <span style={{ fontSize:11, color:"var(--text-dim)" }}>Custom delay (ms):</span>
            <input type="number" min={0} max={30000} value={rateLimitMs} onChange={e=>{ setActivePreset("custom"); onRateLimitChange(parseInt(e.target.value)||0); }}
              style={{ width:100, background:"var(--bg3)", border:"1px solid var(--border)", color:"#f0f0f0", borderRadius:6, padding:"6px 10px", fontSize:13, outline:"none", fontFamily:"var(--font-mono)" }}
              onFocus={e=>(e.target.style.borderColor="var(--accent)")} onBlur={e=>(e.target.style.borderColor="var(--border)")}/>
            <span style={{ fontSize:11, color:"var(--text-dim)" }}>between requests</span>
          </div>
        </div>

        {/* Session resume */}
        <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:10, padding:20 }}>
          <div style={{ fontSize:12, color:"#f0f0f0", fontWeight:700, letterSpacing:1, marginBottom:4 }}>SESSION PERSISTENCE</div>
          <div style={{ fontSize:11, color:"var(--text-dim)", marginBottom:14, lineHeight:1.6 }}>
            Rufus saves scan progress automatically every phase. If a scan is interrupted (crash, power loss, manual abort), you can see interrupted sessions here. Results from completed phases are preserved in the findings database.
          </div>

          {sessions.length === 0 ? (
            <div style={{ fontSize:11, color:"var(--green)" }}>✓ No interrupted sessions — all scans completed normally</div>
          ) : (
            <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
              {sessions.map(s => (
                <div key={s.scan_id} style={{ display:"flex", alignItems:"center", gap:14, padding:"10px 14px", background:"var(--bg3)", border:"1px solid rgba(245,158,11,0.3)", borderRadius:8 }}>
                  <div style={{ width:8, height:8, borderRadius:"50%", background:"#f59e0b", flexShrink:0 }}/>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:11, color:"#f0f0f0", fontFamily:"var(--font-mono)", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                      {s.scan_id.slice(0,8)}... · Phase {s.current_phase} of 9 · {s.completed_phases.length} complete
                    </div>
                    <div style={{ fontSize:10, color:"var(--text-dim)", marginTop:2 }}>
                      Interrupted: {new Date(s.saved_at).toLocaleString()}
                    </div>
                  </div>
                  <button onClick={()=>clearSession(s.scan_id)}
                    style={{ padding:"5px 12px", background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.3)", color:"#ef4444", borderRadius:6, fontSize:10, cursor:"pointer", fontFamily:"var(--font-ui)", letterSpacing:1 }}>
                    CLEAR
                  </button>
                </div>
              ))}
            </div>
          )}
          {sessionStatus && <div style={{ marginTop:10, fontSize:11, color:"var(--text-dim)" }}>{sessionStatus}</div>}
          <div style={{ marginTop:14, fontSize:11, color:"var(--text-dim)", lineHeight:1.6 }}>
            <strong style={{ color:"#f0f0f0" }}>Auto-save:</strong> Phase results are written to disk after each phase completes. A crash after Phase 3 means Phases 1–3 findings are safe in the database — only the interrupted phase may have partial results.
          </div>
        </div>
      </div>
    </div>
  );
}
