// src/components/tabs/TabPenForgeExport.tsx
// Export Rufus findings to PenForge .ptsync + scope enforcement UI
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";

interface PreviewStats {
  total: number; critical: number; high: number;
  medium: number; low: number; info: number; out_of_scope: number;
}

interface Props { currentScanId: string | null; scopeList: string[]; }

export default function TabPenForgeExport({ currentScanId, scopeList }: Props) {
  const [preview, setPreview] = useState<PreviewStats | null>(null);
  const [operatorName, setOperatorName] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string[]>(["CRITICAL","HIGH","MEDIUM","LOW"]);
  const [exporting, setExporting] = useState(false);
  const [status, setStatus] = useState("");
  const [outOfScopeMode, setOutOfScopeMode] = useState<"exclude"|"include">("exclude");

  useEffect(() => { if (currentScanId) loadPreview(); }, [currentScanId]);

  const loadPreview = async () => {
    if (!currentScanId) return;
    try {
      const stats = await invoke<PreviewStats>("get_ptsync_preview", { scanId: currentScanId });
      setPreview(stats);
    } catch { /* no scan yet */ }
  };

  const toggleSev = (s: string) => setSeverityFilter(f => f.includes(s) ? f.filter(x=>x!==s) : [...f,s]);

  const handleExport = async () => {
    if (!currentScanId) return;
    const outputPath = await saveDialog({
      defaultPath: `rufus-export-${new Date().toISOString().slice(0,10)}.ptsync`,
      filters: [{ name:"PenForge PTSync", extensions:["ptsync"] }],
    });
    if (!outputPath) return;
    setExporting(true);
    try {
      const result = await invoke<string>("export_to_ptsync", {
        scanId: currentScanId,
        operatorName,
        outputPath,
        severityFilter,
      });
      setStatus(`✓ ${result}`);
    } catch(e) { setStatus(`Error: ${e}`); }
    setExporting(false);
  };

  const SEV_COLORS: Record<string,string> = { CRITICAL:"#ef4444",HIGH:"#f97316",MEDIUM:"#f59e0b",LOW:"#3b82f6",INFO:"#71717a" };

  return (
    <div style={{ display:"flex", height:"100%", overflow:"hidden", fontFamily:"var(--font-ui)" }}>
      <div style={{ flex:1, overflowY:"auto", padding:24, maxWidth:800 }}>
        <div style={{ fontSize:14, color:"var(--accent)", letterSpacing:2, marginBottom:4, fontWeight:700 }}>🛡 EXPORT TO PENFORGE</div>
        <div style={{ fontSize:12, color:"var(--text-dim)", marginBottom:24, lineHeight:1.7 }}>
          Export Rufus findings directly to PenForge's <span style={{ color:"#f0f0f0", fontFamily:"var(--font-mono)" }}>.ptsync</span> format. Open PenForge → Universal Importer → drop the file to import all findings into any project.
        </div>

        {/* Preview stats */}
        {preview && (
          <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:10, padding:20, marginBottom:24 }}>
            <div style={{ fontSize:11, color:"var(--text-dim)", letterSpacing:1, marginBottom:14 }}>SCAN FINDINGS SUMMARY</div>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:12, marginBottom:14 }}>
              {[["CRITICAL","#ef4444"],["HIGH","#f97316"],["MEDIUM","#f59e0b"],["LOW","#3b82f6"],["INFO","#71717a"]].map(([s,c]) => (
                <div key={s} style={{ textAlign:"center", background:`${c}11`, border:`1px solid ${c}33`, borderRadius:8, padding:"10px 4px" }}>
                  <div style={{ fontSize:22, fontWeight:800, color:c }}>{(preview as any)[s.toLowerCase()]}</div>
                  <div style={{ fontSize:9, color:"var(--text-dim)", marginTop:2 }}>{s}</div>
                </div>
              ))}
              <div style={{ textAlign:"center", background:"rgba(113,113,122,0.08)", border:"1px solid rgba(113,113,122,0.2)", borderRadius:8, padding:"10px 4px" }}>
                <div style={{ fontSize:22, fontWeight:800, color:"#71717a" }}>{preview.out_of_scope}</div>
                <div style={{ fontSize:9, color:"var(--text-dim)", marginTop:2 }}>OUT OF SCOPE</div>
              </div>
            </div>
            <div style={{ fontSize:11, color:"var(--text-dim)" }}>
              {preview.out_of_scope > 0
                ? `⚠ ${preview.out_of_scope} out-of-scope finding${preview.out_of_scope!==1?"s":""} will be excluded from export (scope enforcement active)`
                : `✓ All ${preview.total} findings are in scope`}
            </div>
          </div>
        )}

        {/* Severity filter */}
        <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:10, padding:20, marginBottom:20 }}>
          <div style={{ fontSize:11, color:"var(--text-dim)", letterSpacing:1, marginBottom:14 }}>EXPORT SEVERITY FILTER</div>
          <div style={{ display:"flex", gap:10, flexWrap:"wrap" }}>
            {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s => {
              const active = severityFilter.includes(s);
              const c = SEV_COLORS[s];
              return (
                <button key={s} onClick={()=>toggleSev(s)} style={{ padding:"7px 14px", borderRadius:8, border:`2px solid ${active?c:"var(--border)"}`, background:active?`${c}18`:"transparent", color:active?c:"var(--text-dim)", fontSize:11, fontWeight:700, letterSpacing:1, cursor:"pointer", fontFamily:"var(--font-ui)", transition:"all 0.15s" }}>
                  {active ? "✓ " : ""}{s}
                </button>
              );
            })}
          </div>
          <div style={{ marginTop:10, fontSize:11, color:"var(--text-dim)" }}>
            INFO findings are typically subdomain/port discoveries — uncheck to exclude from report.
          </div>
        </div>

        {/* Scope summary */}
        {scopeList.length > 0 && (
          <div style={{ background:"var(--bg2)", border:"1px solid rgba(34,197,94,0.2)", borderRadius:10, padding:16, marginBottom:20 }}>
            <div style={{ fontSize:11, color:"var(--green)", letterSpacing:1, marginBottom:10, fontWeight:700 }}>🎯 SCOPE ENFORCEMENT ACTIVE</div>
            <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
              {scopeList.map(s => (
                <span key={s} style={{ fontSize:10, color:"var(--green)", background:"rgba(34,197,94,0.08)", border:"1px solid rgba(34,197,94,0.25)", padding:"2px 8px", borderRadius:4, fontFamily:"var(--font-mono)" }}>{s}</span>
              ))}
            </div>
            <div style={{ marginTop:10, fontSize:11, color:"var(--text-dim)" }}>
              Only findings with affected URLs matching these scope entries will be exported.
            </div>
          </div>
        )}

        {/* Operator name */}
        <div style={{ marginBottom:20 }}>
          <div style={{ fontSize:11, color:"var(--text-dim)", letterSpacing:1, marginBottom:8 }}>OPERATOR NAME (for .ptsync header)</div>
          <input value={operatorName} onChange={e=>setOperatorName(e.target.value)} placeholder="Your name or team name..."
            style={{ width:"100%", background:"var(--bg2)", border:"1px solid var(--border)", color:"#f0f0f0", borderRadius:8, padding:"9px 12px", fontSize:13, outline:"none", fontFamily:"var(--font-ui)", boxSizing:"border-box" }}
            onFocus={e=>(e.target.style.borderColor="var(--accent)")} onBlur={e=>(e.target.style.borderColor="var(--border)")}/>
        </div>

        {/* How to use */}
        <div style={{ background:"rgba(59,130,246,0.05)", border:"1px solid rgba(59,130,246,0.2)", borderRadius:10, padding:16, marginBottom:24 }}>
          <div style={{ fontSize:11, color:"#3b82f6", letterSpacing:1, marginBottom:10, fontWeight:700 }}>📋 HOW TO IMPORT INTO PENFORGE</div>
          <ol style={{ paddingLeft:0, listStyle:"none", display:"flex", flexDirection:"column", gap:6 }}>
            {[
              "Click Export below to save the .ptsync file",
              "Open PenForge → click Universal Importer in the sidebar",
              "Drop or browse to the .ptsync file",
              "Select your target project and click Import",
            ].map((step, i) => (
              <li key={i} style={{ display:"flex", gap:12, fontSize:12, color:"var(--text-dim)" }}>
                <span style={{ color:"#3b82f6", fontWeight:700, flexShrink:0 }}>{i+1}.</span>
                {step}
              </li>
            ))}
          </ol>
        </div>

        {/* Export button */}
        <button onClick={handleExport} disabled={exporting || !currentScanId || severityFilter.length === 0}
          style={{ display:"flex", alignItems:"center", gap:10, padding:"12px 28px", background: exporting||!currentScanId?"var(--bg3)":"var(--accent)", color:"#fff", border:"none", borderRadius:10, fontSize:12, fontWeight:700, letterSpacing:2, cursor:exporting||!currentScanId?"not-allowed":"pointer", fontFamily:"var(--font-ui)", boxShadow: exporting||!currentScanId?"none":"0 0 20px rgba(232,0,26,0.3)", transition:"all 0.15s" }}>
          {exporting ? "EXPORTING..." : "⬇ EXPORT AS .PTSYNC"}
        </button>
        {status && (
          <div style={{ marginTop:12, padding:"10px 16px", background:status.startsWith("✓")?"rgba(34,197,94,0.08)":"rgba(239,68,68,0.08)", border:`1px solid ${status.startsWith("✓")?"rgba(34,197,94,0.25)":"rgba(239,68,68,0.25)"}`, borderRadius:8, fontSize:12, color:status.startsWith("✓")?"#22c55e":"#ef4444" }}>
            {status}
          </div>
        )}
      </div>
    </div>
  );
}
