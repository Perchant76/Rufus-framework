// src/components/tabs/TabSecrets.tsx
// JS Secret Scanner — displays discovered secrets from JS files
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SecretMatch {
  id: string; scan_id: string; js_url: string; rule_name: string;
  matched_text: string; full_match: string; severity: string;
  line_number?: number; context: string; found_at: string;
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#f59e0b", LOW:"#3b82f6"
};

interface Props { currentScanId: string | null; findings: any[]; }

export default function TabSecrets({ currentScanId, findings }: Props) {
  const [secrets, setSecrets] = useState<SecretMatch[]>([]);
  const [scanning, setScanning] = useState(false);
  const [selected, setSelected] = useState<SecretMatch | null>(null);
  const [filter, setFilter] = useState<string>("ALL");
  const [scanStatus, setScanStatus] = useState("");

  // Extract JS URLs from discovered findings
  const jsUrls = findings
    .filter(f => f.affected_url?.match(/\.js(\?|$)/))
    .map(f => f.affected_url)
    .filter((v, i, a) => a.indexOf(v) === i)
    .slice(0, 100); // cap at 100 JS files

  const runScan = async () => {
    if (!currentScanId || jsUrls.length === 0) return;
    setScanning(true); setSecrets([]); setScanStatus("Scanning JS files for secrets...");
    try {
      const result = await invoke<SecretMatch[]>("scan_js_for_secrets", {
        scanId: currentScanId, jsUrls,
      });
      setSecrets(result);
      setScanStatus(`Scan complete — ${result.length} secret${result.length !== 1 ? "s" : ""} found in ${jsUrls.length} JS files`);
    } catch(e) {
      setScanStatus(`Error: ${e}`);
    }
    setScanning(false);
  };

  const displayed = filter === "ALL" ? secrets : secrets.filter(s => s.severity === filter);

  const RULE_GROUPS = [...new Set(secrets.map(s => s.rule_name))].sort();

  return (
    <div style={{ display:"flex", height:"100%", overflow:"hidden", fontFamily:"var(--font-ui)" }}>
      {/* Left panel */}
      <div style={{ width:320, flexShrink:0, borderRight:"1px solid var(--border)", display:"flex", flexDirection:"column", overflow:"hidden" }}>
        <div style={{ padding:16, borderBottom:"1px solid var(--border)" }}>
          <div style={{ fontSize:12, color:"var(--accent)", letterSpacing:2, marginBottom:12, fontWeight:700 }}>
            🔍 JS SECRET SCANNER
          </div>
          <div style={{ fontSize:11, color:"var(--text-dim)", marginBottom:12, lineHeight:1.6 }}>
            Scans discovered JavaScript files for 30+ types of exposed secrets including API keys, tokens, database URLs, and private keys.
          </div>
          {jsUrls.length > 0 ? (
            <div style={{ fontSize:11, color:"var(--green)", marginBottom:10 }}>
              ✓ {jsUrls.length} JS file{jsUrls.length !== 1?"s":""} queued from discovery
            </div>
          ) : (
            <div style={{ fontSize:11, color:"var(--text-dim)", marginBottom:10 }}>
              No JS files found yet — run a scan with Katana/GAU first
            </div>
          )}
          <button onClick={runScan} disabled={scanning || jsUrls.length === 0 || !currentScanId}
            style={{ width:"100%", padding:"9px 0", background:scanning?"var(--bg3)":"var(--accent)", color:"#fff", border:"none", borderRadius:"var(--r)", fontSize:11, fontFamily:"var(--font-ui)", fontWeight:700, letterSpacing:2, cursor:scanning||jsUrls.length===0||!currentScanId?"not-allowed":"pointer", opacity:scanning||jsUrls.length===0||!currentScanId?0.5:1 }}>
            {scanning ? "SCANNING..." : "▶ SCAN FOR SECRETS"}
          </button>
          {scanStatus && <div style={{ marginTop:8, fontSize:10, color: secrets.length > 0 ? "var(--red)" : "var(--text-dim)", lineHeight:1.5 }}>{scanStatus}</div>}
        </div>

        {/* Severity filter */}
        <div style={{ padding:"8px 12px", borderBottom:"1px solid var(--border)", display:"flex", gap:4, flexWrap:"wrap" }}>
          {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
            <button key={s} onClick={()=>setFilter(s)} style={{ padding:"3px 8px", fontSize:10, fontFamily:"var(--font-ui)", letterSpacing:1, border:`1px solid ${filter===s?SEV_COLOR[s]??"var(--accent)":"var(--border)"}`, borderRadius:4, background:filter===s?"rgba(232,0,26,0.08)":"transparent", color:filter===s?SEV_COLOR[s]??"var(--accent)":"var(--text-dim)", cursor:"pointer" }}>
              {s} {s!=="ALL"&&`(${secrets.filter(x=>x.severity===s).length})`}
            </button>
          ))}
        </div>

        {/* Secret list */}
        <div style={{ flex:1, overflowY:"auto" }}>
          {displayed.length === 0 ? (
            <div style={{ padding:32, textAlign:"center", color:"var(--text-dim)", fontSize:11 }}>
              {scanning ? "Scanning..." : secrets.length === 0 ? "No secrets found yet" : "No secrets match filter"}
            </div>
          ) : displayed.map(s => (
            <div key={s.id} onClick={()=>setSelected(s)}
              style={{ padding:"10px 14px", borderBottom:"1px solid rgba(255,255,255,0.04)", cursor:"pointer", background:selected?.id===s.id?"rgba(232,0,26,0.06)":"transparent", borderLeft:`2px solid ${selected?.id===s.id?SEV_COLOR[s.severity]??"var(--accent)":"transparent"}` }}>
              <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                <span style={{ fontSize:9, fontWeight:700, background:`${SEV_COLOR[s.severity]???"#666"}22`, color:SEV_COLOR[s.severity]??"#666", border:`1px solid ${SEV_COLOR[s.severity]??"#666"}44`, padding:"1px 6px", borderRadius:3, letterSpacing:1 }}>{s.severity}</span>
              </div>
              <div style={{ fontSize:11, color:"#f0f0f0", fontWeight:600, marginBottom:2 }}>{s.rule_name}</div>
              <div style={{ fontSize:10, color:"var(--text-dim)", fontFamily:"var(--font-mono)", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{s.js_url.split('/').pop()}</div>
              {s.line_number && <div style={{ fontSize:9, color:"var(--text-dim)", marginTop:2 }}>Line {s.line_number}</div>}
            </div>
          ))}
        </div>

        {/* Stats footer */}
        {secrets.length > 0 && (
          <div style={{ padding:"8px 14px", borderTop:"1px solid var(--border)", display:"flex", gap:14 }}>
            {["CRITICAL","HIGH","MEDIUM"].map(s => {
              const n = secrets.filter(x=>x.severity===s).length;
              return n > 0 ? <div key={s} style={{ textAlign:"center" }}><div style={{ fontSize:16, fontWeight:800, color:SEV_COLOR[s] }}>{n}</div><div style={{ fontSize:9, color:"var(--text-dim)" }}>{s}</div></div> : null;
            })}
          </div>
        )}
      </div>

      {/* Right detail panel */}
      <div style={{ flex:1, overflowY:"auto", padding:24 }}>
        {!selected ? (
          <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"80%", textAlign:"center" }}>
            <div style={{ fontSize:48, marginBottom:16, opacity:0.15 }}>🔑</div>
            <div style={{ fontSize:14, color:"#f0f0f0", fontWeight:700, marginBottom:8 }}>JS Secret Scanner</div>
            <div style={{ fontSize:12, color:"var(--text-dim)", maxWidth:380, lineHeight:1.7 }}>
              Analyses discovered JavaScript files for 30+ types of leaked secrets. Select a finding from the list to see full details.
            </div>
            <div style={{ marginTop:24, display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, maxWidth:400, width:"100%" }}>
              {["AWS Keys","GitHub Tokens","Stripe/Payment","Database URLs","Private Keys","Slack Webhooks","Firebase Config","OAuth Secrets"].map(r => (
                <div key={r} style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:6, padding:"8px 12px", fontSize:11, color:"var(--text-dim)" }}>
                  ✓ {r}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:20 }}>
              <span style={{ fontSize:10, fontWeight:700, background:`${SEV_COLOR[selected.severity]???"#666"}22`, color:SEV_COLOR[selected.severity]??"#666", border:`1px solid ${SEV_COLOR[selected.severity]??"#666"}44`, padding:"3px 10px", borderRadius:4, letterSpacing:1 }}>{selected.severity}</span>
              <h2 style={{ margin:0, fontSize:16, fontWeight:800, color:"#fff" }}>{selected.rule_name}</h2>
            </div>

            {[
              { label:"Source File", val:selected.js_url },
              { label:"Line Number", val:selected.line_number?.toString() ?? "Unknown" },
              { label:"Redacted Match", val:selected.matched_text, mono:true },
              { label:"Context", val:selected.context, mono:true, code:true },
            ].map(({ label, val, mono, code }) => (
              <div key={label} style={{ marginBottom:16 }}>
                <div style={{ fontSize:10, fontWeight:700, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:1, marginBottom:6 }}>{label}</div>
                <div style={{ background: code ? "#0a0a0a" : "var(--bg2)", border:`1px solid ${code ? "var(--border)" : "var(--border)"}`, borderRadius:6, padding:"10px 14px", fontSize:12, color: code ? "#22c55e" : "#d4d4d4", fontFamily: mono ? "var(--font-mono)" : "inherit", wordBreak:"break-all", lineHeight:1.6 }}>{val}</div>
              </div>
            ))}

            <div style={{ marginBottom:16 }}>
              <div style={{ fontSize:10, fontWeight:700, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:1, marginBottom:6 }}>Remediation</div>
              <div style={{ background:"rgba(34,197,94,0.05)", border:"1px solid rgba(34,197,94,0.2)", borderRadius:6, padding:"10px 14px", fontSize:12, color:"#d4d4d4", lineHeight:1.7 }}>
                1. Rotate/revoke the exposed credential immediately.<br/>
                2. Move all secrets to server-side environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).<br/>
                3. Implement pre-commit hooks (git-secrets, gitleaks) to prevent future exposure.<br/>
                4. Audit Git history for historical exposure of the same secret.
              </div>
            </div>

            <div style={{ display:"flex", gap:10 }}>
              <button onClick={()=>navigator.clipboard.writeText(selected.js_url)} style={{ padding:"7px 14px", background:"var(--bg2)", border:"1px solid var(--border)", color:"var(--text-dim)", borderRadius:"var(--r)", fontSize:11, cursor:"pointer", fontFamily:"var(--font-ui)" }}>Copy URL</button>
              <button onClick={()=>navigator.clipboard.writeText(selected.context)} style={{ padding:"7px 14px", background:"var(--bg2)", border:"1px solid var(--border)", color:"var(--text-dim)", borderRadius:"var(--r)", fontSize:11, cursor:"pointer", fontFamily:"var(--font-ui)" }}>Copy Context</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
