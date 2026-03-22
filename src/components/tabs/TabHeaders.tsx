// src/components/tabs/TabHeaders.tsx
// Security header + CORS analysis tab
import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface HeaderFinding {
  url: string; check_name: string; severity: string;
  detail: string; remediation: string; header_value?: string;
}

const SEV_COLOR: Record<string,string> = { CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#f59e0b", LOW:"#3b82f6", INFO:"#71717a" };

interface Props { currentScanId: string | null; assets: any[]; }

export default function TabHeaders({ currentScanId, assets }: Props) {
  const [findings, setFindings] = useState<HeaderFinding[]>([]);
  const [scanning, setScanning] = useState(false);
  const [selected, setSelected] = useState<HeaderFinding | null>(null);
  const [filter, setFilter] = useState<string>("ALL");
  const [scanStatus, setScanStatus] = useState("");
  const [customUrls, setCustomUrls] = useState("");

  // Pull live HTTP hosts from assets
  const liveUrls = assets
    .filter(a => a.asset_type === "endpoint" || a.asset_type === "subdomain")
    .filter(a => a.http_status && a.value.startsWith("http"))
    .map(a => a.value)
    .filter((v, i, arr) => arr.indexOf(v) === i)
    .slice(0, 50);

  const runScan = async () => {
    if (!currentScanId) return;
    const urls = [
      ...liveUrls,
      ...customUrls.split("\n").map(u => u.trim()).filter(u => u.startsWith("http")),
    ].filter((v, i, a) => a.indexOf(v) === i);

    if (urls.length === 0) { setScanStatus("No URLs to scan. Add custom URLs or run a discovery scan first."); return; }
    setScanning(true); setFindings([]); setScanStatus(`Checking headers on ${urls.length} URLs...`);
    try {
      const result = await invoke<HeaderFinding[]>("check_security_headers", {
        scanId: currentScanId, urls,
      });
      setFindings(result);
      const cors = result.filter(f => f.check_name.includes("CORS")).length;
      setScanStatus(`Complete — ${result.length} issues found (${cors} CORS issues) across ${urls.length} URLs`);
    } catch(e) { setScanStatus(`Error: ${e}`); }
    setScanning(false);
  };

  const displayed = filter === "ALL" ? findings : findings.filter(f => f.severity === filter);
  const bySeverity = (s: string) => findings.filter(f => f.severity === s).length;
  const corsIssues = findings.filter(f => f.check_name.includes("CORS"));

  const groupedByUrl = displayed.reduce((acc, f) => {
    const host = f.url.replace(/https?:\/\//, "").split("/")[0];
    if (!acc[host]) acc[host] = [];
    acc[host].push(f);
    return acc;
  }, {} as Record<string, HeaderFinding[]>);

  return (
    <div style={{ display:"flex", height:"100%", overflow:"hidden", fontFamily:"var(--font-ui)" }}>
      {/* Left controls */}
      <div style={{ width:340, flexShrink:0, borderRight:"1px solid var(--border)", display:"flex", flexDirection:"column", overflow:"hidden" }}>
        <div style={{ padding:16, borderBottom:"1px solid var(--border)" }}>
          <div style={{ fontSize:12, color:"var(--accent)", letterSpacing:2, marginBottom:10, fontWeight:700 }}>🛡 HEADER & CORS ANALYSER</div>
          <div style={{ fontSize:11, color:"var(--text-dim)", marginBottom:12, lineHeight:1.6 }}>
            Checks security headers (HSTS, CSP, X-Frame-Options, etc.) and detects CORS misconfigurations by probing with an attacker-controlled Origin.
          </div>

          {liveUrls.length > 0 && (
            <div style={{ background:"rgba(34,197,94,0.05)", border:"1px solid rgba(34,197,94,0.2)", borderRadius:6, padding:"8px 12px", marginBottom:10, fontSize:11, color:"var(--green)" }}>
              ✓ {liveUrls.length} live URL{liveUrls.length!==1?"s":""} from discovery scan
            </div>
          )}

          <div style={{ marginBottom:10 }}>
            <div style={{ fontSize:10, color:"var(--text-dim)", letterSpacing:1, marginBottom:6 }}>ADDITIONAL URLs (one per line)</div>
            <textarea value={customUrls} onChange={e=>setCustomUrls(e.target.value)} rows={4}
              placeholder={"https://api.target.com\nhttps://admin.target.com"}
              style={{ width:"100%", background:"var(--bg2)", border:"1px solid var(--border)", color:"#f0f0f0", borderRadius:6, padding:"8px 10px", fontSize:11, outline:"none", resize:"vertical", fontFamily:"var(--font-mono)", boxSizing:"border-box" }}/>
          </div>

          <button onClick={runScan} disabled={scanning || !currentScanId}
            style={{ width:"100%", padding:"9px 0", background:scanning?"var(--bg3)":"var(--accent)", color:"#fff", border:"none", borderRadius:"var(--r)", fontSize:11, fontFamily:"var(--font-ui)", fontWeight:700, letterSpacing:2, cursor:scanning||!currentScanId?"not-allowed":"pointer", opacity:scanning||!currentScanId?0.5:1 }}>
            {scanning ? "SCANNING..." : "▶ RUN ANALYSIS"}
          </button>
          {scanStatus && <div style={{ marginTop:8, fontSize:10, color:"var(--text-dim)", lineHeight:1.5 }}>{scanStatus}</div>}
        </div>

        {/* Stats */}
        {findings.length > 0 && (
          <div style={{ padding:"10px 14px", borderBottom:"1px solid var(--border)", display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:8 }}>
            {[["CRITICAL","#ef4444"],["HIGH","#f97316"],["MEDIUM","#f59e0b"],["LOW","#3b82f6"]].map(([s,c])=>(
              bySeverity(s) > 0 ? <div key={s} style={{ textAlign:"center", background:`${c}11`, border:`1px solid ${c}33`, borderRadius:6, padding:"6px 4px" }}>
                <div style={{ fontSize:18, fontWeight:800, color:c }}>{bySeverity(s)}</div>
                <div style={{ fontSize:9, color:"var(--text-dim)" }}>{s}</div>
              </div> : null
            ))}
            {corsIssues.length > 0 && (
              <div style={{ textAlign:"center", background:"rgba(168,85,247,0.1)", border:"1px solid rgba(168,85,247,0.3)", borderRadius:6, padding:"6px 4px" }}>
                <div style={{ fontSize:18, fontWeight:800, color:"#a855f7" }}>{corsIssues.length}</div>
                <div style={{ fontSize:9, color:"var(--text-dim)" }}>CORS</div>
              </div>
            )}
          </div>
        )}

        {/* Severity filter */}
        {findings.length > 0 && (
          <div style={{ padding:"6px 12px", borderBottom:"1px solid var(--border)", display:"flex", gap:4, flexWrap:"wrap" }}>
            {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
              <button key={s} onClick={()=>setFilter(s)} style={{ padding:"2px 8px", fontSize:10, letterSpacing:1, border:`1px solid ${filter===s?(SEV_COLOR[s]??"var(--accent)"):"var(--border)"}`, borderRadius:3, background:filter===s?"rgba(232,0,26,0.08)":"transparent", color:filter===s?(SEV_COLOR[s]??"var(--accent)"):"var(--text-dim)", cursor:"pointer", fontFamily:"var(--font-ui)" }}>
                {s}
              </button>
            ))}
          </div>
        )}

        {/* Finding list */}
        <div style={{ flex:1, overflowY:"auto" }}>
          {Object.entries(groupedByUrl).map(([host, hf]) => (
            <div key={host}>
              <div style={{ padding:"6px 14px", fontSize:9, color:"var(--text-dim)", letterSpacing:1, background:"rgba(255,255,255,0.02)", borderBottom:"1px solid var(--border)", textTransform:"uppercase" }}>
                {host} ({hf.length})
              </div>
              {hf.map((f, i) => (
                <div key={i} onClick={()=>setSelected(f)}
                  style={{ padding:"9px 14px", borderBottom:"1px solid rgba(255,255,255,0.04)", cursor:"pointer", background:selected?.check_name===f.check_name&&selected?.url===f.url?"rgba(232,0,26,0.06)":"transparent", borderLeft:`2px solid ${selected?.check_name===f.check_name&&selected?.url===f.url?(SEV_COLOR[f.severity]??"var(--accent)"):"transparent"}` }}>
                  <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:3 }}>
                    <span style={{ fontSize:9, color:SEV_COLOR[f.severity]??"#666", fontWeight:700, letterSpacing:1 }}>{f.severity}</span>
                    {f.check_name.includes("CORS") && <span style={{ fontSize:9, color:"#a855f7", letterSpacing:1 }}>CORS</span>}
                  </div>
                  <div style={{ fontSize:11, color:"#f0f0f0", fontWeight:600 }}>{f.check_name}</div>
                </div>
              ))}
            </div>
          ))}
          {findings.length === 0 && !scanning && (
            <div style={{ padding:32, textAlign:"center", color:"var(--text-dim)", fontSize:11 }}>
              No findings yet. Run the analysis to check security headers.
            </div>
          )}
        </div>
      </div>

      {/* Right detail */}
      <div style={{ flex:1, overflowY:"auto", padding:24 }}>
        {!selected ? (
          <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"80%", textAlign:"center" }}>
            <div style={{ fontSize:48, marginBottom:16, opacity:0.15 }}>🛡</div>
            <div style={{ fontSize:14, color:"#f0f0f0", fontWeight:700, marginBottom:8 }}>Header & CORS Analyser</div>
            <div style={{ fontSize:12, color:"var(--text-dim)", maxWidth:380, lineHeight:1.7 }}>
              Checks 7 security headers and 3 CORS misconfigurations per URL. Select a finding for full details and remediation guidance.
            </div>
            <div style={{ marginTop:24, display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, maxWidth:400 }}>
              {["HSTS","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy","Permissions-Policy","CORS Origin Reflection","CORS + Credentials","Server Disclosure"].map(h => (
                <div key={h} style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:6, padding:"7px 12px", fontSize:11, color:"var(--text-dim)" }}>
                  ✓ {h}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:20 }}>
              <span style={{ fontSize:10, fontWeight:700, background:`${SEV_COLOR[selected.severity]??"#666"}22`, color:SEV_COLOR[selected.severity]??"#666", border:`1px solid ${SEV_COLOR[selected.severity]??"#666"}44`, padding:"3px 10px", borderRadius:4, letterSpacing:1 }}>{selected.severity}</span>
              {selected.check_name.includes("CORS") && <span style={{ fontSize:10, fontWeight:700, background:"rgba(168,85,247,0.1)", color:"#a855f7", border:"1px solid rgba(168,85,247,0.3)", padding:"3px 10px", borderRadius:4, letterSpacing:1 }}>CORS</span>}
              <h2 style={{ margin:0, fontSize:16, fontWeight:800, color:"#fff" }}>{selected.check_name}</h2>
            </div>

            {[
              { label:"Affected URL", val:selected.url },
              { label:"Detail", val:selected.detail },
              ...(selected.header_value ? [{ label:"Header Value", val:selected.header_value }] : []),
              { label:"Remediation", val:selected.remediation, green:true },
            ].map(({ label, val, green }) => (
              <div key={label} style={{ marginBottom:16 }}>
                <div style={{ fontSize:10, fontWeight:700, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:1, marginBottom:6 }}>{label}</div>
                <div style={{ background: green ? "rgba(34,197,94,0.05)" : "var(--bg2)", border:`1px solid ${green?"rgba(34,197,94,0.2)":"var(--border)"}`, borderRadius:6, padding:"10px 14px", fontSize:12, color:"#d4d4d4", lineHeight:1.7, fontFamily: label==="Header Value"?"var(--font-mono)":"inherit", wordBreak:"break-all" }}>{val}</div>
              </div>
            ))}
            <button onClick={()=>navigator.clipboard.writeText(selected.url)} style={{ padding:"7px 14px", background:"var(--bg2)", border:"1px solid var(--border)", color:"var(--text-dim)", borderRadius:"var(--r)", fontSize:11, cursor:"pointer", fontFamily:"var(--font-ui)" }}>Copy URL</button>
          </div>
        )}
      </div>
    </div>
  );
}
