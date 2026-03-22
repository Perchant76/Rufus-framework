// src/components/tabs/TabDashboard.tsx — Main Rufus Dashboard
import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
         XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import type { Scan, VulnFinding, DiscoveredAsset } from "../../types";

interface Props {
  scans: Scan[];
  findings: VulnFinding[];
  assets: DiscoveredAsset[];
  isRunning: boolean;
  onScanSelect: (id: string) => void;
  onScanDelete: (id: string) => void;
  onNavigate: (tab: string) => void;
}

const SEV_COLS: Record<string,string> = {
  CRITICAL:"#ff1a3d", HIGH:"#ff6b2b", MEDIUM:"#ffd700", LOW:"#00ff88", INFO:"#60a5fa"
};

const CARD: React.CSSProperties = {
  background:"#0f1117", border:"1px solid #1e2438",
  borderRadius:12, padding:20, position:"relative", overflow:"hidden",
};

const TT_STYLE = {
  contentStyle:{ background:"#0a0b0f", border:"1px solid #1e2438", borderRadius:8, color:"#fff", fontSize:11 },
  labelStyle:{ color:"#a0aec0", fontSize:10 },
  itemStyle:{ color:"#fff" },
};

export default function TabDashboard({ scans, findings, assets, isRunning, onScanSelect, onScanDelete, onNavigate }: Props) {
  const [confirmDeleteId, setConfirmDeleteId] = useState<string|null>(null);
  const [allFindings, setAllFindings] = useState<VulnFinding[]>([]);
  const [allAssets, setAllAssets]     = useState<DiscoveredAsset[]>([]);

  useEffect(() => {
    invoke<VulnFinding[]>("get_findings").then(f => setAllFindings(f)).catch(() => {});
    invoke<DiscoveredAsset[]>("list_assets_all").then(a => setAllAssets(a)).catch(() => {});
  }, [scans.length]);

  const combined = allFindings.length > 0 ? allFindings : findings;
  const inScope  = combined.filter(f => f.in_scope);

  // Stats
  const totalScans    = scans.length;
  const totalFindings = inScope.length;
  const critCount     = inScope.filter(f => f.severity === "CRITICAL").length;
  const highCount     = inScope.filter(f => f.severity === "HIGH").length;
  const uniqueTargets = [...new Set(scans.map(s => s.target))].length;
  const totalAssets   = (allAssets.length > 0 ? allAssets : assets).length;

  // Severity pie
  const sevData = (["CRITICAL","HIGH","MEDIUM","LOW","INFO"] as const).map(s => ({
    name: s, value: inScope.filter(f => f.severity === s).length, color: SEV_COLS[s],
  })).filter(d => d.value > 0);

  // Findings over time (last 10 scans)
  const timeData = scans.slice(-10).map(s => ({
    target: s.target.length > 12 ? s.target.slice(0,12)+"…" : s.target,
    findings: combined.filter(f => f.scan_id === s.id && f.in_scope).length,
    date: s.created_at.slice(0,10),
  }));

  // Top tools
  const toolHits: Record<string,number> = {};
  inScope.forEach(f => { toolHits[f.source_tool] = (toolHits[f.source_tool]??0)+1; });
  const topTools = Object.entries(toolHits).sort((a,b)=>b[1]-a[1]).slice(0,6);

  // Recent scans
  const recentScans = [...scans].sort((a,b) => b.created_at.localeCompare(a.created_at)).slice(0,5);

  // Helper for delete dialog
  const scanToDelete = confirmDeleteId ? scans.find(x => x.id === confirmDeleteId) : null;

  const StatCard = ({ label, value, sub, color }: { label:string; value:string|number; sub?:string; color?:string }) => (
    <div style={{ ...CARD }}>
      <div style={{ position:"absolute", top:0, left:0, right:0, height:2, background:color??"var(--accent)", opacity:0.8 }}/>
      <div style={{ fontSize:10, color:"#a0aec0", letterSpacing:2, textTransform:"uppercase", marginBottom:8 }}>{label}</div>
      <div style={{ fontSize:32, fontWeight:900, color:color??"#ffffff", lineHeight:1, fontFamily:"var(--font-ui)", filter:color?`drop-shadow(0 0 8px ${color})`:undefined }}>{value}</div>
      {sub && <div style={{ fontSize:10, color:"rgba(255,255,255,0.4)", marginTop:6 }}>{sub}</div>}
    </div>
  );

  return (
    <>
      <div style={{ height:"100%", overflowY:"auto", background:"#060608", fontFamily:"var(--font-mono)" }}>
        <div style={{ padding:24, display:"flex", flexDirection:"column", gap:20 }}>

          {/* Header */}
          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
            <div>
              <div style={{ fontSize:18, fontWeight:900, color:"#ffffff", letterSpacing:3, fontFamily:"var(--font-ui)" }}>
                COMMAND CENTER
              </div>
              <div style={{ fontSize:11, color:"rgba(255,255,255,0.35)", letterSpacing:2, marginTop:4 }}>
                {isRunning ? "⬤ SCAN ACTIVE" : `${totalScans} SCANS // ${uniqueTargets} TARGETS`}
              </div>
            </div>
            {isRunning && (
              <div style={{ padding:"8px 18px", background:"rgba(232,0,26,0.1)", border:"1px solid rgba(232,0,26,0.4)", borderRadius:8, fontSize:11, color:"#e8001a", letterSpacing:2, display:"flex", alignItems:"center", gap:8 }}>
                <span style={{ width:7, height:7, borderRadius:"50%", background:"#e8001a", display:"inline-block", animation:"pulse-red 1s infinite" }}/>
                SCANNING
              </div>
            )}
          </div>

          {/* Stat grid */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12 }}>
            <StatCard label="Total Scans"    value={totalScans}    sub={`${uniqueTargets} unique targets`} color="#60a5fa"/>
            <StatCard label="Total Findings" value={totalFindings} sub="in-scope only"                    color="#ffffff"/>
            <StatCard label="Critical"       value={critCount}     sub="immediate action"                 color="#ff1a3d"/>
            <StatCard label="High"           value={highCount}     sub="prioritised"                      color="#ff6b2b"/>
            <StatCard label="Assets"         value={totalAssets}   sub="discovered"                       color="#00ff88"/>
          </div>

          {/* Charts row */}
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16 }}>

            {/* Severity pie */}
            <div style={CARD}>
              <div style={{ fontSize:10, color:"#a0aec0", letterSpacing:2, marginBottom:14 }}>SEVERITY DISTRIBUTION</div>
              {sevData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={160}>
                    <PieChart>
                      <Pie data={sevData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value">
                        {sevData.map((d,i) => <Cell key={i} fill={d.color} stroke={`${d.color}44`} strokeWidth={1}/>)}
                      </Pie>
                      <Tooltip {...TT_STYLE}/>
                    </PieChart>
                  </ResponsiveContainer>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:8, marginTop:8 }}>
                    {sevData.map(d => (
                      <div key={d.name} style={{ display:"flex", alignItems:"center", gap:5, fontSize:10 }}>
                        <div style={{ width:8, height:8, borderRadius:2, background:d.color }}/>
                        <span style={{ color:"rgba(255,255,255,0.5)" }}>{d.name}</span>
                        <span style={{ color:"#fff", fontWeight:700 }}>{d.value}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div style={{ height:160, display:"flex", alignItems:"center", justifyContent:"center", color:"rgba(255,255,255,0.2)", fontSize:11 }}>No findings yet</div>
              )}
            </div>

            {/* Findings over time */}
            <div style={CARD}>
              <div style={{ fontSize:10, color:"#a0aec0", letterSpacing:2, marginBottom:14 }}>FINDINGS PER SCAN</div>
              {timeData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={timeData}>
                    <defs>
                      <linearGradient id="fg1" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#e8001a" stopOpacity={0.4}/>
                        <stop offset="95%" stopColor="#e8001a" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="target" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:9 }} axisLine={false} tickLine={false}/>
                    <YAxis tick={{ fill:"rgba(255,255,255,0.3)", fontSize:9 }} axisLine={false} tickLine={false} allowDecimals={false}/>
                    <Tooltip {...TT_STYLE}/>
                    <Area type="monotone" dataKey="findings" stroke="#e8001a" strokeWidth={2} fill="url(#fg1)"/>
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ height:200, display:"flex", alignItems:"center", justifyContent:"center", color:"rgba(255,255,255,0.2)", fontSize:11 }}>Run a scan to see data</div>
              )}
            </div>

            {/* Top tools */}
            <div style={CARD}>
              <div style={{ fontSize:10, color:"#a0aec0", letterSpacing:2, marginBottom:14 }}>TOP FINDING SOURCES</div>
              {topTools.length > 0 ? (
                <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
                  {topTools.map(([tool, count]) => {
                    const maxCount = topTools[0][1];
                    const pct = (count / maxCount) * 100;
                    return (
                      <div key={tool}>
                        <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                          <span style={{ fontSize:10, color:"#ffffff", fontFamily:"var(--font-mono)" }}>{tool}</span>
                          <span style={{ fontSize:10, color:"#e8001a", fontWeight:700 }}>{count}</span>
                        </div>
                        <div style={{ height:3, background:"rgba(255,255,255,0.06)", borderRadius:2 }}>
                          <div style={{ height:"100%", width:`${pct}%`, background:"linear-gradient(90deg, #8b0010, #e8001a)", borderRadius:2, boxShadow:"0 0 6px rgba(232,0,26,0.5)", transition:"width 0.5s ease" }}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ color:"rgba(255,255,255,0.2)", fontSize:11 }}>No data yet</div>
              )}
            </div>
          </div>

          {/* Recent scans */}
          <div style={CARD}>
            <div style={{ fontSize:10, color:"#a0aec0", letterSpacing:2, marginBottom:16 }}>RECENT SCANS</div>
            {recentScans.length === 0 ? (
              <div style={{ color:"rgba(255,255,255,0.2)", fontSize:11, textAlign:"center", padding:24 }}>
                No scans yet. Set a target and engage.
              </div>
            ) : (
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead>
                  <tr style={{ borderBottom:"1px solid rgba(255,255,255,0.06)" }}>
                    {["TARGET","TYPE","STATUS","FINDINGS","TOOLS","DATE",""].map(h => (
                      <th key={h} style={{ textAlign:"left", padding:"6px 12px", fontSize:9, color:"rgba(255,255,255,0.3)", letterSpacing:2, fontWeight:600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map(s => {
                    const sf = combined.filter(f => f.scan_id === s.id && f.in_scope);
                    const crit = sf.filter(f => f.severity === "CRITICAL").length;
                    const statusCol = s.status === "complete" ? "#00ff88" : s.status === "running" ? "#e8001a" : s.status === "stopped" ? "#ffd700" : "#60a5fa";
                    return (
                      <tr key={s.id}
                        onClick={() => onScanSelect(s.id)}
                        style={{ borderBottom:"1px solid rgba(255,255,255,0.04)", cursor:"pointer", transition:"background 0.1s" }}
                        onMouseEnter={e => (e.currentTarget.style.background="rgba(232,0,26,0.04)")}
                        onMouseLeave={e => (e.currentTarget.style.background="transparent")}>
                        <td style={{ padding:"10px 12px", fontSize:11, color:"#ffffff", fontFamily:"var(--font-mono)", fontWeight:600 }}>{s.target}</td>
                        <td style={{ padding:"10px 12px" }}>
                          <span style={{ fontSize:9, background:"rgba(96,165,250,0.12)", color:"#60a5fa", border:"1px solid rgba(96,165,250,0.3)", padding:"2px 7px", borderRadius:3, letterSpacing:1 }}>{s.target_type}</span>
                        </td>
                        <td style={{ padding:"10px 12px" }}>
                          <span style={{ fontSize:9, color:statusCol, fontWeight:700, letterSpacing:1, textTransform:"uppercase" }}>⬤ {s.status}</span>
                        </td>
                        <td style={{ padding:"10px 12px" }}>
                          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                            <span style={{ fontSize:12, fontWeight:700, color: crit > 0 ? "#ff1a3d" : "#fff" }}>{sf.length}</span>
                            {crit > 0 && <span style={{ fontSize:9, color:"#ff1a3d", background:"rgba(255,26,61,0.12)", border:"1px solid rgba(255,26,61,0.3)", padding:"1px 6px", borderRadius:3 }}>{crit} CRIT</span>}
                          </div>
                        </td>
                        <td style={{ padding:"10px 12px", fontSize:10, color:"rgba(255,255,255,0.35)" }}>
                          {s.tools_used?.length ?? 0} tools
                        </td>
                        <td style={{ padding:"10px 12px", fontSize:10, color:"rgba(255,255,255,0.35)", fontFamily:"var(--font-mono)" }}>
                          {s.created_at.slice(0,10)}
                        </td>
                        <td style={{ padding:"10px 12px" }}>
                          <div style={{ display:"flex", gap:6 }}>
                            <button onClick={e => { e.stopPropagation(); onScanSelect(s.id); }}
                              style={{ fontSize:9, color:"#e8001a", background:"rgba(232,0,26,0.08)", border:"1px solid rgba(232,0,26,0.25)", padding:"3px 8px", borderRadius:4, cursor:"pointer", letterSpacing:1, fontFamily:"var(--font-ui)" }}>
                              VIEW →
                            </button>
                            <button onClick={e => { e.stopPropagation(); setConfirmDeleteId(s.id); }}
                              style={{ fontSize:9, color:"rgba(255,255,255,0.4)", background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.1)", padding:"3px 8px", borderRadius:4, cursor:"pointer", letterSpacing:1, fontFamily:"var(--font-ui)" }}
                              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color="#ff1a3d"; (e.currentTarget as HTMLElement).style.borderColor="rgba(255,26,61,0.4)"; }}
                              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color="rgba(255,255,255,0.4)"; (e.currentTarget as HTMLElement).style.borderColor="rgba(255,255,255,0.1)"; }}>
                              ✕ DEL
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Confirm delete dialog */}
      {confirmDeleteId && scanToDelete && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:100, backdropFilter:"blur(4px)" }}
          onClick={() => setConfirmDeleteId(null)}>
          <div style={{ background:"#0f1117", border:"1px solid rgba(232,0,26,0.35)", borderRadius:14, padding:28, width:380, boxShadow:"0 24px 60px rgba(0,0,0,0.8)" }}
            onClick={e => e.stopPropagation()}>
            <div style={{ fontSize:13, fontWeight:700, color:"#ffffff", fontFamily:"var(--font-ui)", letterSpacing:1, marginBottom:10 }}>DELETE SCAN</div>
            <div style={{ fontSize:12, color:"rgba(255,255,255,0.55)", marginBottom:20, lineHeight:1.6, fontFamily:"var(--font-mono)" }}>
              Delete scan of <span style={{ color:"#e8001a", fontWeight:700 }}>{scanToDelete.target}</span>?<br/>
              All findings and assets will be permanently removed.
            </div>
            <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
              <button onClick={() => setConfirmDeleteId(null)}
                style={{ padding:"7px 16px", background:"rgba(255,255,255,0.05)", border:"1px solid rgba(255,255,255,0.12)", color:"rgba(255,255,255,0.6)", borderRadius:6, fontSize:10, cursor:"pointer", fontFamily:"var(--font-ui)", letterSpacing:1 }}>
                CANCEL
              </button>
              <button onClick={() => { onScanDelete(confirmDeleteId); setConfirmDeleteId(null); }}
                style={{ padding:"7px 16px", background:"rgba(255,26,61,0.15)", border:"1px solid rgba(255,26,61,0.45)", color:"#ff1a3d", borderRadius:6, fontSize:10, cursor:"pointer", fontFamily:"var(--font-ui)", letterSpacing:1, fontWeight:700 }}>
                ✕ DELETE
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}