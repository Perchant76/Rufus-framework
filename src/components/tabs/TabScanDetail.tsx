// src/components/tabs/TabScanDetail.tsx — Per-scan detailed dashboard
import React, { useMemo } from "react";
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis,
         Tooltip, ResponsiveContainer, AreaChart, Area } from "recharts";
import type { Scan, VulnFinding, DiscoveredAsset } from "../../types";

const F = "'Orbitron', monospace";
const MONO = "'JetBrains Mono', monospace";
const SEV_COLS: Record<string,string> = {
  CRITICAL:"#ff1a3d", HIGH:"#ff6b2b", MEDIUM:"#ffd700", LOW:"#00ff88", INFO:"#60a5fa"
};
const TT = {
  contentStyle:{ background:"#0a0b0f", border:"1px solid #1e2438", borderRadius:8, color:"#fff", fontSize:11 },
  labelStyle:{ color:"rgba(255,255,255,0.5)", fontSize:10 },
};
const CARD: React.CSSProperties = {
  background:"#0f1117", border:"1px solid #1e2438", borderRadius:12, padding:20, overflow:"hidden", position:"relative"
};

interface Props {
  scan: Scan | null;
  findings: VulnFinding[];
  assets: DiscoveredAsset[];
  onBack: () => void;
}

export default function TabScanDetail({ scan, findings, assets, onBack }: Props) {
  if (!scan) return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100%", color:"rgba(255,255,255,0.3)", fontFamily:F, fontSize:12 }}>
      No scan selected
    </div>
  );

  const scopedFindings = findings.filter(f => f.scan_id === scan.id && f.in_scope);
  const allFindings    = findings.filter(f => f.scan_id === scan.id);
  const scanAssets     = assets.filter(a => a.scan_id === scan.id);

  // Severity distribution
  const sevDist = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s => ({
    name: s, value: scopedFindings.filter(f => f.severity === s).length,
    color: SEV_COLS[s],
  })).filter(d => d.value > 0);

  // Tool breakdown
  const toolCounts: Record<string,number> = {};
  scopedFindings.forEach(f => { toolCounts[f.source_tool] = (toolCounts[f.source_tool] ?? 0) + 1; });
  const toolData = Object.entries(toolCounts).sort((a,b) => b[1]-a[1]).slice(0,10)
    .map(([tool, count]) => ({ tool: tool.length > 12 ? tool.slice(0,12)+"..." : tool, count }));

  // Asset types
  const assetTypes: Record<string,number> = {};
  scanAssets.forEach(a => { assetTypes[a.asset_type] = (assetTypes[a.asset_type] ?? 0) + 1; });

  // Tech stacks from assets
  const techCounts: Record<string,number> = {};
  scanAssets.forEach(a => (a.tech_stack ?? []).forEach(t => { techCounts[t] = (techCounts[t] ?? 0) + 1; }));
  const topTechs = Object.entries(techCounts).sort((a,b) => b[1]-a[1]).slice(0,8);

  // Timeline: group findings by hour
  const timeline = useMemo(() => {
    const hours: Record<string,number> = {};
    scopedFindings.forEach(f => {
      const h = f.timestamp ? f.timestamp.slice(0,13) : "unknown";
      hours[h] = (hours[h] ?? 0) + 1;
    });
    return Object.entries(hours).sort().map(([hour,count]) => ({
      hour: hour.slice(11,16) || hour.slice(0,10),
      count,
    }));
  }, [scopedFindings]);

  const totalScore = scopedFindings.reduce((acc, f) => {
    const scores: Record<string,number> = { CRITICAL:10, HIGH:7, MEDIUM:4, LOW:1, INFO:0 };
    return acc + (scores[f.severity] ?? 0);
  }, 0);

  const riskLevel = totalScore >= 30 ? "CRITICAL" : totalScore >= 15 ? "HIGH" : totalScore >= 5 ? "MEDIUM" : "LOW";
  const riskColor = SEV_COLS[riskLevel] ?? "#00ff88";

  const duration = scan.completed_at
    ? ((new Date(scan.completed_at).getTime() - new Date(scan.created_at).getTime()) / 60000).toFixed(0) + "m"
    : scan.status === "running" ? "Running..." : "—";

  const StatCard = ({ label, value, color, sub }: { label:string; value:string|number; color?:string; sub?:string }) => (
    <div style={{ ...CARD, textAlign:"center" }}>
      <div style={{ position:"absolute", inset:0, background:`radial-gradient(circle at 50% 0%, ${color ?? "#e8001a"}12, transparent 70%)`, pointerEvents:"none" }}/>
      <div style={{ fontSize:9, color:"rgba(255,255,255,0.4)", letterSpacing:2, marginBottom:10, fontFamily:F }}>{label}</div>
      <div style={{ fontSize:32, fontWeight:900, color: color ?? "#ffffff", fontFamily:MONO, lineHeight:1, textShadow:`0 0 20px ${color ?? "#e8001a"}66` }}>{value}</div>
      {sub && <div style={{ fontSize:9, color:"rgba(255,255,255,0.3)", marginTop:6 }}>{sub}</div>}
    </div>
  );

  return (
    <div style={{ height:"100%", overflowY:"auto", fontFamily:MONO }}>
      <div style={{ padding:24, display:"flex", flexDirection:"column", gap:20 }}>

        {/* Header */}
        <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:16 }}>
          <div>
            <button onClick={onBack} style={{ fontSize:10, color:"#e8001a", background:"rgba(232,0,26,0.08)", border:"1px solid rgba(232,0,26,0.25)", padding:"4px 10px", borderRadius:4, cursor:"pointer", fontFamily:F, letterSpacing:1, marginBottom:12 }}>
              ← BACK TO DASHBOARD
            </button>
            <div style={{ fontSize:20, fontWeight:900, color:"#ffffff", fontFamily:F, letterSpacing:2, marginBottom:4 }}>
              {scan.target}
            </div>
            <div style={{ display:"flex", gap:10, flexWrap:"wrap", alignItems:"center" }}>
              <span style={{ fontSize:9, background:"rgba(96,165,250,0.12)", color:"#60a5fa", border:"1px solid rgba(96,165,250,0.3)", padding:"2px 8px", borderRadius:3, letterSpacing:1 }}>{scan.target_type}</span>
              <span style={{ fontSize:9, color: scan.status === "complete" ? "#00ff88" : scan.status === "running" ? "#e8001a" : "#ffd700", fontWeight:700, letterSpacing:1, textTransform:"uppercase" }}>⬤ {scan.status}</span>
              <span style={{ fontSize:10, color:"rgba(255,255,255,0.35)" }}>{scan.created_at.slice(0,10)}</span>
              <span style={{ fontSize:10, color:"rgba(255,255,255,0.35)" }}>Duration: {duration}</span>
            </div>
          </div>
          {/* Risk score */}
          <div style={{ background:"#0f1117", border:`2px solid ${riskColor}`, borderRadius:12, padding:"14px 24px", textAlign:"center", boxShadow:`0 0 24px ${riskColor}44`, flexShrink:0 }}>
            <div style={{ fontSize:9, color:"rgba(255,255,255,0.4)", letterSpacing:2, marginBottom:6, fontFamily:F }}>RISK SCORE</div>
            <div style={{ fontSize:36, fontWeight:900, color:riskColor, fontFamily:MONO, textShadow:`0 0 20px ${riskColor}` }}>{totalScore}</div>
            <div style={{ fontSize:10, fontWeight:700, color:riskColor, letterSpacing:2, fontFamily:F, marginTop:4 }}>{riskLevel}</div>
          </div>
        </div>

        {/* Stat row */}
        <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:12 }}>
          <StatCard label="TOTAL FINDINGS" value={scopedFindings.length} color="#e8001a"/>
          <StatCard label="CRITICAL" value={scopedFindings.filter(f=>f.severity==="CRITICAL").length} color="#ff1a3d"/>
          <StatCard label="HIGH" value={scopedFindings.filter(f=>f.severity==="HIGH").length} color="#ff6b2b"/>
          <StatCard label="ASSETS" value={scanAssets.length} color="#60a5fa"/>
          <StatCard label="SUBDOMAINS" value={scanAssets.filter(a=>a.asset_type==="subdomain").length} color="#a78bfa"/>
          <StatCard label="OUT OF SCOPE" value={allFindings.length - scopedFindings.length} color="#64748b" sub="suppressed"/>
        </div>

        {/* Charts row */}
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16 }}>

          {/* Severity pie */}
          <div style={CARD}>
            <div style={{ fontSize:10, color:"rgba(255,255,255,0.4)", letterSpacing:2, marginBottom:16, fontFamily:F }}>SEVERITY BREAKDOWN</div>
            {sevDist.length > 0 ? (
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={sevDist} cx="50%" cy="50%" innerRadius={40} outerRadius={65} paddingAngle={3} dataKey="value">
                    {sevDist.map((e,i) => <Cell key={i} fill={e.color} opacity={0.9}/>)}
                  </Pie>
                  <Tooltip {...TT} formatter={(v:any,n:any) => [v, n]}/>
                </PieChart>
              </ResponsiveContainer>
            ) : <div style={{ height:160, display:"flex", alignItems:"center", justifyContent:"center", color:"rgba(255,255,255,0.2)", fontSize:11 }}>No findings</div>}
            <div style={{ display:"flex", flexWrap:"wrap", gap:6, justifyContent:"center" }}>
              {sevDist.map(d => (
                <div key={d.name} style={{ display:"flex", alignItems:"center", gap:4, fontSize:9, color:"rgba(255,255,255,0.6)" }}>
                  <div style={{ width:6, height:6, borderRadius:"50%", background:d.color }}/>
                  {d.name} ({d.value})
                </div>
              ))}
            </div>
          </div>

          {/* Tool breakdown bar */}
          <div style={CARD}>
            <div style={{ fontSize:10, color:"rgba(255,255,255,0.4)", letterSpacing:2, marginBottom:16, fontFamily:F }}>FINDINGS BY TOOL</div>
            {toolData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={toolData} layout="vertical" barSize={10}>
                  <XAxis type="number" hide/>
                  <YAxis type="category" dataKey="tool" tick={{ fill:"rgba(255,255,255,0.6)", fontSize:9, fontFamily:MONO }} width={80} axisLine={false} tickLine={false}/>
                  <Tooltip {...TT}/>
                  <Bar dataKey="count" fill="#e8001a" radius={[0,3,3,0]}
                    label={{ position:"right", fill:"rgba(255,255,255,0.5)", fontSize:9 }}/>
                </BarChart>
              </ResponsiveContainer>
            ) : <div style={{ height:200, display:"flex", alignItems:"center", justifyContent:"center", color:"rgba(255,255,255,0.2)", fontSize:11 }}>No tool data</div>}
          </div>

          {/* Asset type breakdown */}
          <div style={CARD}>
            <div style={{ fontSize:10, color:"rgba(255,255,255,0.4)", letterSpacing:2, marginBottom:16, fontFamily:F }}>ASSET BREAKDOWN</div>
            <div style={{ display:"flex", flexDirection:"column", gap:10, marginBottom:16 }}>
              {Object.entries(assetTypes).map(([type, count]) => {
                const pct = scanAssets.length > 0 ? (count/scanAssets.length)*100 : 0;
                const col = { subdomain:"#a78bfa", endpoint:"#60a5fa", port:"#f97316", form:"#ffd700" }[type] ?? "#e8001a";
                return (
                  <div key={type}>
                    <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, marginBottom:4 }}>
                      <span style={{ color:"rgba(255,255,255,0.7)", textTransform:"uppercase", letterSpacing:1 }}>{type}</span>
                      <span style={{ color:"#fff", fontWeight:700 }}>{count}</span>
                    </div>
                    <div style={{ height:4, background:"rgba(255,255,255,0.06)", borderRadius:2 }}>
                      <div style={{ height:"100%", width:`${pct}%`, background:col, borderRadius:2, boxShadow:`0 0 6px ${col}88` }}/>
                    </div>
                  </div>
                );
              })}
              {Object.keys(assetTypes).length === 0 && <div style={{ color:"rgba(255,255,255,0.2)", fontSize:11, textAlign:"center", padding:16 }}>No assets discovered</div>}
            </div>
            {topTechs.length > 0 && (
              <>
                <div style={{ fontSize:9, color:"rgba(255,255,255,0.3)", letterSpacing:2, marginBottom:8, fontFamily:F }}>TECH STACK</div>
                <div style={{ display:"flex", flexWrap:"wrap", gap:5 }}>
                  {topTechs.map(([t, n]) => (
                    <span key={t} style={{ fontSize:9, background:"rgba(96,165,250,0.1)", border:"1px solid rgba(96,165,250,0.25)", color:"#60a5fa", padding:"2px 7px", borderRadius:3, fontFamily:MONO }}>
                      {t} ({n})
                    </span>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

        {/* Finding timeline */}
        {timeline.length > 1 && (
          <div style={CARD}>
            <div style={{ fontSize:10, color:"rgba(255,255,255,0.4)", letterSpacing:2, marginBottom:14, fontFamily:F }}>FINDINGS TIMELINE</div>
            <ResponsiveContainer width="100%" height={100}>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="tl-grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#e8001a" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#e8001a" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="hour" tick={{ fill:"rgba(255,255,255,0.3)", fontSize:9 }} axisLine={false} tickLine={false}/>
                <YAxis hide/>
                <Tooltip {...TT}/>
                <Area type="monotone" dataKey="count" stroke="#e8001a" fill="url(#tl-grad)" strokeWidth={2}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Findings table */}
        <div style={CARD}>
          <div style={{ fontSize:10, color:"rgba(255,255,255,0.4)", letterSpacing:2, marginBottom:14, fontFamily:F }}>
            ALL FINDINGS ({scopedFindings.length})
          </div>
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead>
              <tr style={{ borderBottom:"1px solid rgba(255,255,255,0.06)" }}>
                {["SEV","TITLE","TOOL","URL","CVSS"].map(h => (
                  <th key={h} style={{ textAlign:"left", padding:"6px 12px", fontSize:9, color:"rgba(255,255,255,0.3)", letterSpacing:2 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...scopedFindings]
                .sort((a,b) => {
                  const o: Record<string,number> = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };
                  return (o[a.severity]??4)-(o[b.severity]??4);
                })
                .slice(0,50)
                .map((f,i) => (
                  <tr key={f.id} style={{ borderBottom:"1px solid rgba(255,255,255,0.03)", transition:"background 0.1s" }}
                    onMouseEnter={e=>(e.currentTarget.style.background="rgba(232,0,26,0.03)")}
                    onMouseLeave={e=>(e.currentTarget.style.background="transparent")}>
                    <td style={{ padding:"9px 12px" }}>
                      <span style={{ fontSize:9, fontWeight:700, color:SEV_COLS[f.severity], background:`${SEV_COLS[f.severity]}18`, border:`1px solid ${SEV_COLS[f.severity]}44`, padding:"2px 7px", borderRadius:3, letterSpacing:1 }}>{f.severity}</span>
                    </td>
                    <td style={{ padding:"9px 12px", fontSize:11, color:"#ffffff", maxWidth:280, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{f.title}</td>
                    <td style={{ padding:"9px 12px", fontSize:10, color:"rgba(255,255,255,0.45)", fontFamily:MONO }}>{f.source_tool}</td>
                    <td style={{ padding:"9px 12px", fontSize:10, color:"rgba(96,165,250,0.8)", fontFamily:MONO, maxWidth:200, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{f.affected_url}</td>
                    <td style={{ padding:"9px 12px", fontSize:10, color:"rgba(255,255,255,0.5)", fontFamily:MONO }}>{f.cvss_score?.toFixed(1) ?? "—"}</td>
                  </tr>
                ))}
            </tbody>
          </table>
          {scopedFindings.length > 50 && (
            <div style={{ textAlign:"center", padding:"12px 0", fontSize:10, color:"rgba(255,255,255,0.25)" }}>
              Showing 50 of {scopedFindings.length} — use the Vulns tab for full list
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
