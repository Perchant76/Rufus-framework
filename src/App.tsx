// src/App.tsx — Rufus Framework
import React, { useState, useEffect, useRef, useCallback } from "react";
import type { ScanConfig, ScanProgress, VulnFinding, DiscoveredAsset, TargetType, Scan } from "./types";
import { ALL_TOOLS } from "./types";
import { startScan, stopScan, getScans, onScanProgress, onScanFinding, onScanAsset } from "./lib/api";
import { RufusLogo } from "./components/ui";
import TabTarget     from "./components/tabs/TabTarget";
import TabDiscovery  from "./components/tabs/TabDiscovery";
import TabActiveScan from "./components/tabs/TabActiveScan";
import TabVulns      from "./components/tabs/TabVulns";
import TabComparison from "./components/tabs/TabComparison";
import TabExport     from "./components/tabs/TabExport";
import TabPrograms   from "./components/tabs/TabPrograms";
import TabWorkflow   from "./components/tabs/TabWorkflow";
import TabReplay     from "./components/tabs/TabReplay";
import TabOsint      from "./components/tabs/TabOsint";
import TabCloud      from "./components/tabs/TabCloud";

function detectType(val: string): TargetType {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(val.trim()) ? "IP" : "DOMAIN";
}

function defaultConfig(): ScanConfig {
  return {
    target: "", target_type: "DOMAIN", scope: [], stealth_mode: false,
    concurrency: 25, delay_min_ms: 0, delay_max_ms: 0,
    tools: ALL_TOOLS.map(t => t.name), auth: { mode: "none" },
    respect_robots: false, wordlist_id: null, nuclei_profile_id: null,
  };
}

type TabId = "programs"|"workflow"|"target"|"discovery"|"scan"|"vulns"|"replay"|"osint"|"cloud"|"compare"|"export";

const TABS: { id: TabId; label: string; icon: string }[] = [
  { id:"programs",  label:"Programs",   icon:"◈" },
  { id:"workflow",  label:"Workflow",   icon:"⬡" },
  { id:"target",    label:"Target",     icon:"◎" },
  { id:"discovery", label:"Discovery",  icon:"⊕" },
  { id:"scan",      label:"Scan",       icon:"▶" },
  { id:"vulns",     label:"Vulns",      icon:"⚠" },
  { id:"replay",    label:"Replay",     icon:"↺" },
  { id:"osint",     label:"OSINT",      icon:"◉" },
  { id:"cloud",     label:"Cloud",      icon:"⬢" },
  { id:"compare",   label:"Compare",    icon:"⇌" },
  { id:"export",    label:"Export",     icon:"↗" },
];

export default function App() {
  const [tab, setTab]           = useState<TabId>("programs");
  const [config, setConfig]     = useState<ScanConfig>(defaultConfig);
  const [stealthOn, setStealthOn] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [logs, setLogs]         = useState<ScanProgress[]>([]);
  const [findings, setFindings] = useState<VulnFinding[]>([]);
  const [assets, setAssets]     = useState<DiscoveredAsset[]>([]);
  const [toolProgress, setToolProgress] = useState<Record<string, number>>({});
  const [scans, setScans]       = useState<Scan[]>([]);

  const unlistenProgress = useRef<(()=>void)|null>(null);
  const unlistenFinding  = useRef<(()=>void)|null>(null);
  const unlistenAsset    = useRef<(()=>void)|null>(null);

  useEffect(() => { getScans().then(setScans).catch(console.error); }, []);
  useEffect(() => {
    setConfig(c => ({ ...c, stealth_mode: stealthOn, concurrency: stealthOn ? 1 : 25, delay_min_ms: stealthOn ? 500 : 0, delay_max_ms: stealthOn ? 2000 : 0 }));
  }, [stealthOn]);
  useEffect(() => {
    if (config.target) setConfig(c => ({ ...c, target_type: detectType(c.target) }));
  }, [config.target]);

  const handleStart = useCallback(async () => {
    if (!config.target) return;
    setLogs([]); setFindings([]); setAssets([]); setToolProgress({});
    setIsRunning(true); setTab("discovery");
    unlistenProgress.current = await onScanProgress(p => {
      setLogs(prev => [...prev.slice(-500), p]);
      if (p.percent >= 0) setToolProgress(prev => ({ ...prev, [p.tool]: p.percent }));
    });
    unlistenFinding.current = await onScanFinding(f => setFindings(prev => [...prev, f]));
    unlistenAsset.current   = await onScanAsset(a => setAssets(prev => [...prev, a]));
    try { const id = await startScan(config); setCurrentScanId(id); }
    catch (e) { console.error(e); }
    finally {
      setIsRunning(false);
      getScans().then(setScans).catch(console.error);
      unlistenProgress.current?.(); unlistenFinding.current?.(); unlistenAsset.current?.();
    }
  }, [config]);

  const handleStop = useCallback(async () => {
    try { await stopScan(); } catch {}
    setIsRunning(false);
    unlistenProgress.current?.(); unlistenFinding.current?.(); unlistenAsset.current?.();
    getScans().then(setScans).catch(console.error);
  }, []);

  const handleProgramScan = (partial: Partial<ScanConfig>) => {
    setConfig(c => ({ ...c, ...partial })); setTab("target");
  };

  const targetType    = config.target ? detectType(config.target) : null;
  const criticalCount = findings.filter(f => f.severity === "CRITICAL" && f.in_scope).length;
  const inScopeCount  = findings.filter(f => f.in_scope).length;

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100vh", overflow:"hidden", background:"var(--bg0)", position:"relative", zIndex:1 }}>

      {/* ── Top Bar ──────────────────────────────────────────────────────── */}
      <div style={{
        display:"flex", alignItems:"center", gap:16, height:58, padding:"0 20px", flexShrink:0,
        background:"linear-gradient(180deg, var(--bg1) 0%, rgba(12,15,23,0.95) 100%)",
        borderBottom:"1px solid var(--border)",
        boxShadow:"0 4px 24px rgba(0,0,0,0.5), 0 1px 0 rgba(232,0,26,0.2)",
        position:"relative", zIndex:10,
      }}>
        {/* Logo + Brand */}
        <div style={{ display:"flex", alignItems:"center", gap:12, flexShrink:0 }}>
          <RufusLogo size={38} />
          <div>
            <div style={{ fontFamily:"var(--font-ui)", fontSize:16, fontWeight:900, color:"#fff", letterSpacing:"3px", lineHeight:1 }}>
              RUFUS
            </div>
            <div style={{ fontFamily:"var(--font-mono)", fontSize:9, color:"var(--accent)", letterSpacing:"4px", marginTop:2 }}>
              FRAMEWORK
            </div>
          </div>
        </div>

        <div style={{ width:1, height:30, background:"var(--border)", flexShrink:0 }} />

        {/* Target input */}
        <div style={{
          display:"flex", alignItems:"center", gap:10, flex:1, maxWidth:500,
          background:"var(--bg2)", border:"1px solid var(--border-hi)",
          borderRadius:"var(--r)", padding:"0 14px", height:36,
          transition:"border .15s",
        }}>
          <span style={{ fontSize:9, color:"var(--accent)", textTransform:"uppercase", letterSpacing:"2px", flexShrink:0, fontFamily:"var(--font-ui)" }}>TGT</span>
          <input value={config.target} onChange={e => setConfig(c => ({ ...c, target: e.target.value }))}
            placeholder="target.com  //  1.2.3.4"
            style={{ flex:1, background:"none", border:"none", outline:"none", color:"#fff", fontFamily:"var(--font-mono)", fontSize:13 }} />
          {targetType && (
            <span style={{
              fontSize:9, padding:"2px 8px", borderRadius:3, fontWeight:700, letterSpacing:"1px", textTransform:"uppercase", flexShrink:0,
              background: targetType === "DOMAIN" ? "rgba(139,92,246,.2)" : "rgba(232,0,26,.15)",
              color: targetType === "DOMAIN" ? "#a78bfa" : "var(--accent)",
              border: targetType === "DOMAIN" ? "1px solid rgba(139,92,246,.4)" : "1px solid rgba(232,0,26,.4)",
              fontFamily:"var(--font-ui)",
            }}>{targetType}</span>
          )}
        </div>

        <div style={{ flex:1 }} />

        {/* Status indicator */}
        {isRunning && (
          <div style={{ display:"flex", alignItems:"center", gap:8, padding:"5px 12px", background:"rgba(232,0,26,.1)", border:"1px solid rgba(232,0,26,.3)", borderRadius:"var(--r)", fontSize:11, color:"var(--accent)", fontFamily:"var(--font-ui)", letterSpacing:"1px" }}>
            <Dot color="var(--accent)" pulse /> SCANNING
          </div>
        )}
        {findings.length > 0 && !isRunning && (
          <div style={{ display:"flex", alignItems:"center", gap:8, padding:"5px 12px", background:"rgba(255,26,61,.08)", border:"1px solid rgba(255,26,61,.25)", borderRadius:"var(--r)", fontSize:11, color:"var(--red)" }}>
            ⚠ {findings.length} FINDINGS
          </div>
        )}

        {/* Stealth toggle */}
        <div onClick={() => setStealthOn(s => !s)} style={{
          display:"flex", alignItems:"center", gap:8, cursor:"pointer", fontSize:10,
          padding:"6px 12px", fontFamily:"var(--font-ui)", letterSpacing:"1px",
          background: stealthOn ? "rgba(0,255,136,.08)" : "var(--bg2)",
          border:`1px solid ${stealthOn ? "var(--green)" : "var(--border)"}`,
          borderRadius:"var(--r)", color: stealthOn ? "var(--green)" : "var(--text-dim)",
          transition:"all .2s", userSelect:"none",
          boxShadow: stealthOn ? "0 0 12px rgba(0,255,136,0.2)" : "none",
        }}>
          <div style={{ width:26, height:13, borderRadius:7, position:"relative", background: stealthOn ? "rgba(0,255,136,.2)" : "var(--bg3)", border:`1px solid ${stealthOn ? "var(--green)" : "var(--border)"}`, transition:"all .2s" }}>
            <div style={{ position:"absolute", top:2, borderRadius:"50%", width:7, height:7, transition:"all .2s", left: stealthOn ? 15 : 2, background: stealthOn ? "var(--green)" : "var(--text-dim)", boxShadow: stealthOn ? "0 0 6px var(--green)" : "none" }} />
          </div>
          STEALTH
        </div>

        <div style={{ width:1, height:30, background:"var(--border)" }} />

        {/* Main scan button */}
        <button onClick={isRunning ? handleStop : handleStart}
          disabled={!isRunning && !config.target}
          style={{
            display:"inline-flex", alignItems:"center", gap:8, height:36, padding:"0 20px",
            borderRadius:"var(--r)", fontFamily:"var(--font-ui)", fontSize:11, fontWeight:700,
            letterSpacing:"2px", border:"none",
            cursor: config.target || isRunning ? "pointer" : "not-allowed",
            background: isRunning
              ? "linear-gradient(135deg, #cc0015, #e8001a)"
              : "linear-gradient(135deg, #c0001a, #e8001a)",
            color:"#fff",
            boxShadow: isRunning ? "0 0 20px rgba(232,0,26,0.6), inset 0 1px 0 rgba(255,255,255,0.1)" : "0 0 12px rgba(232,0,26,0.3)",
            animation: isRunning ? "pulse-red 1.5s infinite" : "none",
            transition:"all .15s",
          }}>
          {isRunning ? "■ ABORT" : "▶ ENGAGE"}
        </button>
      </div>

      {/* ── Tab Bar ──────────────────────────────────────────────────────── */}
      <div style={{
        display:"flex", alignItems:"center",
        background:"var(--bg1)", borderBottom:"1px solid var(--border)",
        padding:"0 20px", flexShrink:0, overflowX:"auto", gap:2,
        boxShadow:"0 2px 12px rgba(0,0,0,0.3)",
      }}>
        {TABS.map(t => {
          const badge =
            t.id === "discovery" && assets.length > 0 ? assets.length :
            t.id === "vulns" && inScopeCount > 0 ? inScopeCount :
            t.id === "scan" && isRunning ? "●" : null;
          const isActive = tab === t.id;
          return (
            <div key={t.id} onClick={() => setTab(t.id)} style={{
              display:"flex", alignItems:"center", gap:6, padding:"0 14px", height:44,
              cursor:"pointer", fontSize:10, fontFamily:"var(--font-ui)", letterSpacing:"1.5px",
              color: isActive ? "#fff" : "var(--text-dim)",
              borderBottom:`2px solid ${isActive ? "var(--accent)" : "transparent"}`,
              background: isActive ? "rgba(232,0,26,0.06)" : "transparent",
              whiteSpace:"nowrap", transition:"all .15s",
              textShadow: isActive ? "0 0 12px rgba(232,0,26,0.6)" : "none",
            }}>
              <span style={{ color: isActive ? "var(--accent)" : "var(--text-dim)", fontSize:12 }}>{t.icon}</span>
              {t.label}
              {badge !== null && (
                <span style={{
                  fontSize:9, borderRadius:8, padding:"1px 6px", fontWeight:700, minWidth:18, textAlign:"center",
                  background: t.id === "vulns" && criticalCount > 0 ? "var(--red)" :
                              t.id === "scan" ? "var(--accent)" : "rgba(0,255,136,.9)",
                  color:"#fff", boxShadow:"0 0 6px currentColor",
                }}>{badge}</span>
              )}
            </div>
          );
        })}
        {/* Right side — version */}
        <div style={{ marginLeft:"auto", fontSize:9, color:"var(--text-dim)", fontFamily:"var(--font-ui)", letterSpacing:"2px", paddingRight:8, flexShrink:0 }}>
          v3.0 // ALPHA
        </div>
      </div>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <div style={{ flex:1, overflow:"hidden", display:"flex", position:"relative", zIndex:1 }}>
        {tab === "programs"  && <TabPrograms onStartScan={handleProgramScan} />}
        {tab === "workflow"  && <TabWorkflow />}
        {tab === "target"    && <TabTarget config={config} onChange={setConfig} stealthOn={stealthOn} />}
        {tab === "discovery" && <TabDiscovery assets={assets} logs={logs} toolProgress={toolProgress} isRunning={isRunning} scanId={currentScanId} />}
        {tab === "scan"      && <TabActiveScan config={config} onConfigChange={setConfig} isRunning={isRunning} onStart={handleStart} onStop={handleStop} logs={logs} toolProgress={toolProgress} findingCount={findings.length} />}
        {tab === "vulns"     && <TabVulns findings={findings} scanId={currentScanId} />}
        {tab === "replay"    && <TabReplay />}
        {tab === "osint"     && <TabOsint />}
        {tab === "cloud"     && <TabCloud currentScanId={currentScanId} />}
        {tab === "compare"   && <TabComparison scans={scans} />}
        {tab === "export"    && <TabExport scans={scans} currentScanId={currentScanId} findings={findings} />}
      </div>
    </div>
  );
}

function Dot({ color, pulse }: { color: string; pulse?: boolean }) {
  return <span style={{ display:"inline-block", width:7, height:7, borderRadius:"50%", background:color, flexShrink:0, ...(pulse ? { animation:"pulse-red 1.2s infinite" } : {}) }} />;
}
