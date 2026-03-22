// src/App.tsx — Rufus Framework v4.0
import React, { useState, useEffect, useRef, useCallback } from "react";
import type { ScanConfig, ScanProgress, VulnFinding, DiscoveredAsset, TargetType, Scan } from "./types";
import { ALL_TOOLS } from "./types";
import { startScan, stopScan, getScans, onScanProgress, onScanFinding, onScanAsset } from "./lib/api";
import { invoke } from "@tauri-apps/api/core";
import { RufusLogo } from "./components/ui";
import LoadingScreen  from "./components/LoadingScreen";
import TabTarget      from "./components/tabs/TabTarget";
import TabDiscovery   from "./components/tabs/TabDiscovery";
import TabActiveScan  from "./components/tabs/TabActiveScan";
import TabVulns       from "./components/tabs/TabVulns";
import TabComparison  from "./components/tabs/TabComparison";
import TabExport      from "./components/tabs/TabExport";
import TabPrograms    from "./components/tabs/TabPrograms";
import TabWorkflow    from "./components/tabs/TabWorkflow";
import TabReplay      from "./components/tabs/TabReplay";
import TabOsint       from "./components/tabs/TabOsint";
import TabCloud       from "./components/tabs/TabCloud";
import TabSecrets     from "./components/tabs/TabSecrets";
import TabHeaders     from "./components/tabs/TabHeaders";
import TabPhaseControl from "./components/tabs/TabPhaseControl";
import TabPenForgeExport from "./components/tabs/TabPenForgeExport";
import TabScope       from "./components/tabs/TabScope";
import TabDashboard   from "./components/tabs/TabDashboard";
import TabScanDetail  from "./components/tabs/TabScanDetail";
import TabTechStacks  from "./components/tabs/TabTechStacks";
import TabTakeover    from "./components/tabs/TabTakeover";

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

type TabId =
  "dashboard" | "programs" | "workflow" | "target" | "scope" |
  "discovery" | "scan" | "phases" | "vulns" | "secrets" | "headers" |
  "techstacks" | "takeover" | "replay" | "osint" | "cloud" |
  "compare" | "penforge" | "export" | "scandetail";

const TABS: { id: TabId; label: string; icon: string; group?: string }[] = [
  { id:"dashboard",  label:"Dashboard",    icon:"◈",  group:"main" },
  { id:"programs",   label:"Programs",     icon:"⬡",  group:"main" },
  { id:"workflow",   label:"Workflow",     icon:"⬢",  group:"main" },
  { id:"target",     label:"Target",       icon:"◎",  group:"config" },
  { id:"scope",      label:"Scope",        icon:"🎯", group:"config" },
  { id:"discovery",  label:"Discovery",    icon:"⊕",  group:"recon" },
  { id:"scan",       label:"Scan",         icon:"▶",  group:"recon" },
  { id:"phases",     label:"Phases",       icon:"⚙",  group:"recon" },
  { id:"vulns",      label:"Vulns",        icon:"⚠",  group:"results" },
  { id:"secrets",    label:"JS Secrets",   icon:"🔑", group:"results" },
  { id:"headers",    label:"Headers",      icon:"🛡", group:"results" },
  { id:"techstacks", label:"Tech Stacks",  icon:"⚡", group:"results" },
  { id:"takeover",   label:"Takeover",     icon:"🎣", group:"results" },
  { id:"replay",     label:"Replay",       icon:"↺",  group:"tools" },
  { id:"osint",      label:"OSINT",        icon:"◉",  group:"tools" },
  { id:"cloud",      label:"Cloud",        icon:"☁",  group:"tools" },
  { id:"compare",    label:"Compare",      icon:"⇌",  group:"report" },
  { id:"penforge",   label:"→ PenForge",   icon:"📤", group:"report" },
  { id:"export",     label:"Export",       icon:"↗",  group:"report" },
];

export default function App() {
  const [booting, setBooting]         = useState(true);
  const [tab, setTab]                 = useState<TabId>("dashboard");
  const [config, setConfig]           = useState<ScanConfig>(defaultConfig);
  const [stealthOn, setStealthOn]     = useState(false);
  const [isRunning, setIsRunning]     = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [logs, setLogs]               = useState<ScanProgress[]>([]);
  const [findings, setFindings]       = useState<VulnFinding[]>([]);
  const [assets, setAssets]           = useState<DiscoveredAsset[]>([]);
  const [toolProgress, setToolProgress] = useState<Record<string, number>>({});
  const [scans, setScans]             = useState<Scan[]>([]);
  const [scopeList, setScopeList]     = useState<string[]>([]);
  const [excludePatterns, setExcludePatterns] = useState<string[]>([]);
  const [rateLimitMs, setRateLimitMs] = useState(200);
  const [isPaused, setIsPaused]       = useState(false);
  const [allFindings, setAllFindings] = useState<VulnFinding[]>([]);

  const unlistenProgress = useRef<(()=>void)|null>(null);
  const unlistenFinding  = useRef<(()=>void)|null>(null);
  const unlistenAsset    = useRef<(()=>void)|null>(null);

  useEffect(() => {
    getScans().then(s => { setScans(s); }).catch(() => {});
    // Load all historical findings for dashboard
    invoke<VulnFinding[]>("get_findings").then(setAllFindings).catch(() => {});

    onScanProgress((prog) => {
      setLogs(prev => [prog, ...prev].slice(0, 500));
      if (prog.percent >= 0)
        setToolProgress(prev => ({ ...prev, [prog.tool]: prog.percent }));
    }).then(fn => { unlistenProgress.current = fn; });
    onScanFinding((f) => {
      setFindings(prev => prev.some(x => x.id === f.id) ? prev : [f, ...prev]);
      setAllFindings(prev => prev.some(x => x.id === f.id) ? prev : [f, ...prev]);
    }).then(fn => { unlistenFinding.current = fn; });
    onScanAsset((a) => {
      setAssets(prev => prev.some(x => x.id === a.id) ? prev : [a, ...prev]);
    }).then(fn => { unlistenAsset.current = fn; });

    return () => {
      unlistenProgress.current?.();
      unlistenFinding.current?.();
      unlistenAsset.current?.();
    };
  }, []);

  useEffect(() => {
    setConfig(prev => ({
      ...prev,
      scope: scopeList,
      delay_min_ms: rateLimitMs,
      delay_max_ms: rateLimitMs > 0 ? Math.floor(rateLimitMs * 1.5) : 0,
    }));
  }, [scopeList, rateLimitMs]);

  const handleStart = useCallback(async () => {
    if (isRunning) return;
    const targetType = detectType(config.target);
    const scopeEntries = scopeList.length > 0 ? scopeList : [config.target];
    const cfg: ScanConfig = {
      ...config, target_type: targetType, stealth_mode: stealthOn,
      scope: scopeEntries, delay_min_ms: rateLimitMs,
      delay_max_ms: rateLimitMs > 0 ? Math.floor(rateLimitMs * 1.5) : 0,
    };
    setLogs([]); setFindings([]); setAssets([]); setToolProgress({}); setIsPaused(false);
    setIsRunning(true);
    try {
      const scanId = await startScan(cfg);
      setCurrentScanId(scanId);
      invoke("save_scan_session", { scanId, currentPhase: 1, completedPhases: [] }).catch(() => {});
      getScans().then(setScans).catch(() => {});
      setTab("scan");
    } catch(e) {
      setLogs(prev => [{ scan_id:"", tool:"error", percent:0, message:`Failed to start: ${e}`, level:"error" }, ...prev]);
      setIsRunning(false);
    }
  }, [config, stealthOn, isRunning, scopeList, rateLimitMs]);

  const handleStop = useCallback(async () => {
    await stopScan().catch(() => {});
    setIsRunning(false);
    if (currentScanId) {
      invoke("clear_scan_session", { scanId: currentScanId }).catch(() => {});
      getScans().then(setScans).catch(() => {});
    }
  }, [currentScanId]);

  const handleScanSelect = (id: string) => {
    setSelectedScanId(id);
    setTab("scandetail");
  };

  const handleScanDelete = useCallback(async (id: string) => {
    try {
      await invoke("delete_scan", { scanId: id });
      setScans(prev => prev.filter(s => s.id !== id));
      setAllFindings(prev => prev.filter(f => f.scan_id !== id));
      if (selectedScanId === id) setTab("dashboard");
    } catch(e) {
      console.error("Failed to delete scan:", e);
    }
  }, [selectedScanId]);

  const handleProgramScan = (target: string) => {
    setConfig(prev => ({ ...prev, target, target_type: detectType(target) }));
    setTab("target");
  };

  const inScopeCount  = findings.filter(f => f.in_scope).length;
  const criticalCount = findings.filter(f => f.in_scope && f.severity === "CRITICAL").length;
  const targetType    = detectType(config.target);
  const selectedScan  = scans.find(s => s.id === selectedScanId) ?? null;

  // Group tabs by section for visual separator
  const tabGroups = TABS.reduce((acc, t) => {
    const g = t.group ?? "main";
    if (!acc[g]) acc[g] = [];
    acc[g].push(t);
    return acc;
  }, {} as Record<string, typeof TABS>);

  if (booting) return <LoadingScreen onDone={() => setBooting(false)}/>;

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100vh", overflow:"hidden", background:"var(--bg0)", color:"#ffffff", fontFamily:"var(--font-ui)" }}>

      {/* ── Top Bar ──────────────────────────────────────────────────────── */}
      <div style={{ display:"flex", alignItems:"center", gap:14, padding:"0 20px", height:52, background:"var(--bg1)", borderBottom:"1px solid var(--border)", flexShrink:0, boxShadow:"0 2px 16px rgba(0,0,0,0.5)" }}>
        <RufusLogo size={30}/>
        <span style={{ fontSize:14, fontWeight:900, letterSpacing:4, color:"#ffffff", fontFamily:"var(--font-ui)" }}>
          RUFUS<span style={{ color:"#e8001a", marginLeft:2 }}>⬡</span>
        </span>
        <div style={{ width:1, height:24, background:"var(--border)" }}/>
        {config.target && (
          <span style={{ fontSize:10, color:"rgba(255,255,255,0.6)", letterSpacing:2 }}>
            {config.target}
            <span style={{ marginLeft:8, color:"#e8001a", fontSize:9, background:"rgba(232,0,26,0.1)", border:"1px solid rgba(232,0,26,0.2)", padding:"1px 6px", borderRadius:3 }}>{targetType}</span>
          </span>
        )}
        {scopeList.length > 0 && (
          <span style={{ fontSize:9, color:"#00ff88", background:"rgba(0,255,136,0.08)", border:"1px solid rgba(0,255,136,0.2)", padding:"2px 8px", borderRadius:4, letterSpacing:1 }}>
            🎯 {scopeList.length} SCOPE
          </span>
        )}
        <div style={{ flex:1 }}/>
        {isRunning && (
          <button onClick={isPaused ? () => { invoke("resume_scan"); setIsPaused(false); } : () => { invoke("pause_scan"); setIsPaused(true); }}
            style={{ display:"flex", alignItems:"center", gap:6, height:30, padding:"0 14px", borderRadius:"var(--r)", fontSize:10, fontWeight:700, letterSpacing:1, border:`1px solid ${isPaused?"rgba(0,255,136,0.4)":"rgba(255,215,0,0.4)"}`, background:isPaused?"rgba(0,255,136,0.1)":"rgba(255,215,0,0.1)", color:isPaused?"#00ff88":"#ffd700", cursor:"pointer" }}>
            {isPaused ? "▶ RESUME" : "⏸ PAUSE"}
          </button>
        )}
        {isRunning && (
          <div style={{ display:"flex", alignItems:"center", gap:8, padding:"5px 12px", background:isPaused?"rgba(255,215,0,0.1)":"rgba(232,0,26,0.1)", border:`1px solid ${isPaused?"rgba(255,215,0,0.3)":"rgba(232,0,26,0.3)"}`, borderRadius:"var(--r)", fontSize:11, color:isPaused?"#ffd700":"#e8001a", letterSpacing:1 }}>
            <Dot color={isPaused?"#ffd700":"#e8001a"} pulse={!isPaused}/>
            {isPaused ? "PAUSED" : "SCANNING"}
          </div>
        )}
        {findings.length > 0 && !isRunning && (
          <div style={{ display:"flex", alignItems:"center", gap:8, padding:"5px 12px", background:"rgba(255,26,61,0.08)", border:"1px solid rgba(255,26,61,0.25)", borderRadius:"var(--r)", fontSize:11, color:"#ff1a3d" }}>
            ⚠ {findings.length} FINDINGS
          </div>
        )}
        <div onClick={() => setStealthOn(s => !s)} style={{ display:"flex", alignItems:"center", gap:8, cursor:"pointer", fontSize:10, padding:"6px 12px", letterSpacing:1, background:stealthOn?"rgba(0,255,136,0.08)":"var(--bg2)", border:`1px solid ${stealthOn?"#00ff88":"var(--border)"}`, borderRadius:"var(--r)", color:stealthOn?"#00ff88":"rgba(255,255,255,0.4)", transition:"all .2s", userSelect:"none" }}>
          <div style={{ width:26, height:13, borderRadius:7, position:"relative", background:stealthOn?"rgba(0,255,136,0.2)":"var(--bg3)", border:`1px solid ${stealthOn?"#00ff88":"var(--border)"}`, transition:"all .2s" }}>
            <div style={{ position:"absolute", top:2, borderRadius:"50%", width:7, height:7, transition:"all .2s", left:stealthOn?15:2, background:stealthOn?"#00ff88":"rgba(255,255,255,0.3)" }}/>
          </div>
          STEALTH
        </div>
        <div style={{ width:1, height:30, background:"var(--border)" }}/>
        <button onClick={isRunning ? handleStop : handleStart} disabled={!isRunning && !config.target}
          style={{ display:"inline-flex", alignItems:"center", gap:8, height:36, padding:"0 20px", borderRadius:"var(--r)", fontFamily:"var(--font-ui)", fontSize:11, fontWeight:700, letterSpacing:2, border:"none", cursor:config.target||isRunning?"pointer":"not-allowed", background:isRunning?"linear-gradient(135deg,#cc0015,#e8001a)":"linear-gradient(135deg,#c0001a,#e8001a)", color:"#fff", boxShadow:isRunning?"0 0 20px rgba(232,0,26,0.6)":"0 0 12px rgba(232,0,26,0.3)", animation:isRunning?"pulse-red 1.5s infinite":"none", transition:"all .15s" }}>
          {isRunning ? "■ ABORT" : "▶ ENGAGE"}
        </button>
      </div>

      {/* ── Tab Bar ──────────────────────────────────────────────────────── */}
      <div style={{ display:"flex", alignItems:"center", background:"var(--bg1)", borderBottom:"1px solid var(--border)", padding:"0 8px", flexShrink:0, overflowX:"auto", boxShadow:"0 2px 12px rgba(0,0,0,0.3)", gap:0 }}>
        {Object.entries(tabGroups).map(([group, groupTabs], gi) => (
          <React.Fragment key={group}>
            {gi > 0 && <div style={{ width:1, height:28, background:"rgba(255,255,255,0.06)", margin:"0 4px", flexShrink:0 }}/>}
            {groupTabs.map(t => {
              if (t.id === "scandetail") return null; // hidden tab
              const badge =
                t.id==="discovery" && assets.length > 0 ? assets.length :
                t.id==="vulns" && inScopeCount > 0 ? inScopeCount :
                t.id==="scan" && isRunning ? "●" :
                t.id==="phases" && isRunning ? "●" :
                null;
              const isActive = tab === t.id || (t.id === "dashboard" && tab === "scandetail");
              const isPF = t.id === "penforge";
              return (
                <div key={t.id} onClick={() => setTab(t.id)} style={{ display:"flex", alignItems:"center", gap:4, padding:"0 10px", height:42, cursor:"pointer", fontSize:9, fontFamily:"var(--font-ui)", letterSpacing:1.5, color:isActive?"#ffffff":isPF?"rgba(96,165,250,0.7)":"rgba(255,255,255,0.4)", borderBottom:`2px solid ${isActive?(isPF?"#3b82f6":"#e8001a"):"transparent"}`, background:isActive?(isPF?"rgba(59,130,246,0.06)":"rgba(232,0,26,0.06)"):"transparent", whiteSpace:"nowrap", transition:"all .15s" }}
                  onMouseEnter={e=>{if(!isActive)(e.currentTarget as HTMLElement).style.color="#ffffff";}}
                  onMouseLeave={e=>{if(!isActive)(e.currentTarget as HTMLElement).style.color=isPF?"rgba(96,165,250,0.7)":"rgba(255,255,255,0.4)";}}>
                  <span style={{ fontSize:10 }}>{t.icon}</span>
                  {t.label}
                  {badge !== null && (
                    <span style={{ fontSize:9, borderRadius:8, padding:"1px 5px", fontWeight:700, minWidth:16, textAlign:"center", background:t.id==="vulns"&&criticalCount>0?"#ff1a3d":t.id==="scan"||t.id==="phases"?"#e8001a":"rgba(0,255,136,0.9)", color:"#fff" }}>{badge}</span>
                  )}
                </div>
              );
            })}
          </React.Fragment>
        ))}
        <div style={{ marginLeft:"auto", fontSize:9, color:"rgba(255,255,255,0.2)", letterSpacing:2, paddingRight:8, flexShrink:0, fontFamily:"var(--font-ui)" }}>v4.0</div>
      </div>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <div style={{ flex:1, overflow:"hidden", display:"flex", position:"relative", zIndex:1 }}>
        {tab === "dashboard"  && <TabDashboard scans={scans} findings={allFindings} assets={assets} isRunning={isRunning} onScanSelect={handleScanSelect} onScanDelete={handleScanDelete} onNavigate={(t) => setTab(t as TabId)}/>}
        {tab === "scandetail" && <TabScanDetail scan={selectedScan} findings={allFindings} assets={assets} onBack={() => setTab("dashboard")}/>}
        {tab === "programs"   && <TabPrograms onStartScan={handleProgramScan}/>}
        {tab === "workflow"   && <TabWorkflow/>}
        {tab === "target"     && <TabTarget config={config} onChange={setConfig} stealthOn={stealthOn}/>}
        {tab === "scope"      && <TabScope scope={scopeList} onScopeChange={setScopeList} rateLimitMs={rateLimitMs} onRateLimitChange={setRateLimitMs} excludePatterns={excludePatterns} onExcludeChange={setExcludePatterns}/>}
        {tab === "discovery"  && <TabDiscovery assets={assets} logs={logs} toolProgress={toolProgress} isRunning={isRunning} scanId={currentScanId}/>}
        {tab === "scan"       && <TabActiveScan config={config} onConfigChange={setConfig} isRunning={isRunning} onStart={handleStart} onStop={handleStop} logs={logs} toolProgress={toolProgress} findingCount={findings.length}/>}
        {tab === "phases"     && <TabPhaseControl isRunning={isRunning} currentScanId={currentScanId}/>}
        {tab === "vulns"      && <TabVulns findings={findings} scanId={currentScanId}/>}
        {tab === "secrets"    && <TabSecrets currentScanId={currentScanId} findings={findings}/>}
        {tab === "headers"    && <TabHeaders currentScanId={currentScanId} assets={assets}/>}
        {tab === "techstacks" && <TabTechStacks assets={assets} findings={findings} isRunning={isRunning} onRunNuclei={() => setTab("scan")}/>}
        {tab === "takeover"   && <TabTakeover assets={assets} currentScanId={currentScanId}/>}
        {tab === "replay"     && <TabReplay/>}
        {tab === "osint"      && <TabOsint/>}
        {tab === "cloud"      && <TabCloud currentScanId={currentScanId}/>}
        {tab === "compare"    && <TabComparison scans={scans}/>}
        {tab === "penforge"   && <TabPenForgeExport currentScanId={currentScanId} scopeList={scopeList}/>}
        {tab === "export"     && <TabExport scans={scans} currentScanId={currentScanId} findings={findings}/>}
      </div>
    </div>
  );
}

function Dot({ color, pulse }: { color:string; pulse?:boolean }) {
  return <span style={{ display:"inline-block", width:7, height:7, borderRadius:"50%", background:color, flexShrink:0, ...(pulse?{animation:"pulse-red 1.2s infinite"}:{}) }}/>;
}
