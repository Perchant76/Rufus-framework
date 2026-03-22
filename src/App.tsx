// src/App.tsx — Rufus Framework v4.0
import React, { useState, useEffect, useRef, useCallback } from "react";
import type { ScanConfig, ScanProgress, VulnFinding, DiscoveredAsset, TargetType, Scan } from "./types";
import { ALL_TOOLS } from "./types";
import { startScan, stopScan, getScans, onScanProgress, onScanFinding, onScanAsset } from "./lib/api";
import { invoke } from "@tauri-apps/api/core";
import { RufusLogo } from "./components/ui";
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
  "programs" | "workflow" | "target" | "scope" | "discovery" | "scan" |
  "phases" | "vulns" | "secrets" | "headers" | "replay" | "osint" |
  "cloud" | "compare" | "penforge" | "export";

const TABS: { id: TabId; label: string; icon: string }[] = [
  { id:"programs",  label:"Programs",    icon:"◈" },
  { id:"workflow",  label:"Workflow",    icon:"⬡" },
  { id:"target",    label:"Target",      icon:"◎" },
  { id:"scope",     label:"Scope",       icon:"🎯" },
  { id:"discovery", label:"Discovery",   icon:"⊕" },
  { id:"scan",      label:"Scan",        icon:"▶" },
  { id:"phases",    label:"Phases",      icon:"⚙" },
  { id:"vulns",     label:"Vulns",       icon:"⚠" },
  { id:"secrets",   label:"JS Secrets",  icon:"🔑" },
  { id:"headers",   label:"Headers",     icon:"🛡" },
  { id:"replay",    label:"Replay",      icon:"↺" },
  { id:"osint",     label:"OSINT",       icon:"◉" },
  { id:"cloud",     label:"Cloud",       icon:"⬢" },
  { id:"compare",   label:"Compare",     icon:"⇌" },
  { id:"penforge",  label:"→ PenForge",  icon:"📤" },
  { id:"export",    label:"Export",      icon:"↗" },
];

export default function App() {
  const [tab, setTab]             = useState<TabId>("programs");
  const [config, setConfig]       = useState<ScanConfig>(defaultConfig);
  const [stealthOn, setStealthOn] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [logs, setLogs]           = useState<ScanProgress[]>([]);
  const [findings, setFindings]   = useState<VulnFinding[]>([]);
  const [assets, setAssets]       = useState<DiscoveredAsset[]>([]);
  const [toolProgress, setToolProgress] = useState<Record<string, number>>({});
  const [scans, setScans]         = useState<Scan[]>([]);
  // New state for added features
  const [scopeList, setScopeList] = useState<string[]>([]);
  const [excludePatterns, setExcludePatterns] = useState<string[]>([]);
  const [rateLimitMs, setRateLimitMs] = useState(200);
  const [isPaused, setIsPaused]   = useState(false);

  const unlistenProgress = useRef<(()=>void)|null>(null);
  const unlistenFinding  = useRef<(()=>void)|null>(null);
  const unlistenAsset    = useRef<(()=>void)|null>(null);

  useEffect(() => {
    getScans().then(setScans).catch(() => {});
    // Setup listeners
    onScanProgress((prog) => {
      setLogs(prev => [prog, ...prev].slice(0, 500));
      if (prog.percent >= 0)
        setToolProgress(prev => ({ ...prev, [prog.tool]: prog.percent }));
    }).then(fn => { unlistenProgress.current = fn; });

    onScanFinding((f) => setFindings(prev => {
      if (prev.some(x => x.id === f.id)) return prev;
      return [f, ...prev];
    })).then(fn => { unlistenFinding.current = fn; });

    onScanAsset((a) => setAssets(prev => {
      if (prev.some(x => x.id === a.id)) return prev;
      return [a, ...prev];
    })).then(fn => { unlistenAsset.current = fn; });

    return () => {
      unlistenProgress.current?.();
      unlistenFinding.current?.();
      unlistenAsset.current?.();
    };
  }, []);

  // Sync scope changes to config
  useEffect(() => {
    setConfig(prev => ({
      ...prev,
      scope: scopeList,
      delay_min_ms: rateLimitMs,
      delay_max_ms: rateLimitMs > 0 ? rateLimitMs * 1.5 : 0,
    }));
  }, [scopeList, rateLimitMs]);

  const handleStart = useCallback(async () => {
    if (isRunning) return;
    const targetType = detectType(config.target);
    const scopeEntries = scopeList.length > 0 ? scopeList : [config.target];
    const cfg: ScanConfig = {
      ...config,
      target_type: targetType,
      stealth_mode: stealthOn,
      scope: scopeEntries,
      delay_min_ms: rateLimitMs,
      delay_max_ms: rateLimitMs > 0 ? Math.floor(rateLimitMs * 1.5) : 0,
    };
    setLogs([]); setFindings([]); setAssets([]); setToolProgress({}); setIsPaused(false);
    setIsRunning(true);
    try {
      const scanId = await startScan(cfg);
      setCurrentScanId(scanId);
      // Save session checkpoint
      invoke("save_scan_session", { scanId, currentPhase: 1, completedPhases: [] }).catch(() => {});
      getScans().then(setScans).catch(() => {});
      setTab("scan");
    } catch (e) {
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

  const handlePause = useCallback(async () => {
    await invoke("pause_scan").catch(() => {});
    setIsPaused(true);
  }, []);

  const handleResume = useCallback(async () => {
    await invoke("resume_scan").catch(() => {});
    setIsPaused(false);
  }, []);

  const handleProgramScan = (target: string) => {
    setConfig(prev => ({ ...prev, target, target_type: detectType(target) }));
    setTab("target");
  };

  const inScopeCount  = findings.filter(f => f.in_scope).length;
  const criticalCount = findings.filter(f => f.in_scope && f.severity === "CRITICAL").length;
  const targetType    = detectType(config.target);

  return (
    <div style={{
      display:"flex", flexDirection:"column", height:"100vh", overflow:"hidden",
      background:"var(--bg0)", color:"var(--text)",
      fontFamily:"var(--font-ui)",
    }}>
      {/* ── Top Bar ──────────────────────────────────────────────────────── */}
      <div style={{
        display:"flex", alignItems:"center", gap:14, padding:"0 20px",
        height:52, background:"var(--bg1)", borderBottom:"1px solid var(--border)",
        flexShrink:0, boxShadow:"0 2px 16px rgba(0,0,0,0.5)",
      }}>
        <RufusLogo size={28}/>
        <span style={{ fontSize:14, fontWeight:900, letterSpacing:4, color:"var(--text)", fontFamily:"var(--font-ui)" }}>
          RUFUS<span style={{ color:"var(--accent)", marginLeft:2 }}>⬡</span>
        </span>
        <div style={{ width:1, height:24, background:"var(--border)" }}/>
        {config.target && (
          <span style={{ fontSize:10, color:"var(--text-dim)", letterSpacing:2, fontFamily:"var(--font-ui)" }}>
            {config.target}
            <span style={{ marginLeft:8, color:"var(--accent)", fontSize:9, background:"rgba(232,0,26,0.1)", border:"1px solid rgba(232,0,26,0.2)", padding:"1px 6px", borderRadius:3 }}>{targetType}</span>
          </span>
        )}
        {scopeList.length > 0 && (
          <span style={{ fontSize:9, color:"var(--green)", background:"rgba(34,197,94,0.08)", border:"1px solid rgba(34,197,94,0.2)", padding:"2px 8px", borderRadius:4, letterSpacing:1 }}>
            🎯 {scopeList.length} SCOPE ENTRIES
          </span>
        )}
        <div style={{ flex:1 }}/>

        {/* Pause/Resume button when running */}
        {isRunning && (
          <button onClick={isPaused ? handleResume : handlePause}
            style={{ display:"flex", alignItems:"center", gap:6, height:30, padding:"0 14px", borderRadius:"var(--r)", fontFamily:"var(--font-ui)", fontSize:10, fontWeight:700, letterSpacing:1, border:`1px solid ${isPaused?"rgba(34,197,94,0.4)":"rgba(245,158,11,0.4)"}`, background:isPaused?"rgba(34,197,94,0.1)":"rgba(245,158,11,0.1)", color:isPaused?"var(--green)":"#f59e0b", cursor:"pointer", transition:"all .15s" }}>
            {isPaused ? "▶ RESUME" : "⏸ PAUSE"}
          </button>
        )}

        {/* Status indicator */}
        {isRunning && (
          <div style={{ display:"flex", alignItems:"center", gap:8, padding:"5px 12px", background:isPaused?"rgba(245,158,11,0.1)":"rgba(232,0,26,.1)", border:`1px solid ${isPaused?"rgba(245,158,11,0.3)":"rgba(232,0,26,.3)"}`, borderRadius:"var(--r)", fontSize:11, color:isPaused?"#f59e0b":"var(--accent)", fontFamily:"var(--font-ui)", letterSpacing:"1px" }}>
            <Dot color={isPaused?"#f59e0b":"var(--accent)"} pulse={!isPaused}/>
            {isPaused ? "PAUSED" : "SCANNING"}
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
        }}>
          <div style={{ width:26, height:13, borderRadius:7, position:"relative", background: stealthOn ? "rgba(0,255,136,.2)" : "var(--bg3)", border:`1px solid ${stealthOn ? "var(--green)" : "var(--border)"}`, transition:"all .2s" }}>
            <div style={{ position:"absolute", top:2, borderRadius:"50%", width:7, height:7, transition:"all .2s", left: stealthOn ? 15 : 2, background: stealthOn ? "var(--green)" : "var(--text-dim)" }} />
          </div>
          STEALTH
        </div>

        <div style={{ width:1, height:30, background:"var(--border)" }}/>

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
            boxShadow: isRunning ? "0 0 20px rgba(232,0,26,0.6)" : "0 0 12px rgba(232,0,26,0.3)",
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
        padding:"0 12px", flexShrink:0, overflowX:"auto", gap:0,
        boxShadow:"0 2px 12px rgba(0,0,0,0.3)",
      }}>
        {TABS.map(t => {
          const badge =
            t.id === "discovery" && assets.length > 0 ? assets.length :
            t.id === "vulns" && inScopeCount > 0 ? inScopeCount :
            t.id === "scan" && isRunning ? "●" :
            t.id === "phases" && isRunning ? "●" :
            null;
          const isActive = tab === t.id;
          const isPenForge = t.id === "penforge";
          return (
            <div key={t.id} onClick={() => setTab(t.id)} style={{
              display:"flex", alignItems:"center", gap:5, padding:"0 12px", height:44,
              cursor:"pointer", fontSize:9, fontFamily:"var(--font-ui)", letterSpacing:"1.5px",
              color: isActive ? "#fff" : isPenForge ? "rgba(59,130,246,0.7)" : "var(--text-dim)",
              borderBottom:`2px solid ${isActive ? (isPenForge?"#3b82f6":"var(--accent)") : "transparent"}`,
              background: isActive ? (isPenForge?"rgba(59,130,246,0.06)":"rgba(232,0,26,0.06)") : "transparent",
              whiteSpace:"nowrap", transition:"all .15s",
            }}>
              <span style={{ fontSize:11 }}>{t.icon}</span>
              {t.label}
              {badge !== null && (
                <span style={{ fontSize:9, borderRadius:8, padding:"1px 5px", fontWeight:700, minWidth:16, textAlign:"center", background: t.id === "vulns" && criticalCount > 0 ? "var(--red)" : t.id === "scan" || t.id === "phases" ? "var(--accent)" : "rgba(0,255,136,.9)", color:"#fff" }}>{badge}</span>
              )}
            </div>
          );
        })}
        <div style={{ marginLeft:"auto", fontSize:9, color:"var(--text-dim)", fontFamily:"var(--font-ui)", letterSpacing:"2px", paddingRight:8, flexShrink:0 }}>
          v4.0 // ALPHA
        </div>
      </div>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <div style={{ flex:1, overflow:"hidden", display:"flex", position:"relative", zIndex:1 }}>
        {tab === "programs"  && <TabPrograms onStartScan={handleProgramScan} />}
        {tab === "workflow"  && <TabWorkflow />}
        {tab === "target"    && <TabTarget config={config} onChange={setConfig} stealthOn={stealthOn} />}
        {tab === "scope"     && <TabScope scope={scopeList} onScopeChange={setScopeList} rateLimitMs={rateLimitMs} onRateLimitChange={setRateLimitMs} excludePatterns={excludePatterns} onExcludeChange={setExcludePatterns}/>}
        {tab === "discovery" && <TabDiscovery assets={assets} logs={logs} toolProgress={toolProgress} isRunning={isRunning} scanId={currentScanId} />}
        {tab === "scan"      && <TabActiveScan config={config} onConfigChange={setConfig} isRunning={isRunning} onStart={handleStart} onStop={handleStop} logs={logs} toolProgress={toolProgress} findingCount={findings.length} />}
        {tab === "phases"    && <TabPhaseControl isRunning={isRunning} currentScanId={currentScanId} />}
        {tab === "vulns"     && <TabVulns findings={findings} scanId={currentScanId} />}
        {tab === "secrets"   && <TabSecrets currentScanId={currentScanId} findings={findings} />}
        {tab === "headers"   && <TabHeaders currentScanId={currentScanId} assets={assets} />}
        {tab === "replay"    && <TabReplay />}
        {tab === "osint"     && <TabOsint />}
        {tab === "cloud"     && <TabCloud currentScanId={currentScanId} />}
        {tab === "compare"   && <TabComparison scans={scans} />}
        {tab === "penforge"  && <TabPenForgeExport currentScanId={currentScanId} scopeList={scopeList} />}
        {tab === "export"    && <TabExport scans={scans} currentScanId={currentScanId} findings={findings} />}
      </div>
    </div>
  );
}

function Dot({ color, pulse }: { color: string; pulse?: boolean }) {
  return <span style={{ display:"inline-block", width:7, height:7, borderRadius:"50%", background:color, flexShrink:0, ...(pulse ? { animation:"pulse-red 1.2s infinite" } : {}) }} />;
}
