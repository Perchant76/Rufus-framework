// src/App.tsx
import React, { useState, useEffect, useRef, useCallback } from "react";
import type {
  ScanConfig, ScanProgress, VulnFinding, DiscoveredAsset,
  TargetType, Scan,
} from "./types";
import { ALL_TOOLS } from "./types";
import {
  startScan, stopScan, getScans,
  onScanProgress, onScanFinding, onScanAsset,
} from "./lib/api";
import TabTarget from "./components/tabs/TabTarget";
import TabDiscovery from "./components/tabs/TabDiscovery";
import TabActiveScan from "./components/tabs/TabActiveScan";
import TabVulns from "./components/tabs/TabVulns";
import TabComparison from "./components/tabs/TabComparison";
import TabExport from "./components/tabs/TabExport";

// ── Detect target type ────────────────────────────────────────────────────────
function detectType(val: string): TargetType {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(val.trim()) ? "IP" : "DOMAIN";
}

// ── Default scan config ───────────────────────────────────────────────────────
function defaultConfig(): ScanConfig {
  return {
    target: "",
    target_type: "DOMAIN",
    scope: [],
    stealth_mode: false,
    concurrency: 25,
    delay_min_ms: 0,
    delay_max_ms: 0,
    tools: ALL_TOOLS.map(t => t.name),
    auth: { mode: "none" },
    respect_robots: false,
  };
}

type TabId = "target" | "discovery" | "scan" | "vulns" | "compare" | "export";

// ── Tab definition ────────────────────────────────────────────────────────────
const TABS: { id: TabId; label: string; icon: string }[] = [
  { id: "target",    label: "Target & Scope",  icon: "◎" },
  { id: "discovery", label: "Discovery",        icon: "⊕" },
  { id: "scan",      label: "Active Scan",      icon: "▶" },
  { id: "vulns",     label: "Vulnerabilities",  icon: "⚠" },
  { id: "compare",   label: "Comparison",       icon: "⇌" },
  { id: "export",    label: "Export",           icon: "↗" },
];

export default function App() {
  const [tab, setTab] = useState<TabId>("target");
  const [config, setConfig] = useState<ScanConfig>(defaultConfig);
  const [stealthOn, setStealthOn] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  // Live scan data
  const [logs, setLogs] = useState<ScanProgress[]>([]);
  const [findings, setFindings] = useState<VulnFinding[]>([]);
  const [assets, setAssets] = useState<DiscoveredAsset[]>([]);
  const [toolProgress, setToolProgress] = useState<Record<string, number>>({});

  // Historical scans
  const [scans, setScans] = useState<Scan[]>([]);

  // Event unlisten refs
  const unlistenProgress = useRef<(() => void) | null>(null);
  const unlistenFinding  = useRef<(() => void) | null>(null);
  const unlistenAsset    = useRef<(() => void) | null>(null);

  // Load scan history on mount
  useEffect(() => {
    getScans().then(setScans).catch(console.error);
  }, []);

  // Keep stealth in config in sync
  useEffect(() => {
    setConfig(c => ({
      ...c,
      stealth_mode: stealthOn,
      concurrency: stealthOn ? 1 : 25,
      delay_min_ms: stealthOn ? 500 : 0,
      delay_max_ms: stealthOn ? 2000 : 0,
    }));
  }, [stealthOn]);

  // Keep target_type in sync with target value
  useEffect(() => {
    if (config.target) {
      setConfig(c => ({ ...c, target_type: detectType(c.target) }));
    }
  }, [config.target]);

  // ── Start scan ───────────────────────────────────────────────────────────
  const handleStart = useCallback(async () => {
    if (!config.target) return;

    // Reset live state
    setLogs([]);
    setFindings([]);
    setAssets([]);
    setToolProgress({});
    setIsRunning(true);
    setTab("discovery");

    // Set up event listeners
    unlistenProgress.current = await onScanProgress(p => {
      setLogs(prev => [...prev.slice(-500), p]); // keep last 500 lines
      if (p.percent >= 0) {
        setToolProgress(prev => ({ ...prev, [p.tool]: p.percent }));
      }
    });

    unlistenFinding.current = await onScanFinding(f => {
      setFindings(prev => [...prev, f]);
    });

    unlistenAsset.current = await onScanAsset(a => {
      setAssets(prev => [...prev, a]);
    });

    try {
      const scanId = await startScan(config);
      setCurrentScanId(scanId);
    } catch (err) {
      console.error("Scan failed:", err);
    } finally {
      setIsRunning(false);
      // Refresh scan history
      getScans().then(setScans).catch(console.error);
      // Clean up listeners
      unlistenProgress.current?.();
      unlistenFinding.current?.();
      unlistenAsset.current?.();
    }
  }, [config]);

  // ── Stop scan ────────────────────────────────────────────────────────────
  const handleStop = useCallback(async () => {
    try {
      await stopScan();
    } catch (err) {
      console.error("Stop failed:", err);
    }
    setIsRunning(false);
    unlistenProgress.current?.();
    unlistenFinding.current?.();
    unlistenAsset.current?.();
    getScans().then(setScans).catch(console.error);
  }, []);

  const targetType = config.target ? detectType(config.target) : null;

  const criticalCount = findings.filter(f => f.severity === "CRITICAL" && f.in_scope).length;
  const inScopeCount  = findings.filter(f => f.in_scope).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden", background: "var(--bg0)" }}>

      {/* ── Top bar ─────────────────────────────────────────────────────── */}
      <div style={{
        display: "flex", alignItems: "center", gap: 16,
        height: 52, padding: "0 20px", flexShrink: 0,
        background: "var(--bg1)", borderBottom: "1px solid var(--border)",
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
          <div style={{
            width: 28, height: 28, background: "var(--accent)", borderRadius: 6,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 14, color: "#000", fontWeight: 900,
          }}>P</div>
          <span style={{ fontFamily: "var(--font-ui)", fontSize: 17, fontWeight: 800, color: "var(--text-hi)", letterSpacing: "-.3px" }}>
            PROBE<span style={{ color: "var(--accent)" }}>SCAN</span>
          </span>
        </div>

        {/* Target bar */}
        <div style={{
          display: "flex", alignItems: "center", gap: 8, flex: 1, maxWidth: 520,
          background: "var(--bg2)", border: "1px solid var(--border)",
          borderRadius: "var(--r)", padding: "0 12px", height: 34,
        }}>
          <span style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, flexShrink: 0 }}>
            Target
          </span>
          <input
            value={config.target}
            onChange={e => setConfig(c => ({ ...c, target: e.target.value }))}
            placeholder="domain.com or 1.2.3.4"
            style={{
              flex: 1, background: "none", border: "none", outline: "none",
              color: "var(--accent)", fontFamily: "var(--font-mono)", fontSize: 13,
            }}
          />
          {targetType && (
            <span style={{
              fontSize: 9, padding: "2px 7px", borderRadius: 3, fontWeight: 700,
              letterSpacing: ".8px", textTransform: "uppercase", flexShrink: 0,
              ...(targetType === "DOMAIN"
                ? { background: "rgba(168,85,247,.2)", color: "var(--purple)", border: "1px solid rgba(168,85,247,.35)" }
                : { background: "rgba(0,212,255,.12)", color: "var(--accent)", border: "1px solid rgba(0,212,255,.25)" }),
            }}>{targetType}</span>
          )}
        </div>

        {/* Spacer */}
        <div style={{ flex: 1 }} />

        {/* Stealth toggle */}
        <div
          onClick={() => setStealthOn(s => !s)}
          style={{
            display: "flex", alignItems: "center", gap: 8, cursor: "pointer",
            fontSize: 11, padding: "5px 10px",
            background: stealthOn ? "rgba(34,197,94,.08)" : "var(--bg2)",
            border: `1px solid ${stealthOn ? "var(--green)" : "var(--border)"}`,
            borderRadius: "var(--r)", color: stealthOn ? "var(--green)" : "var(--text-dim)",
            transition: "all .2s", userSelect: "none",
          }}>
          <div style={{
            width: 24, height: 12, borderRadius: 6, position: "relative",
            background: stealthOn ? "rgba(34,197,94,.3)" : "var(--bg3)",
            border: `1px solid ${stealthOn ? "var(--green)" : "var(--border)"}`,
            transition: "all .2s",
          }}>
            <div style={{
              position: "absolute", top: 2, borderRadius: "50%",
              width: 6, height: 6, transition: "all .2s",
              left: stealthOn ? 14 : 2,
              background: stealthOn ? "var(--green)" : "var(--text-dim)",
            }} />
          </div>
          Stealth
        </div>

        <div style={{ width: 1, height: 20, background: "var(--border)" }} />

        {/* Scan button */}
        <button
          onClick={isRunning ? handleStop : handleStart}
          disabled={!isRunning && !config.target}
          style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            height: 34, padding: "0 18px", borderRadius: "var(--r)",
            fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 700,
            border: "none", cursor: config.target || isRunning ? "pointer" : "not-allowed",
            background: isRunning ? "var(--red)" : "var(--accent)",
            color: isRunning ? "#fff" : "#000",
            transition: "all .15s",
          }}>
          {isRunning ? "⏹ Stop" : "▶ Scan"}
        </button>
      </div>

      {/* ── Tab bar ──────────────────────────────────────────────────────── */}
      <div style={{
        display: "flex", alignItems: "center",
        background: "var(--bg1)", borderBottom: "1px solid var(--border)",
        padding: "0 20px", flexShrink: 0, overflowX: "auto",
      }}>
        {TABS.map(t => {
          const badge =
            t.id === "discovery" && assets.length > 0 ? assets.length :
            t.id === "vulns" && inScopeCount > 0 ? inScopeCount :
            t.id === "scan" && isRunning ? "RUN" :
            null;

          const badgeDanger = t.id === "vulns" && criticalCount > 0;

          return (
            <div
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                display: "flex", alignItems: "center", gap: 7,
                padding: "0 16px", height: 42, cursor: "pointer",
                fontSize: 12, color: tab === t.id ? "var(--accent)" : "var(--text-dim)",
                borderBottom: `2px solid ${tab === t.id ? "var(--accent)" : "transparent"}`,
                whiteSpace: "nowrap", transition: "all .15s",
              }}>
              <span style={{ opacity: .7 }}>{t.icon}</span>
              {t.label}
              {badge !== null && (
                <span style={{
                  fontSize: 9, borderRadius: 8, padding: "1px 5px", fontWeight: 700,
                  minWidth: 16, textAlign: "center",
                  background: badgeDanger ? "var(--red)" : t.id === "discovery" ? "var(--green)" : isRunning ? "var(--yellow)" : "var(--accent)",
                  color: t.id === "scan" && isRunning ? "#000" : "#fff",
                }}>{badge}</span>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <div style={{ flex: 1, overflow: "hidden", display: "flex" }}>
        {tab === "target" && (
          <TabTarget config={config} onChange={setConfig} stealthOn={stealthOn} />
        )}
        {tab === "discovery" && (
          <TabDiscovery
            assets={assets}
            logs={logs}
            toolProgress={toolProgress}
            isRunning={isRunning}
            scanId={currentScanId}
          />
        )}
        {tab === "scan" && (
          <TabActiveScan
            config={config}
            onConfigChange={setConfig}
            isRunning={isRunning}
            onStart={handleStart}
            onStop={handleStop}
            logs={logs}
            toolProgress={toolProgress}
            findingCount={findings.length}
          />
        )}
        {tab === "vulns" && (
          <TabVulns
            findings={findings}
            scanId={currentScanId}
          />
        )}
        {tab === "compare" && (
          <TabComparison scans={scans} />
        )}
        {tab === "export" && (
          <TabExport
            scans={scans}
            currentScanId={currentScanId}
            findings={findings}
          />
        )}
      </div>
    </div>
  );
}
