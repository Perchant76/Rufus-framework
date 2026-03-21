// src/components/tabs/TabActiveScan.tsx
import React from "react";
import { Card, SectionHdr, Dot, ProgBar, Tag } from "../ui";
import type { ScanConfig, ScanProgress } from "../../types";
import { ALL_TOOLS } from "../../types";

interface Props {
  config: ScanConfig;
  onConfigChange: (c: ScanConfig) => void;
  isRunning: boolean;
  onStart: () => void | Promise<void>;
  onStop: () => void | Promise<void>;
  logs: ScanProgress[];
  toolProgress: Record<string, number>;
  findingCount: number;
}

export default function TabActiveScan({
  config, onConfigChange, isRunning, onStart, onStop,
  logs, toolProgress, findingCount,
}: Props) {
  const toggleTool = (name: string) => {
    const tools = config.tools.includes(name)
      ? config.tools.filter(t => t !== name)
      : [...config.tools, name];
    onConfigChange({ ...config, tools });
  };

  const overallPct = Object.keys(toolProgress).length > 0
    ? Object.values(toolProgress).reduce((a, b) => a + b, 0) / Object.keys(toolProgress).length
    : 0;

  const logColor: Record<string, string> = {
    info: "var(--accent)", warn: "var(--yellow)", error: "var(--red)", ok: "var(--green)",
  };

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 840, paddingBottom: 40 }}>

        {/* Tool selector */}
        <SectionHdr title="Select Tools"
          right={
            <div style={{ display: "flex", gap: 6 }}>
              <button onClick={() => onConfigChange({ ...config, tools: ALL_TOOLS.map(t => t.name) })}
                style={{ padding: "4px 10px", background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: "var(--r)", fontSize: 11, cursor: "pointer", color: "var(--text)", fontFamily: "var(--font-mono)" }}>
                All
              </button>
              <button onClick={() => onConfigChange({ ...config, tools: [] })}
                style={{ padding: "4px 10px", background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: "var(--r)", fontSize: 11, cursor: "pointer", color: "var(--text)", fontFamily: "var(--font-mono)" }}>
                None
              </button>
            </div>
          }
        />
        <Card style={{ marginBottom: 16 }}>
          {ALL_TOOLS.map(def => {
            const sel = config.tools.includes(def.name);
            return (
              <div key={def.name} onClick={() => toggleTool(def.name)}
                style={{
                  display: "flex", alignItems: "center", gap: 12, padding: "10px 12px",
                  cursor: "pointer", background: "var(--bg2)", border: "1px solid var(--border)",
                  borderRadius: "var(--r)", marginBottom: 6,
                }}>
                <div style={{
                  width: 16, height: 16, border: `1px solid ${sel ? "var(--accent)" : "var(--border)"}`,
                  borderRadius: 3, background: sel ? "var(--accent)" : "transparent", flexShrink: 0,
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}>
                  {sel && <span style={{ color: "#000", fontSize: 10, fontWeight: 900 }}>✓</span>}
                </div>
                <span style={{ fontSize: 12, color: "var(--text-hi)", flex: 1 }}>{def.name}</span>
                <Tag>{def.category}</Tag>
                <span style={{ fontSize: 10, color: "var(--text-dim)" }}>
                  {def.domain ? "web" : ""}{def.domain && def.ip ? " · " : ""}{def.ip ? "network" : ""}
                </span>
              </div>
            );
          })}
        </Card>

        {/* Scan control */}
        <SectionHdr title="Scan Control" />
        <Card style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                  Target: <span style={{ color: "var(--accent)" }}>{config.target || "—"}</span>
                </span>
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{config.tools.length} tools</span>
                {findingCount > 0 && (
                  <span style={{ fontSize: 11, color: "var(--yellow)" }}>{findingCount} findings</span>
                )}
              </div>
              <ProgBar pct={isRunning ? overallPct : 0} />
            </div>
            <button onClick={isRunning ? onStop : onStart}
              disabled={!isRunning && !config.target}
              style={{
                height: 38, padding: "0 20px", borderRadius: "var(--r)",
                fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 700,
                border: "none", cursor: "pointer",
                background: isRunning ? "var(--red)" : "var(--accent)",
                color: isRunning ? "#fff" : "#000",
              }}>
              {isRunning ? "⏹ Stop" : "▶ Start Scan"}
            </button>
          </div>
        </Card>

        {/* Finding count */}
        {(isRunning || findingCount > 0) && (
          <>
            <SectionHdr title="Live Findings" />
            <Card style={{ marginBottom: 16, textAlign: "center", padding: "20px 16px" }}>
              {findingCount === 0 ? (
                <span style={{ color: "var(--text-dim)", fontSize: 12 }}>Waiting for findings…</span>
              ) : (
                <span style={{ fontSize: 28, fontFamily: "var(--font-ui)", fontWeight: 800, color: "var(--accent)" }}>
                  {findingCount}
                  <span style={{ fontSize: 13, color: "var(--text-dim)", fontWeight: 400, marginLeft: 8 }}>
                    findings — see Vulnerabilities tab for details
                  </span>
                </span>
              )}
            </Card>
          </>
        )}

        {/* Per-tool progress */}
        {Object.keys(toolProgress).length > 0 && (
          <>
            <SectionHdr title="Tool Progress" />
            <Card style={{ marginBottom: 16 }}>
              {config.tools.map(name => {
                const pct = toolProgress[name] ?? 0;
                const active = isRunning && pct > 0 && pct < 100;
                return (
                  <div key={name} style={{ marginBottom: 12 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <Dot color={pct >= 100 ? "var(--green)" : active ? "var(--yellow)" : "var(--bg4)"} pulse={active} />
                      <span style={{ fontSize: 12, color: "var(--text-hi)", flex: 1 }}>{name}</span>
                      <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{Math.round(pct)}%</span>
                    </div>
                    <ProgBar pct={pct} color={pct >= 100 ? "var(--green)" : undefined} />
                  </div>
                );
              })}
            </Card>
          </>
        )}

        {/* Log output */}
        {logs.length > 0 && (
          <>
            <SectionHdr title="Output Log" />
            <div style={{
              background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)",
              padding: 12, height: 300, overflowY: "auto", fontFamily: "var(--font-mono)",
            }}>
              {logs.slice(-200).map((l, i) => (
                <div key={i} style={{ display: "flex", gap: 10, lineHeight: 1.7 }}>
                  <span style={{ fontSize: 11, color: "var(--text-dim)", flexShrink: 0 }}>
                    {new Date().toTimeString().slice(0, 8)}
                  </span>
                  <span style={{ fontSize: 11, color: logColor[l.level] ?? "var(--text)" }}>
                    {l.message}
                  </span>
                </div>
              ))}
              {isRunning && <span style={{ color: "var(--text-dim)", animation: "blink 1s infinite" }}>▋</span>}
            </div>
          </>
        )}

        {!isRunning && !config.target && (
          <div style={{ textAlign: "center", padding: "60px 0", color: "var(--text-dim)" }}>
            <div style={{ fontSize: 40, opacity: .2, marginBottom: 12 }}>◎</div>
            <div style={{ fontSize: 12 }}>Set a target in the Target & Scope tab to begin.</div>
          </div>
        )}
      </div>
    </div>
  );
}
