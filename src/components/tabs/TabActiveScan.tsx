// src/components/tabs/TabActiveScan.tsx
import React from "react";
import { Card, SectionHdr, Btn, Dot, ProgBar, Tag } from "../ui";
import type { ScanConfig, ScanProgress } from "../../types";
import { ALL_TOOLS } from "../../types";

interface Props {
  config: ScanConfig;
  onConfigChange: (c: ScanConfig) => void;
  isRunning: boolean;
  onStart: () => void;
  onStop: () => void;
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

  const relevantTools = ALL_TOOLS.filter(t =>
    config.target_type === "DOMAIN" ? t.domain : t.ip
  );

  const totalPct = toolProgress
    ? Object.values(toolProgress).reduce((a, b) => a + b, 0) / Math.max(config.tools.length, 1)
    : 0;

  return (
    <div style={{ display: "grid", gridTemplateColumns: "340px 1fr", gap: 16, padding: 20, height: "100%", overflow: "hidden" }}>

      {/* Left — tool selection + scan control */}
      <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: 16 }}>
        <div>
          <SectionHdr title="Select Tools"
            right={
              <div style={{ display: "flex", gap: 6 }}>
                <Btn size="sm" onClick={() => onConfigChange({ ...config, tools: relevantTools.map(t => t.name) })}>All</Btn>
                <Btn size="sm" onClick={() => onConfigChange({ ...config, tools: [] })}>None</Btn>
              </div>
            }
          />
          <Card>
            {relevantTools.map(t => {
              const sel = config.tools.includes(t.name);
              const pct = toolProgress[t.name] ?? 0;
              const done = pct >= 100;
              const running = isRunning && pct > 0 && pct < 100;
              return (
                <div key={t.name} onClick={() => !isRunning && toggleTool(t.name)}
                  style={{
                    display: "flex", alignItems: "center", gap: 10, padding: "9px 0",
                    borderBottom: "1px solid var(--border)", cursor: isRunning ? "default" : "pointer",
                  }}>
                  <div style={{
                    width: 14, height: 14, border: `1px solid ${sel ? "var(--accent)" : "var(--border)"}`,
                    borderRadius: 3, background: sel ? "var(--accent)" : "transparent",
                    flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    {sel && <span style={{ color: "#000", fontSize: 9, fontWeight: 900 }}>✓</span>}
                  </div>
                  <Dot color={done ? "var(--green)" : running ? "var(--yellow)" : "var(--bg4)"} pulse={running} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: "var(--text-hi)" }}>{t.name}</div>
                    <div style={{ fontSize: 10, color: "var(--text-dim)" }}>{t.category}</div>
                    {isRunning && sel && (
                      <div style={{ marginTop: 4 }}>
                        <ProgBar pct={pct} color={done ? "var(--green)" : undefined} />
                      </div>
                    )}
                  </div>
                  {isRunning && sel && (
                    <span style={{ fontSize: 10, color: "var(--text-dim)", flexShrink: 0 }}>{Math.round(pct)}%</span>
                  )}
                </div>
              );
            })}
          </Card>
        </div>

        {/* Scan control card */}
        <Card>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 8 }}>
              Target: <span style={{ color: "var(--accent)" }}>{config.target || "not set"}</span>
              {" · "}{config.tools.length} tools selected
              {" · "}{config.stealth_mode ? "Stealth ON" : "Full speed"}
            </div>
            {isRunning && (
              <div style={{ marginBottom: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: 10, color: "var(--text-dim)" }}>Overall progress</span>
                  <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{Math.round(totalPct)}%</span>
                </div>
                <ProgBar pct={totalPct} />
              </div>
            )}
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            {isRunning ? (
              <Btn variant="danger" onClick={onStop} style={{ flex: 1 }}>
                ⏹ Stop Scan
              </Btn>
            ) : (
              <Btn variant="primary" onClick={onStart} style={{ flex: 1 }}
                disabled={!config.target || config.tools.length === 0}>
                ▶ Start Scan
              </Btn>
            )}
          </div>

          {!config.target && (
            <p style={{ fontSize: 11, color: "var(--red)", marginTop: 8 }}>
              ⚠ No target set — go to Target & Scope tab first.
            </p>
          )}
        </Card>
      </div>

      {/* Right — live output */}
      <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: 16 }}>

        {/* Live findings count */}
        <div>
          <SectionHdr title="Live Findings"
            right={
              findingCount > 0 && (
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{findingCount} so far</span>
              )
            }
          />
          <Card style={{ padding: "20px 16px", textAlign: "center" }}>
            {findingCount === 0 ? (
              <span style={{ color: "var(--text-dim)", fontSize: 12 }}>
                {isRunning ? "Waiting for findings…" : "No findings yet. Start a scan."}
              </span>
            ) : (
              <span style={{ fontSize: 28, fontFamily: "var(--font-ui)", fontWeight: 800, color: "var(--accent)" }}>
                {findingCount}
                <span style={{ fontSize: 13, color: "var(--text-dim)", fontWeight: 400, marginLeft: 8 }}>
                  findings — see Vulnerabilities tab for details
                </span>
              </span>
            )}
          </Card>
        </div>

        {/* Log stream */}
        <div>
          <SectionHdr title="Scanner Log" />
          <div style={{
            background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)",
            padding: 12, height: 320, overflowY: "auto", fontFamily: "var(--font-mono)",
          }}>
            {logs.length === 0 && (
              <span style={{ color: "var(--text-dim)", fontSize: 11 }}>Ready.</span>
            )}
            {logs.map((l, i) => {
              const levelColors: Record<string, string> = {
                info: "var(--accent)", warn: "var(--yellow)",
                error: "var(--red)", ok: "var(--green)",
              };
              return (
                <div key={i} style={{ display: "flex", gap: 10, lineHeight: 1.8 }}>
                  <span style={{ color: "var(--text-dim)", fontSize: 10, flexShrink: 0 }}>
                    {new Date().toTimeString().slice(0, 8)}
                  </span>
                  <span style={{ fontSize: 11, color: levelColors[l.level] ?? "var(--text)" }}>
                    {l.message}
                  </span>
                </div>
              );
            })}
            {isRunning && (
              <span style={{ color: "var(--text-dim)", fontSize: 11, animation: "blink 1s infinite" }}>▋</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
