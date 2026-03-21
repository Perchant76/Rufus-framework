// src/components/tabs/TabDiscovery.tsx
import React, { useRef, useEffect } from "react";
import { Card, SectionHdr, Dot, ScopeTag, Tag, Btn, StatCard, ProgBar } from "../ui";
import type { DiscoveredAsset, ScanProgress } from "../../types";
import { parseTechStack } from "../../types";

interface Props {
  assets: DiscoveredAsset[];
  logs: ScanProgress[];
  toolProgress: Record<string, number>;
  isRunning: boolean;
  scanId: string | null;
}

function statusColor(code: number | null) {
  if (!code) return "var(--bg4)";
  if (code >= 200 && code < 300) return "var(--green)";
  if (code >= 300 && code < 400) return "var(--yellow)";
  if (code >= 400) return "var(--red)";
  return "var(--text-dim)";
}

function SubdomainTree({ nodes, depth = 0 }: { nodes: DiscoveredAsset[]; depth?: number }) {
  const rootNodes = nodes.filter(n => n.parent === null || depth === 0 && !nodes.some(p => n.parent === p.value));
  const sorted = [...nodes].sort((a, b) => a.value.localeCompare(b.value));

  return (
    <div style={depth > 0 ? { paddingLeft: 20, borderLeft: "1px solid var(--border)", marginLeft: 6 } : {}}>
      {sorted.filter(n => depth === 0 ? !n.parent : n.parent === undefined).map(n => {
        const children = nodes.filter(c => c.parent === n.value);
        const techs = parseTechStack(n.tech_stack);
        return (
          <div key={n.id}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", fontSize: 11, lineHeight: 1.8 }}>
              {depth > 0 && <span style={{ color: "var(--border-hi)" }}>├─</span>}
              <Dot color={statusColor(n.http_status)} />
              <span style={{ color: n.in_scope ? "var(--text-hi)" : "var(--red)" }}>{n.value}</span>
              {!n.in_scope && <ScopeTag inScope={false} />}
              {n.ip && <span style={{ color: "var(--text-dim)", fontSize: 10 }}>{n.ip}</span>}
              {n.http_status && <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{n.http_status}</span>}
              {techs.map(t => <Tag key={t}>{t}</Tag>)}
            </div>
            {children.length > 0 && <SubdomainTree nodes={children} depth={depth + 1} />}
          </div>
        );
      })}
    </div>
  );
}

export default function TabDiscovery({ assets, logs, toolProgress, isRunning, scanId }: Props) {
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  const subdomains = assets.filter(a => a.asset_type === "subdomain");
  const endpoints = assets.filter(a => a.asset_type === "endpoint");
  const inScope = assets.filter(a => a.in_scope);

  const logLevelColor: Record<string, string> = {
    info: "var(--accent)", warn: "var(--yellow)", error: "var(--red)",
    ok: "var(--green)", dim: "var(--text-dim)",
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 16, padding: 20, height: "100%", overflow: "hidden" }}>

      {/* Left column */}
      <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: 16 }}>

        <div>
          <SectionHdr title="Subdomain Tree"
            right={
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                  {subdomains.length} found · {inScope.length} in-scope
                </span>
                <Btn size="sm">Export CSV</Btn>
              </div>
            }
          />
          <Card style={{ fontFamily: "var(--font-mono)" }}>
            {subdomains.length === 0 ? (
              <p style={{ color: "var(--text-dim)", fontSize: 11 }}>
                {isRunning ? "Discovering subdomains…" : "No subdomains found yet. Start a scan to begin."}
              </p>
            ) : (
              <SubdomainTree nodes={subdomains} />
            )}
          </Card>
        </div>

        <div>
          <SectionHdr title="Live Log"
            right={isRunning && (
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Dot color="var(--red)" pulse />
                <span style={{ fontSize: 11, color: "var(--red)" }}>SCANNING</span>
              </div>
            )}
          />
          <div ref={logRef} style={{
            background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)",
            padding: 12, height: 260, overflowY: "auto", fontFamily: "var(--font-mono)",
          }}>
            {logs.length === 0 && (
              <p style={{ color: "var(--text-dim)", fontSize: 11 }}>No activity yet.</p>
            )}
            {logs.map((l, i) => {
              const time = new Date().toTimeString().slice(0, 8);
              return (
                <div key={i} style={{ display: "flex", gap: 10, lineHeight: 1.7 }}>
                  <span style={{ color: "var(--text-dim)", fontSize: 11, flexShrink: 0 }}>{time}</span>
                  <span style={{ fontSize: 11, color: logLevelColor[l.level] ?? "var(--text)" }}>{l.message}</span>
                </div>
              );
            })}
            {isRunning && (
              <span style={{ color: "var(--text-dim)", fontSize: 11, animation: "blink 1s infinite" }}>▋</span>
            )}
          </div>
        </div>
      </div>

      {/* Right column */}
      <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: 16 }}>

        <div>
          <SectionHdr title="Discovery Stats" />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <StatCard num={subdomains.length} label="Subdomains" color="var(--accent)" />
            <StatCard num={endpoints.length} label="Endpoints" color="var(--purple)" />
            <StatCard num={assets.filter(a => a.asset_type === "form").length} label="Forms Found" color="var(--yellow)" />
            <StatCard num={inScope.length} label="In-Scope" color="var(--green)" />
          </div>
        </div>

        <div>
          <SectionHdr title="Tool Progress" />
          <Card>
            {Object.entries(toolProgress).length === 0 && (
              <p style={{ fontSize: 11, color: "var(--text-dim)" }}>Tools idle.</p>
            )}
            {Object.entries(toolProgress).map(([tool, pct]) => (
              <div key={tool} style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: 11, color: "var(--text-hi)" }}>{tool}</span>
                  <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{Math.round(pct)}%</span>
                </div>
                <ProgBar pct={pct} color={pct === 100 ? "var(--green)" : undefined} />
              </div>
            ))}
          </Card>
        </div>

        {subdomains.length > 0 && (
          <div>
            <SectionHdr title="Endpoint Sample" />
            <Card style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
              {endpoints.slice(0, 15).map(e => (
                <div key={e.id} style={{ padding: "3px 0", borderBottom: "1px solid var(--border)", color: "var(--text-dim)" }}>
                  <span style={{ color: "var(--accent)" }}>{e.value}</span>
                </div>
              ))}
              {endpoints.length > 15 && (
                <p style={{ marginTop: 6, color: "var(--text-dim)" }}>+{endpoints.length - 15} more</p>
              )}
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
