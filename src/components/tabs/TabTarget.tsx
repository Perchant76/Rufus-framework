// src/components/tabs/TabTarget.tsx
import React, { useState, useEffect } from "react";
import { Card, SectionHdr, Field, Input, Textarea, Select, Btn, Dot, ProgBar, FilterChip } from "../ui";
import type { AuthConfig, ScanConfig } from "../../types";
import { ALL_TOOLS } from "../../types";
import { checkAllTools } from "../../lib/api";
import type { ToolStatus } from "../../types";

interface Props {
  config: ScanConfig;
  onChange: (c: ScanConfig) => void;
  stealthOn: boolean;
}

export default function TabTarget({ config, onChange, stealthOn }: Props) {
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [loadingTools, setLoadingTools] = useState(true);

  useEffect(() => {
    checkAllTools()
      .then(setTools)
      .catch(() => setTools([]))
      .finally(() => setLoadingTools(false));
  }, []);

  const set = (partial: Partial<ScanConfig>) => onChange({ ...config, ...partial });

  const setAuth = (partial: Partial<AuthConfig>) =>
    onChange({ ...config, auth: { ...config.auth!, ...partial } });

  const toggleTool = (name: string) => {
    const next = config.tools.includes(name)
      ? config.tools.filter(t => t !== name)
      : [...config.tools, name];
    set({ tools: next });
  };

  const authMode = config.auth?.mode ?? "none";
  const setAuthMode = (mode: AuthConfig["mode"]) =>
    onChange({ ...config, auth: { mode, ...config.auth } });

  const statusFor = (name: string) => tools.find(t => t.name === name);

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 840, paddingBottom: 40 }}>

        {/* Target */}
        <SectionHdr title="Primary Target" />
        <Card style={{ marginBottom: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Field label="Domain or IP Address">
              <Input
                value={config.target}
                onChange={e => set({ target: e.target.value })}
                placeholder="target.com or 93.184.216.0"
              />
            </Field>
            <Field label="Scan Profile">
              <Select onChange={e => {}}>
                <option>Full Scan (All Tools)</option>
                <option>Discovery Only</option>
                <option>Web Focus</option>
                <option>Network Focus</option>
              </Select>
            </Field>
          </div>
        </Card>

        {/* Scope */}
        <SectionHdr title="Scope Definition" />
        <Card style={{ marginBottom: 16 }}>
          <Field label="In-Scope Domains / IPs / CIDR Ranges (one per line)">
            <Textarea
              value={config.scope.join("\n")}
              onChange={e => set({ scope: e.target.value.split("\n").filter(Boolean) })}
              rows={4}
            />
          </Field>
          <p style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
            Assets discovered outside this scope are flagged OOS and excluded from active scanning.
          </p>
        </Card>

        {/* Authentication */}
        <SectionHdr title="Authentication" />
        <Card style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
            {(["none","form","cookie","bearer","basic"] as AuthConfig["mode"][]).map(m => (
              <FilterChip key={m} label={
                m === "none" ? "No Auth" : m === "form" ? "Form Login" :
                m === "cookie" ? "Cookie" : m === "bearer" ? "Bearer Token" : "HTTP Basic"
              } active={authMode === m} onClick={() => setAuthMode(m)} />
            ))}
          </div>

          {authMode === "form" && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <Field label="Login URL"><Input placeholder="https://target.com/login" onChange={e => setAuth({ login_url: e.target.value })} /></Field>
              <Field label="Username Field"><Input placeholder="username" /></Field>
              <Field label="Username"><Input onChange={e => setAuth({ username: e.target.value })} /></Field>
              <Field label="Password"><Input type="password" onChange={e => setAuth({ password: e.target.value })} /></Field>
            </div>
          )}
          {authMode === "cookie" && (
            <Field label="Raw Cookie String">
              <Input placeholder="session_id=abc123; csrf_token=xyz..." onChange={e => setAuth({ cookie_string: e.target.value })} />
            </Field>
          )}
          {authMode === "bearer" && (
            <Field label="Authorization Header">
              <Input placeholder="Bearer eyJhbGciOiJIUzI1NiIs..." onChange={e => setAuth({ bearer_token: e.target.value })} />
            </Field>
          )}
          {authMode === "basic" && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <Field label="Username"><Input onChange={e => setAuth({ username: e.target.value })} /></Field>
              <Field label="Password"><Input type="password" onChange={e => setAuth({ password: e.target.value })} /></Field>
            </div>
          )}
          {authMode === "none" && (
            <p style={{ fontSize: 11, color: "var(--text-dim)" }}>No credentials — scans run unauthenticated.</p>
          )}
        </Card>

        {/* Rate / Concurrency */}
        <SectionHdr title="Rate & Concurrency" />
        <Card style={{ marginBottom: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <Field label="Concurrency">
              <Input type="number" value={config.concurrency} min={1} max={100}
                onChange={e => set({ concurrency: Number(e.target.value) })} />
            </Field>
            <Field label="Delay Min (ms)">
              <Input type="number" value={config.delay_min_ms}
                onChange={e => set({ delay_min_ms: Number(e.target.value) })} />
            </Field>
            <Field label="Delay Max (ms)">
              <Input type="number" value={config.delay_max_ms}
                onChange={e => set({ delay_max_ms: Number(e.target.value) })} />
            </Field>
          </div>
          {stealthOn && (
            <div style={{ marginTop: 12, padding: "8px 12px", background: "rgba(34,197,94,.06)", border: "1px solid rgba(34,197,94,.2)", borderRadius: "var(--r)", fontSize: 11, color: "var(--green)" }}>
              ⚡ Stealth mode active — UA rotation enabled, passive-first, robots.txt respected
            </div>
          )}
        </Card>

        {/* Tool Selection + Status */}
        <SectionHdr title="Tool Availability & Selection"
          right={
            <div style={{ display: "flex", gap: 6 }}>
              <Btn size="sm" onClick={() => set({ tools: ALL_TOOLS.map(t => t.name) })}>Select All</Btn>
              <Btn size="sm" onClick={() => set({ tools: [] })}>None</Btn>
            </div>
          }
        />
        <Card>
          {loadingTools ? (
            <p style={{ color: "var(--text-dim)", fontSize: 12, padding: "8px 0" }}>Checking tools…</p>
          ) : (
            ALL_TOOLS.map(def => {
              const st = statusFor(def.name);
              const available = st?.available ?? false;
              const selected = config.tools.includes(def.name);
              return (
                <div key={def.name} onClick={() => available && toggleTool(def.name)}
                  style={{
                    display: "flex", alignItems: "center", gap: 12, padding: "10px 12px",
                    background: "var(--bg2)", border: "1px solid var(--border)",
                    borderRadius: "var(--r)", marginBottom: 6, cursor: available ? "pointer" : "default",
                    opacity: available ? 1 : .5,
                  }}>
                  {/* Checkbox */}
                  <div style={{
                    width: 16, height: 16, border: `1px solid ${selected ? "var(--accent)" : "var(--border)"}`,
                    borderRadius: 3, background: selected ? "var(--accent)" : "transparent",
                    flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    {selected && <span style={{ color: "#000", fontSize: 10, fontWeight: 900 }}>✓</span>}
                  </div>

                  <Dot color={available ? "var(--green)" : "var(--red)"} />

                  <span style={{ fontSize: 12, color: "var(--text-hi)", flex: 1 }}>{def.name}</span>
                  <span style={{ fontSize: 10, color: "var(--text-dim)", flex: 1 }}>{def.category}</span>
                  {st?.version && <span style={{ fontSize: 10, color: "var(--text-dim)" }}>v{st.version}</span>}

                  {!available && (
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                        {def.install}
                      </span>
                      <Btn size="sm" style={{ borderColor: "var(--yellow)", color: "var(--yellow)", background: "rgba(245,197,24,.06)" }}>
                        Install
                      </Btn>
                    </div>
                  )}
                  {available && (
                    <span style={{ fontSize: 10, color: "var(--green)", background: "rgba(34,197,94,.1)", border: "1px solid rgba(34,197,94,.2)", borderRadius: 3, padding: "1px 7px" }}>
                      ready
                    </span>
                  )}
                </div>
              );
            })
          )}
        </Card>
      </div>
    </div>
  );
}
