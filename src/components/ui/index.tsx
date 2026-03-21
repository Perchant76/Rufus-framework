// src/components/ui/index.tsx
import React from "react";
import type { Severity } from "../../types";

// ── Severity Badge ────────────────────────────────────────────────────────────
const SEV_STYLES: Record<Severity, React.CSSProperties> = {
  CRITICAL: { background: "rgba(255,59,92,.18)", color: "var(--red)",    border: "1px solid rgba(255,59,92,.35)" },
  HIGH:     { background: "rgba(255,123,44,.15)",color: "var(--orange)", border: "1px solid rgba(255,123,44,.3)" },
  MEDIUM:   { background: "rgba(245,197,24,.12)",color: "var(--yellow)", border: "1px solid rgba(245,197,24,.25)"},
  LOW:      { background: "rgba(34,197,94,.1)",  color: "var(--green)",  border: "1px solid rgba(34,197,94,.2)"  },
  INFO:     { background: "rgba(0,212,255,.1)",  color: "var(--accent)", border: "1px solid rgba(0,212,255,.2)" },
};

export function SevBadge({ sev }: { sev: Severity }) {
  return (
    <span style={{
      ...SEV_STYLES[sev],
      display: "inline-flex", alignItems: "center",
      fontSize: 10, fontWeight: 700, letterSpacing: ".8px",
      padding: "2px 8px", borderRadius: 3, textTransform: "uppercase",
      whiteSpace: "nowrap",
    }}>{sev}</span>
  );
}

// ── Status dot ────────────────────────────────────────────────────────────────
export function Dot({ color, pulse }: { color: string; pulse?: boolean }) {
  return (
    <span style={{
      display: "inline-block", width: 7, height: 7, borderRadius: "50%",
      background: color, flexShrink: 0,
      ...(pulse ? { animation: "pulse-dot 1s infinite", color } : {}),
    }} />
  );
}

// ── Progress bar ──────────────────────────────────────────────────────────────
export function ProgBar({ pct, color }: { pct: number; color?: string }) {
  return (
    <div style={{ width: "100%", height: 3, background: "var(--bg3)", borderRadius: 2, overflow: "hidden" }}>
      <div style={{
        height: "100%", width: `${Math.min(pct, 100)}%`,
        borderRadius: 2, transition: "width .4s ease",
        background: color ?? "linear-gradient(90deg, var(--accent), var(--purple))",
      }} />
    </div>
  );
}

// ── Button ────────────────────────────────────────────────────────────────────
interface BtnProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost" | "danger";
  size?: "sm" | "md";
}
export function Btn({ variant = "ghost", size = "md", style, ...props }: BtnProps) {
  const base: React.CSSProperties = {
    display: "inline-flex", alignItems: "center", gap: 6,
    fontFamily: "var(--font-mono)", fontWeight: 600, cursor: "pointer",
    border: "none", borderRadius: "var(--r)", transition: "all .15s",
    ...(size === "sm" ? { height: 28, padding: "0 10px", fontSize: 11 }
                      : { height: 34, padding: "0 14px", fontSize: 12 }),
  };
  const variants: Record<string, React.CSSProperties> = {
    primary: { background: "var(--accent)", color: "#000" },
    ghost:   { background: "var(--bg2)", color: "var(--text)", border: "1px solid var(--border)" },
    danger:  { background: "rgba(255,59,92,.15)", color: "var(--red)", border: "1px solid rgba(255,59,92,.3)" },
  };
  return <button style={{ ...base, ...variants[variant], ...style }} {...props} />;
}

// ── Card ──────────────────────────────────────────────────────────────────────
export function Card({ children, style, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div style={{
      background: "var(--bg1)", border: "1px solid var(--border)",
      borderRadius: "var(--r-lg)", padding: 16, ...style
    }} {...props}>{children}</div>
  );
}

// ── Section Header ────────────────────────────────────────────────────────────
export function SectionHdr({ title, right }: { title: string; right?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ width: 3, height: 12, background: "var(--accent)", borderRadius: 2 }} />
        <span style={{
          fontFamily: "var(--font-ui)", fontSize: 11, fontWeight: 700,
          color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "1.5px",
        }}>{title}</span>
      </div>
      {right && <div style={{ display: "flex", alignItems: "center", gap: 8 }}>{right}</div>}
    </div>
  );
}

// ── Field ─────────────────────────────────────────────────────────────────────
export function Field({
  label, children, style,
}: { label: string; children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6, ...style }}>
      <label style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1 }}>
        {label}
      </label>
      {children}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  background: "var(--bg2)", border: "1px solid var(--border)",
  color: "var(--text)", fontFamily: "var(--font-mono)", fontSize: 13,
  borderRadius: "var(--r)", padding: "8px 12px", outline: "none",
  width: "100%", transition: "border .15s",
};

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const [focused, setFocused] = React.useState(false);
  return (
    <input
      {...props}
      style={{ ...inputStyle, borderColor: focused ? "var(--accent)" : "var(--border)", ...props.style }}
      onFocus={e => { setFocused(true); props.onFocus?.(e); }}
      onBlur={e => { setFocused(false); props.onBlur?.(e); }}
    />
  );
}

export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const [focused, setFocused] = React.useState(false);
  return (
    <textarea
      {...props}
      style={{ ...inputStyle, resize: "vertical", minHeight: 80, borderColor: focused ? "var(--accent)" : "var(--border)", ...props.style }}
      onFocus={e => { setFocused(true); props.onFocus?.(e); }}
      onBlur={e => { setFocused(false); props.onBlur?.(e); }}
    />
  );
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select {...props} style={{ ...inputStyle, cursor: "pointer", ...props.style }} />
  );
}

// ── FilterChip ────────────────────────────────────────────────────────────────
export function FilterChip({
  label, active, onClick, accentColor,
}: { label: string; active: boolean; onClick: () => void; accentColor?: string }) {
  const ac = accentColor ?? "var(--accent)";
  return (
    <button onClick={onClick} style={{
      display: "flex", alignItems: "center", gap: 4, padding: "4px 10px",
      background: active ? `${ac}18` : "var(--bg2)",
      border: `1px solid ${active ? ac : "var(--border)"}`,
      borderRadius: 20, fontSize: 11, cursor: "pointer",
      color: active ? ac : "var(--text-dim)", transition: "all .15s",
      fontFamily: "var(--font-mono)",
    }}>{label}</button>
  );
}

// ── Scope tag ─────────────────────────────────────────────────────────────────
export function ScopeTag({ inScope }: { inScope: boolean }) {
  return (
    <span style={{
      fontSize: 9, padding: "2px 7px", borderRadius: 3, fontWeight: 600,
      textTransform: "uppercase", letterSpacing: ".5px",
      ...(inScope
        ? { background: "rgba(34,197,94,.1)", color: "var(--green)", border: "1px solid rgba(34,197,94,.2)" }
        : { background: "rgba(255,59,92,.1)", color: "var(--red)", border: "1px solid rgba(255,59,92,.2)" }),
    }}>{inScope ? "In-Scope" : "Out-of-Scope"}</span>
  );
}

// ── Log line ──────────────────────────────────────────────────────────────────
const LOG_COLORS: Record<string, string> = {
  info: "var(--accent)", warn: "var(--yellow)", error: "var(--red)",
  ok: "var(--green)", dim: "var(--text-dim)",
};
export function LogLine({ time, level, msg }: { time: string; level: string; msg: string }) {
  return (
    <div style={{ display: "flex", gap: 10, lineHeight: 1.7 }}>
      <span style={{ color: "var(--text-dim)", flexShrink: 0, fontSize: 11 }}>{time}</span>
      <span style={{ color: LOG_COLORS[level] ?? "var(--text)", fontSize: 11 }}>{msg}</span>
    </div>
  );
}

// ── CVE chips ─────────────────────────────────────────────────────────────────
export function CVEChip({ cve }: { cve: string }) {
  return (
    <span style={{
      display: "inline-block", fontSize: 11, color: "var(--accent)",
      background: "var(--accent-dim)", border: "1px solid rgba(0,212,255,.25)",
      borderRadius: 3, padding: "1px 7px", marginRight: 6, marginBottom: 4,
    }}>{cve}</span>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────
export function StatCard({ num, label, color }: { num: number | string; label: string; color: string }) {
  return (
    <div style={{
      background: "var(--bg2)", border: "1px solid var(--border)",
      borderRadius: "var(--r)", padding: "14px 16px",
    }}>
      <div style={{ fontFamily: "var(--font-ui)", fontSize: 32, fontWeight: 800, color, lineHeight: 1 }}>{num}</div>
      <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginTop: 4 }}>{label}</div>
    </div>
  );
}

// ── Divider ───────────────────────────────────────────────────────────────────
export function Divider() {
  return <div style={{ width: 1, height: 20, background: "var(--border)", flexShrink: 0 }} />;
}

// ── Tag ───────────────────────────────────────────────────────────────────────
export function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span style={{
      display: "inline-block", fontSize: 10, padding: "1px 6px",
      background: "var(--bg3)", border: "1px solid var(--border)",
      borderRadius: 3, color: "var(--text-dim)", marginRight: 4,
    }}>{children}</span>
  );
}
