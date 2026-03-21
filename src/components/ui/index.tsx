// src/components/ui/index.tsx
import React from "react";
import type { Severity } from "../../types";

// ── Rufus SVG Logo ────────────────────────────────────────────────────────────
export function RufusLogo({ size = 36 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" style={{ animation: "glow-pulse 3s infinite", flexShrink: 0 }}>
      {/* Outer hexagon */}
      <polygon points="50,4 93,27 93,73 50,96 7,73 7,27" fill="none" stroke="#e8001a" strokeWidth="3" />
      {/* Inner hexagon */}
      <polygon points="50,16 82,34 82,66 50,84 18,66 18,34" fill="#e8001a" opacity="0.12" />
      {/* R letter */}
      <text x="50" y="67" textAnchor="middle" fontFamily="Orbitron,monospace" fontWeight="900" fontSize="44" fill="#e8001a">R</text>
      {/* Corner dots */}
      {[[50,4],[93,27],[93,73],[50,96],[7,73],[7,27]].map(([cx,cy],i) => (
        <circle key={i} cx={cx} cy={cy} r="3" fill="#e8001a" />
      ))}
      {/* Crosshair lines */}
      <line x1="0" y1="50" x2="14" y2="50" stroke="#e8001a" strokeWidth="1.5" opacity="0.6" />
      <line x1="86" y1="50" x2="100" y2="50" stroke="#e8001a" strokeWidth="1.5" opacity="0.6" />
      <line x1="50" y1="0" x2="50" y2="12" stroke="#e8001a" strokeWidth="1.5" opacity="0.6" />
      <line x1="50" y1="88" x2="50" y2="100" stroke="#e8001a" strokeWidth="1.5" opacity="0.6" />
    </svg>
  );
}

// ── Severity Badge ────────────────────────────────────────────────────────────
const SEV_STYLES: Record<Severity, React.CSSProperties> = {
  CRITICAL: { background:"rgba(255,26,61,.18)",  color:"#ff1a3d",  border:"1px solid rgba(255,26,61,.45)",  boxShadow:"0 0 8px rgba(255,26,61,.2)"  },
  HIGH:     { background:"rgba(255,107,43,.15)", color:"#ff6b2b",  border:"1px solid rgba(255,107,43,.4)"  },
  MEDIUM:   { background:"rgba(255,204,0,.12)",  color:"#ffcc00",  border:"1px solid rgba(255,204,0,.35)"  },
  LOW:      { background:"rgba(0,255,136,.1)",   color:"#00ff88",  border:"1px solid rgba(0,255,136,.3)"   },
  INFO:     { background:"rgba(59,130,246,.12)", color:"#60a5fa",  border:"1px solid rgba(59,130,246,.3)"  },
};

export function SevBadge({ sev }: { sev: Severity }) {
  return (
    <span style={{
      ...SEV_STYLES[sev],
      display:"inline-flex", alignItems:"center",
      fontSize:10, fontWeight:700, letterSpacing:"1px",
      padding:"3px 9px", borderRadius:4, textTransform:"uppercase",
      whiteSpace:"nowrap", fontFamily:"var(--font-mono)",
    }}>{sev}</span>
  );
}

// ── Status dot ────────────────────────────────────────────────────────────────
export function Dot({ color, pulse }: { color: string; pulse?: boolean }) {
  return (
    <span style={{
      display:"inline-block", width:7, height:7, borderRadius:"50%",
      background:color, flexShrink:0,
      ...(pulse ? { animation:"pulse-red 1.2s infinite", boxShadow:`0 0 0 0 ${color}` } : {}),
    }} />
  );
}

// ── Progress bar ──────────────────────────────────────────────────────────────
export function ProgBar({ pct, color }: { pct: number; color?: string }) {
  return (
    <div style={{ width:"100%", height:3, background:"var(--bg3)", borderRadius:2, overflow:"hidden", position:"relative" }}>
      <div style={{
        height:"100%", width:`${Math.min(pct,100)}%`, borderRadius:2,
        background: color ?? "linear-gradient(90deg, var(--accent), #ff3355)",
        transition:"width .4s ease",
        boxShadow: pct > 0 ? "0 0 6px rgba(232,0,26,0.5)" : "none",
      }} />
    </div>
  );
}

// ── Button ────────────────────────────────────────────────────────────────────
interface BtnProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost" | "danger" | "success";
  size?: "sm" | "md";
}
export function Btn({ variant="ghost", size="md", style, ...props }: BtnProps) {
  const base: React.CSSProperties = {
    display:"inline-flex", alignItems:"center", gap:6,
    fontFamily:"var(--font-mono)", fontWeight:600, cursor:"pointer",
    border:"none", borderRadius:"var(--r)", transition:"all .15s",
    letterSpacing:".3px", position:"relative", overflow:"hidden",
    ...(size==="sm" ? { height:28, padding:"0 12px", fontSize:11 } : { height:36, padding:"0 16px", fontSize:12 }),
  };
  const variants: Record<string, React.CSSProperties> = {
    primary: { background:"var(--accent)", color:"#fff", boxShadow:"0 0 16px rgba(232,0,26,0.4)" },
    ghost:   { background:"var(--bg2)", color:"var(--text)", border:"1px solid var(--border)" },
    danger:  { background:"rgba(255,26,61,.15)", color:"var(--red)", border:"1px solid rgba(255,26,61,.4)" },
    success: { background:"rgba(0,255,136,.1)", color:"var(--green)", border:"1px solid rgba(0,255,136,.3)" },
  };
  return <button style={{ ...base, ...variants[variant], ...style }} {...props} />;
}

// ── Card ──────────────────────────────────────────────────────────────────────
export function Card({ children, style, glow, ...props }: React.HTMLAttributes<HTMLDivElement> & { glow?: boolean }) {
  return (
    <div style={{
      background:"var(--bg1)",
      border:`1px solid ${glow ? "var(--accent)" : "var(--border)"}`,
      borderRadius:"var(--r-lg)", padding:16,
      boxShadow: glow ? "0 0 20px rgba(232,0,26,0.15), inset 0 0 20px rgba(232,0,26,0.03)" : "0 4px 24px rgba(0,0,0,0.4)",
      position:"relative",
      ...style,
    }} {...props}>{children}</div>
  );
}

// ── Section Header ────────────────────────────────────────────────────────────
export function SectionHdr({ title, right }: { title: string; right?: React.ReactNode }) {
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:14 }}>
      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
        <div style={{ width:3, height:14, background:"var(--accent)", borderRadius:2, boxShadow:"0 0 8px var(--accent)" }} />
        <span style={{ fontFamily:"var(--font-ui)", fontSize:10, fontWeight:700, color:"var(--text-hi)", textTransform:"uppercase", letterSpacing:"2px" }}>
          {title}
        </span>
      </div>
      {right && <div style={{ display:"flex", alignItems:"center", gap:8 }}>{right}</div>}
    </div>
  );
}

// ── Field ─────────────────────────────────────────────────────────────────────
export function Field({ label, children, style }: { label: string; children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:6, ...style }}>
      <label style={{ fontSize:10, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:"1.2px", fontFamily:"var(--font-mono)" }}>{label}</label>
      {children}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  background:"var(--bg2)", border:"1px solid var(--border)", color:"var(--text-hi)",
  fontFamily:"var(--font-mono)", fontSize:13, borderRadius:"var(--r)",
  padding:"8px 12px", outline:"none", width:"100%", transition:"border .15s",
};

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const [f, setF] = React.useState(false);
  return <input {...props} style={{ ...inputStyle, borderColor: f ? "var(--accent)" : "var(--border)", boxShadow: f ? "0 0 0 2px rgba(232,0,26,0.15)" : "none", ...props.style }} onFocus={e => { setF(true); props.onFocus?.(e); }} onBlur={e => { setF(false); props.onBlur?.(e); }} />;
}
export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const [f, setF] = React.useState(false);
  return <textarea {...props} style={{ ...inputStyle, resize:"vertical", minHeight:80, borderColor: f ? "var(--accent)" : "var(--border)", boxShadow: f ? "0 0 0 2px rgba(232,0,26,0.15)" : "none", ...props.style }} onFocus={e => { setF(true); props.onFocus?.(e); }} onBlur={e => { setF(false); props.onBlur?.(e); }} />;
}
export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} style={{ ...inputStyle, cursor:"pointer", ...props.style }}>{props.children}</select>;
}

// ── Filter Chip ───────────────────────────────────────────────────────────────
export function FilterChip({ label, active, onClick, accentColor }: { label: string; active: boolean; onClick: () => void; accentColor?: string }) {
  const ac = accentColor ?? "var(--accent)";
  return (
    <button onClick={onClick} style={{
      display:"flex", alignItems:"center", gap:4, padding:"4px 12px",
      background: active ? `rgba(${ac === "var(--accent)" ? "232,0,26" : "0,255,136"},.12)` : "var(--bg2)",
      border:`1px solid ${active ? ac : "var(--border)"}`,
      borderRadius:20, fontSize:11, cursor:"pointer", color: active ? ac : "var(--text-dim)",
      transition:"all .15s", fontFamily:"var(--font-mono)",
      boxShadow: active ? `0 0 8px ${ac}44` : "none",
    }}>{label}</button>
  );
}

// ── Scope tag ─────────────────────────────────────────────────────────────────
export function ScopeTag({ inScope }: { inScope: boolean }) {
  return (
    <span style={{
      fontSize:9, padding:"2px 7px", borderRadius:3, fontWeight:700,
      textTransform:"uppercase", letterSpacing:".8px", fontFamily:"var(--font-mono)",
      ...(inScope
        ? { background:"rgba(0,255,136,.1)", color:"var(--green)", border:"1px solid rgba(0,255,136,.25)" }
        : { background:"rgba(255,26,61,.1)", color:"var(--red)", border:"1px solid rgba(255,26,61,.25)" }),
    }}>{inScope ? "In-Scope" : "OOS"}</span>
  );
}

// ── CVE Chip ──────────────────────────────────────────────────────────────────
export function CVEChip({ cve }: { cve: string }) {
  return (
    <span style={{
      display:"inline-block", fontSize:10, color:"#60a5fa",
      background:"rgba(59,130,246,.12)", border:"1px solid rgba(59,130,246,.3)",
      borderRadius:3, padding:"1px 7px", marginRight:4, marginBottom:3,
      fontFamily:"var(--font-mono)",
    }}>{cve}</span>
  );
}

// ── Stat Card ─────────────────────────────────────────────────────────────────
export function StatCard({ num, label, color }: { num: number | string; label: string; color: string }) {
  return (
    <div style={{
      background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--r)",
      padding:"16px 18px", position:"relative", overflow:"hidden",
    }}>
      <div style={{ position:"absolute", inset:0, background:`radial-gradient(ellipse at top left, ${color}08, transparent 70%)` }} />
      <div style={{ fontFamily:"var(--font-ui)", fontSize:30, fontWeight:900, color, lineHeight:1, marginBottom:6, textShadow:`0 0 20px ${color}66` }}>{num}</div>
      <div style={{ fontSize:10, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:"1.2px", fontFamily:"var(--font-mono)" }}>{label}</div>
    </div>
  );
}

// ── Divider ───────────────────────────────────────────────────────────────────
export function Divider() {
  return <div style={{ width:1, height:20, background:"var(--border)", flexShrink:0 }} />;
}

// ── Tag ───────────────────────────────────────────────────────────────────────
export function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span style={{
      display:"inline-block", fontSize:10, padding:"2px 7px",
      background:"var(--bg3)", border:"1px solid var(--border)",
      borderRadius:3, color:"var(--text-dim)", marginRight:4,
      fontFamily:"var(--font-mono)",
    }}>{children}</span>
  );
}

// ── Log Line ──────────────────────────────────────────────────────────────────
const LOG_COLORS: Record<string, string> = {
  info:"#60a5fa", warn:"var(--yellow)", error:"var(--red)", ok:"var(--green)",
};
export function LogLine({ time, level, msg }: { time: string; level: string; msg: string }) {
  return (
    <div style={{ display:"flex", gap:10, lineHeight:1.7 }}>
      <span style={{ color:"var(--text-dim)", flexShrink:0, fontSize:11 }}>{time}</span>
      <span style={{ color: LOG_COLORS[level] ?? "var(--text)", fontSize:11 }}>{msg}</span>
    </div>
  );
}

// ── Footer brand ──────────────────────────────────────────────────────────────
export function FooterBrand() {
  return (
    <div style={{ textAlign:"center", marginTop:48, paddingTop:20, borderTop:"1px solid var(--border)", fontSize:11, color:"var(--text-dim)", fontFamily:"var(--font-mono)", letterSpacing:1 }}>
      <span style={{ color:"var(--accent)", fontFamily:"var(--font-ui)", fontWeight:700, fontSize:12 }}>RUFUS</span>
      {" FRAMEWORK  //  "}
      <span style={{ color:"var(--text-dim)" }}>BUILD WITH ❤️ BY PERCHANT</span>
    </div>
  );
}
