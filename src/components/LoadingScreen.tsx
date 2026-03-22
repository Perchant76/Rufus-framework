// src/components/LoadingScreen.tsx — Doxbin-style elite boot sequence
import React, { useEffect, useState, useRef } from "react";

const BOOT_LINES = [
  { delay: 0,    text: "RUFUS FRAMEWORK v4.0 // INITIALISING",        color: "#e8001a" },
  { delay: 150,  text: "► Loading recon engine...",                    color: "#ffffff" },
  { delay: 280,  text: "► Mounting JSON data store...",                color: "#ffffff" },
  { delay: 420,  text: "► Verifying tool availability...",             color: "#ffffff" },
  { delay: 600,  text: "► Loading nuclei template index...",           color: "#ffffff" },
  { delay: 750,  text: "► Initialising scope enforcement engine...",   color: "#ffffff" },
  { delay: 900,  text: "► Loading JS secret pattern library (30)...",  color: "#ffffff" },
  { delay: 1050, text: "► Connecting subsystems...",                   color: "#ffffff" },
  { delay: 1200, text: "[ OK ] All systems nominal.",                  color: "#00ff88" },
  { delay: 1400, text: "[ OK ] FOR AUTHORISED USE ONLY.",              color: "#ffd700" },
];

interface Props { onDone: () => void; }

export default function LoadingScreen({ onDone }: Props) {
  const [visibleLines, setVisibleLines] = useState<number[]>([]);
  const [progress, setProgress] = useState(0);
  const [done, setDone] = useState(false);
  const [fadeOut, setFadeOut] = useState(false);
  const startRef = useRef(Date.now());

  useEffect(() => {
    // Show each line on its delay
    BOOT_LINES.forEach((line, i) => {
      setTimeout(() => {
        setVisibleLines(prev => [...prev, i]);
        setProgress(Math.round(((i + 1) / BOOT_LINES.length) * 100));
      }, line.delay);
    });

    // Mark done after all lines + small pause
    const totalDuration = BOOT_LINES[BOOT_LINES.length - 1].delay + 700;
    setTimeout(() => setDone(true), totalDuration);
    setTimeout(() => setFadeOut(true), totalDuration + 200);
    setTimeout(() => onDone(), totalDuration + 700);
  }, []);

  // Animate progress bar independently
  useEffect(() => {
    const interval = setInterval(() => {
      const elapsed = Date.now() - startRef.current;
      const total = BOOT_LINES[BOOT_LINES.length - 1].delay + 500;
      setProgress(Math.min(100, Math.round((elapsed / total) * 100)));
    }, 16);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9999,
      background: "#060608",
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      fontFamily: "'JetBrains Mono', monospace",
      opacity: fadeOut ? 0 : 1,
      transition: "opacity 0.5s ease",
      overflow: "hidden",
    }}>
      {/* Background grid */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        backgroundImage: "linear-gradient(rgba(232,0,26,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(232,0,26,0.025) 1px, transparent 1px)",
        backgroundSize: "40px 40px",
      }}/>

      {/* Radial glow behind logo */}
      <div style={{
        position: "absolute", top: "20%", left: "50%", transform: "translateX(-50%)",
        width: 600, height: 600,
        background: "radial-gradient(circle, rgba(232,0,26,0.08) 0%, transparent 70%)",
        pointerEvents: "none",
      }}/>

      {/* Corner brackets — top left */}
      <div style={{ position:"absolute", top:20, left:20, width:50, height:50, borderTop:"2px solid rgba(232,0,26,0.6)", borderLeft:"2px solid rgba(232,0,26,0.6)" }}/>
      <div style={{ position:"absolute", top:20, right:20, width:50, height:50, borderTop:"2px solid rgba(232,0,26,0.6)", borderRight:"2px solid rgba(232,0,26,0.6)" }}/>
      <div style={{ position:"absolute", bottom:20, left:20, width:50, height:50, borderBottom:"2px solid rgba(232,0,26,0.6)", borderLeft:"2px solid rgba(232,0,26,0.6)" }}/>
      <div style={{ position:"absolute", bottom:20, right:20, width:50, height:50, borderBottom:"2px solid rgba(232,0,26,0.6)", borderRight:"2px solid rgba(232,0,26,0.6)" }}/>

      {/* Main content */}
      <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:32, position:"relative", zIndex:1, width:"100%", maxWidth:600, padding:"0 40px" }}>

        {/* Logo */}
        <LogoSplash/>

        {/* Title */}
        <div style={{ textAlign:"center" }}>
          <div style={{
            fontSize: 28, fontWeight: 900, letterSpacing: 8,
            fontFamily: "'Orbitron', monospace",
            color: "#ffffff",
            textShadow: "0 0 20px rgba(232,0,26,0.8), 0 0 40px rgba(232,0,26,0.4)",
          }}>
            RUFUS<span style={{ color:"#e8001a" }}>⬡</span>FRAMEWORK
          </div>
          <div style={{ fontSize: 10, letterSpacing: 5, color: "rgba(232,0,26,0.7)", marginTop: 6, fontFamily:"'Orbitron',monospace" }}>
            ELITE RECONNAISSANCE SUITE
          </div>
        </div>

        {/* Boot log terminal */}
        <div style={{
          width: "100%",
          background: "rgba(10,11,15,0.9)",
          border: "1px solid rgba(232,0,26,0.25)",
          borderRadius: 8,
          padding: "14px 18px",
          minHeight: 160,
          boxShadow: "0 0 30px rgba(232,0,26,0.08), inset 0 0 30px rgba(0,0,0,0.5)",
        }}>
          {BOOT_LINES.map((line, i) => (
            <div key={i} style={{
              fontSize: 11,
              color: visibleLines.includes(i) ? line.color : "transparent",
              marginBottom: 4,
              lineHeight: 1.6,
              transition: "color 0.15s ease",
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              {visibleLines.includes(i) && (
                <TypeWriter text={line.text} speed={18}/>
              )}
            </div>
          ))}
          {/* Cursor blink */}
          {!done && (
            <span style={{ display:"inline-block", width:8, height:14, background:"#e8001a", animation:"blink 1s step-end infinite", verticalAlign:"middle", marginTop:2 }}/>
          )}
        </div>

        {/* Progress bar */}
        <div style={{ width:"100%", display:"flex", flexDirection:"column", gap:8 }}>
          <div style={{ display:"flex", justifyContent:"space-between", fontSize:9, color:"rgba(255,255,255,0.3)", letterSpacing:2 }}>
            <span>LOADING</span>
            <span style={{ color: progress === 100 ? "#00ff88" : "rgba(255,255,255,0.3)" }}>{progress}%</span>
          </div>
          <div style={{ height:3, background:"rgba(255,255,255,0.06)", borderRadius:2, overflow:"hidden" }}>
            <div style={{
              height: "100%",
              width: `${progress}%`,
              background: progress === 100
                ? "linear-gradient(90deg, #00ff88, #22c55e)"
                : "linear-gradient(90deg, #8b0010, #e8001a, #ff2244)",
              borderRadius: 2,
              boxShadow: `0 0 12px ${progress === 100 ? "rgba(0,255,136,0.6)" : "rgba(232,0,26,0.6)"}`,
              transition: "width 0.1s linear, background 0.5s ease, box-shadow 0.5s ease",
            }}/>
          </div>
        </div>

        {/* Version footer */}
        <div style={{ fontSize:9, color:"rgba(255,255,255,0.15)", letterSpacing:3, fontFamily:"'Orbitron',monospace" }}>
          BUILD 4.0.0 — FOR AUTHORISED USE ONLY
        </div>
      </div>

      <style>{`
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes logoSpin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes logoPulse { 0%,100%{opacity:0.6} 50%{opacity:1} }
      `}</style>
    </div>
  );
}

// Typewriter effect for each boot line
function TypeWriter({ text, speed }: { text: string; speed: number }) {
  const [displayed, setDisplayed] = useState("");
  useEffect(() => {
    let i = 0;
    const interval = setInterval(() => {
      i++;
      setDisplayed(text.slice(0, i));
      if (i >= text.length) clearInterval(interval);
    }, speed);
    return () => clearInterval(interval);
  }, [text]);
  return <>{displayed}</>;
}

// Big logo for splash screen
function LogoSplash() {
  return (
    <svg width="120" height="120" viewBox="0 0 200 200" fill="none"
      style={{ filter:"drop-shadow(0 0 20px rgba(232,0,26,0.7))", animation:"logoPulse 2s ease-in-out infinite" }}>
      <defs>
        <filter id="glow-splash" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="4" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <linearGradient id="rg-splash" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#ff2244"/>
          <stop offset="100%" stopColor="#8b0010"/>
        </linearGradient>
        <radialGradient id="core-splash" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#e8001a" stopOpacity="0.3"/>
          <stop offset="100%" stopColor="#e8001a" stopOpacity="0"/>
        </radialGradient>
      </defs>
      <circle cx="100" cy="100" r="90" fill="url(#core-splash)"/>
      <polygon points="100,6 180,50 180,150 100,194 20,150 20,50"
        fill="none" stroke="url(#rg-splash)" strokeWidth="3" filter="url(#glow-splash)"/>
      <polygon points="100,22 164,60 164,140 100,178 36,140 36,60"
        fill="none" stroke="#e8001a" strokeWidth="1" opacity="0.4"/>
      <polygon points="100,38 148,65 148,135 100,162 52,135 52,65"
        fill="rgba(232,0,26,0.08)" stroke="#e8001a" strokeWidth="0.75" opacity="0.6"/>
      {[72,82,92,102,112,122,132].map((y,i) => (
        <line key={y} x1="52" y1={y} x2="148" y2={y} stroke="#e8001a" strokeWidth="0.5" opacity={0.05+i*0.012}/>
      ))}
      {/* Rotating reticle */}
      <circle cx="100" cy="100" r="32"
        stroke="#e8001a" strokeWidth="1.5" fill="none" strokeDasharray="6 4" opacity="0.8"
        style={{ animation:"logoSpin 8s linear infinite", transformOrigin:"100px 100px" }}/>
      <circle cx="100" cy="100" r="22" stroke="#e8001a" strokeWidth="0.75" fill="none" opacity="0.4"/>
      <circle cx="100" cy="100" r="18" fill="rgba(232,0,26,0.15)"/>
      <text x="100" y="118" textAnchor="middle"
        fontFamily="Orbitron,monospace" fontWeight="900" fontSize="52"
        fill="#ffffff" filter="url(#glow-splash)" letterSpacing="-2">R</text>
      <circle cx="100" cy="100" r="3.5" fill="#e8001a" filter="url(#glow-splash)"/>
      <circle cx="100" cy="100" r="1.5" fill="#fff"/>
      <circle cx="100" cy="6"   r="4" fill="#e8001a" filter="url(#glow-splash)"/>
      <circle cx="100" cy="194" r="4" fill="#e8001a" filter="url(#glow-splash)"/>
      <line x1="0" y1="100" x2="20" y2="100" stroke="#e8001a" strokeWidth="2.5" filter="url(#glow-splash)"/>
      <line x1="180" y1="100" x2="200" y2="100" stroke="#e8001a" strokeWidth="2.5" filter="url(#glow-splash)"/>
      <path d="M8,30 L8,8 L30,8" stroke="#e8001a" strokeWidth="2" fill="none" opacity="0.6"/>
      <path d="M192,30 L192,8 L170,8" stroke="#e8001a" strokeWidth="2" fill="none" opacity="0.6"/>
      <path d="M8,170 L8,192 L30,192" stroke="#e8001a" strokeWidth="2" fill="none" opacity="0.6"/>
      <path d="M192,170 L192,192 L170,192" stroke="#e8001a" strokeWidth="2" fill="none" opacity="0.6"/>
    </svg>
  );
}
