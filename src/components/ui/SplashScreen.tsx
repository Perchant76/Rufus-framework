// src/components/ui/SplashScreen.tsx
// Loading screen — Doxbin-inspired terminal aesthetic, aggressive
import React, { useState, useEffect } from "react";
import { RufusLogoLarge } from "./RufusLogo";

const BOOT_LINES = [
  { text: "INITIALIZING RUFUS FRAMEWORK v4.0",   delay: 0,    color: "#e8001a" },
  { text: "LOADING SCAN ENGINE..................", delay: 180,  color: "#ffffff" },
  { text: "MOUNTING ENCRYPTED VAULT.............", delay: 320,  color: "#ffffff" },
  { text: "INITIALIZING TOOL REGISTRY...........", delay: 480,  color: "#ffffff" },
  { text: "LOADING FINGERPRINT DATABASE.........", delay: 640,  color: "#ffffff" },
  { text: "STARTING PARSER MODULES..............", delay: 800,  color: "#ffffff" },
  { text: "CONFIGURING SCOPE ENGINE.............", delay: 920,  color: "#ffffff" },
  { text: "ALL SYSTEMS NOMINAL", delay: 1050, color: "#00ff88" },
  { text: "AUTHENTICATION REQUIRED ▮",           delay: 1200, color: "#e8001a" },
];

interface Props { onComplete: () => void; }

export function SplashScreen({ onComplete }: Props) {
  const [progress, setProgress] = useState(0);
  const [visibleLines, setVisibleLines] = useState<number[]>([]);
  const [done, setDone] = useState(false);
  const [fadeOut, setFadeOut] = useState(false);

  useEffect(() => {
    // Progress bar — smooth fill over 1.6s
    const start = Date.now();
    const total = 1600;
    const raf = () => {
      const elapsed = Date.now() - start;
      const pct = Math.min(100, (elapsed / total) * 100);
      setProgress(pct);
      if (pct < 100) requestAnimationFrame(raf);
      else {
        setTimeout(() => {
          setDone(true);
          setTimeout(() => {
            setFadeOut(true);
            setTimeout(onComplete, 500);
          }, 400);
        }, 200);
      }
    };
    requestAnimationFrame(raf);

    // Boot lines — staggered reveal
    BOOT_LINES.forEach((line, i) => {
      setTimeout(() => setVisibleLines(prev => [...prev, i]), line.delay + 100);
    });
  }, []);

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9999,
      background: "#000000",
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      fontFamily: "'Orbitron', monospace",
      transition: "opacity 0.5s ease",
      opacity: fadeOut ? 0 : 1,
    }}>
      {/* Grid background */}
      <div style={{
        position: "absolute", inset: 0,
        backgroundImage: "linear-gradient(rgba(232,0,26,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(232,0,26,0.06) 1px, transparent 1px)",
        backgroundSize: "60px 60px",
        pointerEvents: "none",
      }}/>

      {/* Scan line effect */}
      <div style={{
        position: "absolute", left: 0, right: 0, height: "2px",
        background: "linear-gradient(90deg, transparent 0%, rgba(232,0,26,0.7) 50%, transparent 100%)",
        animation: "scan-line 2s linear infinite",
        pointerEvents: "none",
      }}/>

      {/* Corner decorations */}
      {[
        { top:20, left:20, borderStyle:"20px 0 0 20px" },
        { top:20, right:20, borderStyle:"20px 20px 0 0" },
        { bottom:20, left:20, borderStyle:"0 0 20px 20px" },
        { bottom:20, right:20, borderStyle:"0 20px 20px 0" },
      ].map((s, i) => (
        <div key={i} style={{
          position: "absolute", width: 60, height: 60,
          ...(s.top !== undefined ? { top: s.top } : { bottom: s.bottom }),
          ...(s.left !== undefined ? { left: s.left } : { right: s.right }),
          border: "2px solid rgba(232,0,26,0.4)",
          borderRadius: s.borderStyle === "20px 0 0 20px" ? "12px 0 0 0" :
                        s.borderStyle === "20px 20px 0 0" ? "0 12px 0 0" :
                        s.borderStyle === "0 0 20px 20px" ? "0 0 0 12px" : "0 0 12px 0",
          // Only show 2 sides
          ...(i === 0 ? { borderRight:"none", borderBottom:"none" } :
              i === 1 ? { borderLeft:"none", borderBottom:"none" } :
              i === 2 ? { borderRight:"none", borderTop:"none" } :
                        { borderLeft:"none", borderTop:"none" }),
        }}/>
      ))}

      {/* Main content */}
      <div style={{
        display: "flex", flexDirection: "column", alignItems: "center",
        gap: 32, position: "relative", zIndex: 1,
        animation: "fadeIn 0.4s ease",
      }}>
        {/* Logo with ring animation */}
        <div style={{ position: "relative", display: "flex", alignItems: "center", justifyContent: "center" }}>
          {/* Rotating outer ring */}
          <svg width="260" height="260" style={{ position: "absolute", animation: "spin 12s linear infinite", opacity: 0.25 }}>
            <circle cx="130" cy="130" r="124" stroke="#e8001a" strokeWidth="1" fill="none" strokeDasharray="8 5"/>
          </svg>
          {/* Counter-rotating middle ring */}
          <svg width="220" height="220" style={{ position: "absolute", animation: "spin 8s linear infinite reverse", opacity: 0.35 }}>
            <circle cx="110" cy="110" r="104" stroke="#e8001a" strokeWidth="1.5" fill="none" strokeDasharray="4 8"/>
          </svg>
          {/* Static glow ring */}
          <div style={{
            position: "absolute", width: 190, height: 190, borderRadius: "50%",
            background: "radial-gradient(circle, rgba(232,0,26,0.15) 0%, transparent 70%)",
            animation: "pulse-red 2s infinite",
          }}/>
          <RufusLogoLarge size={160}/>
        </div>

        {/* Title */}
        <div style={{ textAlign: "center" }}>
          <div style={{
            fontSize: 32, fontWeight: 900, letterSpacing: 8,
            color: "#ffffff",
            textShadow: "0 0 20px rgba(232,0,26,0.8), 0 0 40px rgba(232,0,26,0.4)",
            animation: "neon-pulse 2s infinite",
            position: "relative",
          }}>
            RUFUS
            {/* Glitch layers */}
            <span style={{ position:"absolute", left:0, top:0, color:"#ff0033", animation:"glitch1 3s infinite", clipPath:"inset(0 0 50% 0)" }}>RUFUS</span>
            <span style={{ position:"absolute", left:0, top:0, color:"#0066ff", animation:"glitch2 3s infinite 0.1s", clipPath:"inset(50% 0 0 0)" }}>RUFUS</span>
          </div>
          <div style={{
            fontSize: 10, letterSpacing: 6, color: "rgba(232,0,26,0.8)",
            marginTop: 6, fontWeight: 600,
          }}>
            FRAMEWORK // RECON SUITE v4.0
          </div>
        </div>

        {/* Boot terminal */}
        <div style={{
          width: 440, background: "rgba(0,0,0,0.6)",
          border: "1px solid rgba(232,0,26,0.2)",
          borderRadius: 8, padding: "14px 16px",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, lineHeight: 1.8,
          minHeight: 180,
        }}>
          {BOOT_LINES.map((line, i) => (
            visibleLines.includes(i) ? (
              <div key={i} style={{
                color: line.color,
                animation: "fadeIn 0.15s ease",
                display: "flex", alignItems: "center", gap: 10,
              }}>
                <span style={{ color: "rgba(232,0,26,0.5)", flexShrink: 0 }}>›</span>
                {line.text}
                {i === BOOT_LINES.length - 1 && !done && (
                  <span style={{ animation: "blink 1s infinite", color: "#e8001a" }}>█</span>
                )}
                {i === BOOT_LINES.length - 1 && done && (
                  <span style={{ color: "#00ff88", animation: "fadeIn 0.2s ease" }}> OK</span>
                )}
              </div>
            ) : null
          ))}
        </div>

        {/* Progress bar */}
        <div style={{ width: 440 }}>
          <div style={{
            display: "flex", justifyContent: "space-between",
            marginBottom: 8, fontSize: 10, color: "rgba(255,255,255,0.4)",
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            <span>LOADING MODULES</span>
            <span style={{ color: progress >= 100 ? "#00ff88" : "#e8001a" }}>
              {Math.round(progress)}%
            </span>
          </div>
          <div style={{
            height: 4, background: "rgba(232,0,26,0.12)",
            borderRadius: 3, overflow: "hidden",
            border: "1px solid rgba(232,0,26,0.2)",
          }}>
            <div className="progress-bar-fill" style={{ width: `${progress}%` }}/>
          </div>
          {/* Block-style secondary progress */}
          <div style={{ display: "flex", gap: 3, marginTop: 8 }}>
            {Array.from({ length: 20 }).map((_, i) => (
              <div key={i} style={{
                flex: 1, height: 3, borderRadius: 2,
                background: i < (progress / 5) ? "#e8001a" : "rgba(232,0,26,0.1)",
                boxShadow: i < (progress / 5) ? "0 0 4px rgba(232,0,26,0.5)" : "none",
                transition: "all 0.1s ease",
              }}/>
            ))}
          </div>
        </div>

        {/* Bottom warning */}
        <div style={{
          fontSize: 9, color: "rgba(232,0,26,0.45)", letterSpacing: 2,
          textAlign: "center", fontFamily: "'Orbitron', monospace",
        }}>
          FOR AUTHORIZED PENETRATION TESTING ONLY
        </div>
      </div>
    </div>
  );
}
