// src/components/SplashScreen.tsx
// Doxbin-inspired loading splash: pure black, red glitch, animated progress
import React, { useState, useEffect } from "react";

interface Props { onComplete: () => void; }

const BOOT_LINES = [
  "INITIALISING CORE MODULES...",
  "LOADING SCAN ENGINE...",
  "MOUNTING FILESYSTEM STORE...",
  "CHECKING TOOL AVAILABILITY...",
  "DECRYPTING CONFIGURATION...",
  "BUILDING SCOPE ENGINE...",
  "LOADING PARSER REGISTRY...",
  "ARMED AND READY.",
];

export function SplashScreen({ onComplete }: Props) {
  const [progress, setProgress] = useState(0);
  const [lines, setLines]       = useState<string[]>([]);
  const [glitch, setGlitch]     = useState(false);
  const [done, setDone]         = useState(false);
  const [fadeOut, setFadeOut]   = useState(false);

  useEffect(() => {
    let lineIdx = 0;
    let pct = 0;

    const addLine = () => {
      if (lineIdx < BOOT_LINES.length) {
        setLines(prev => [...prev, BOOT_LINES[lineIdx]]);
        lineIdx++;
        const targetPct = Math.round((lineIdx / BOOT_LINES.length) * 100);
        animatePct(pct, targetPct);
        pct = targetPct;

        if (lineIdx < BOOT_LINES.length) {
          setTimeout(addLine, 180 + Math.random() * 220);
        } else {
          setTimeout(() => {
            setDone(true);
            setGlitch(true);
            setTimeout(() => setGlitch(false), 200);
            setTimeout(() => setFadeOut(true), 800);
            setTimeout(onComplete, 1200);
          }, 400);
        }
      }
    };

    const animatePct = (from: number, to: number) => {
      const step = () => {
        setProgress(p => {
          if (p >= to) return to;
          return Math.min(p + 2, to);
        });
      };
      const id = setInterval(() => {
        setProgress(p => {
          if (p >= to) { clearInterval(id); return to; }
          return p + 1;
        });
      }, 12);
    };

    setTimeout(addLine, 300);
  }, []);

  return (
    <div style={{
      position: "fixed", inset: 0,
      background: "#000000",
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      fontFamily: "'JetBrains Mono', 'Courier New', monospace",
      zIndex: 9999,
      opacity: fadeOut ? 0 : 1,
      transition: "opacity 0.4s ease",
      overflow: "hidden",
    }}>
      {/* Scanline overlay */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(232,0,26,0.03) 2px, rgba(232,0,26,0.03) 4px)",
        zIndex: 1,
      }}/>

      {/* Vignette */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        background: "radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.8) 100%)",
        zIndex: 2,
      }}/>

      <div style={{ position: "relative", zIndex: 3, width: "100%", maxWidth: 520, padding: "0 40px" }}>

        {/* Logo */}
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 48 }}>
          <SplashLogo glitch={glitch}/>
          <div style={{
            marginTop: 20,
            fontSize: 28, fontWeight: 900,
            letterSpacing: 12,
            color: "#ffffff",
            textTransform: "uppercase",
            fontFamily: "'Orbitron', monospace",
            filter: glitch ? "blur(2px)" : "none",
            transition: "filter 0.1s",
          }}>
            RUFUS
          </div>
          <div style={{
            fontSize: 10, letterSpacing: 8, color: "#e8001a",
            marginTop: 6, textTransform: "uppercase",
            fontFamily: "'Orbitron', monospace",
            opacity: 0.8,
          }}>
            FRAMEWORK
          </div>
        </div>

        {/* Boot log */}
        <div style={{
          marginBottom: 28,
          minHeight: 140,
          display: "flex", flexDirection: "column", justifyContent: "flex-end",
          gap: 4,
        }}>
          {lines.map((line, i) => (
            <div key={i} style={{
              fontSize: 11, color: i === lines.length - 1 ? "#ffffff" : "rgba(255,255,255,0.35)",
              letterSpacing: 1,
              display: "flex", gap: 8, alignItems: "center",
              animation: "fadeIn 0.15s ease",
            }}>
              <span style={{ color: "#e8001a", flexShrink: 0 }}>›</span>
              {line}
              {i === lines.length - 1 && !done && (
                <span style={{ color: "#e8001a", animation: "blink 0.8s infinite" }}>_</span>
              )}
            </div>
          ))}
        </div>

        {/* Progress bar */}
        <div>
          <div style={{
            display: "flex", justifyContent: "space-between", marginBottom: 8,
            fontSize: 10, color: "rgba(255,255,255,0.3)", letterSpacing: 2,
          }}>
            <span>LOADING</span>
            <span style={{ color: progress === 100 ? "#e8001a" : "rgba(255,255,255,0.5)", fontWeight: 700 }}>
              {progress}%
            </span>
          </div>

          {/* Track */}
          <div style={{
            width: "100%", height: 3,
            background: "rgba(255,255,255,0.06)",
            borderRadius: 2, overflow: "hidden",
            position: "relative",
          }}>
            {/* Fill */}
            <div style={{
              height: "100%",
              width: `${progress}%`,
              background: "linear-gradient(90deg, #8b0010, #e8001a, #ff3355)",
              borderRadius: 2,
              transition: "width 0.08s linear",
              boxShadow: "0 0 12px rgba(232,0,26,0.8), 0 0 4px rgba(232,0,26,1)",
              position: "relative",
            }}>
              {/* Leading glow */}
              <div style={{
                position: "absolute", right: 0, top: -4, bottom: -4,
                width: 20,
                background: "radial-gradient(ellipse at right, rgba(255,50,80,0.9) 0%, transparent 70%)",
              }}/>
            </div>
          </div>

          {/* Segment markers */}
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
            {Array.from({length: 8}).map((_,i) => (
              <div key={i} style={{
                width: 1, height: 4,
                background: progress > (i+1)*12.5 ? "rgba(232,0,26,0.6)" : "rgba(255,255,255,0.1)",
                transition: "background 0.3s",
              }}/>
            ))}
          </div>
        </div>

        {done && (
          <div style={{
            textAlign: "center", marginTop: 24,
            fontSize: 11, color: "#e8001a", letterSpacing: 3,
            animation: "fadeIn 0.3s ease",
          }}>
            ▶ SYSTEM READY
          </div>
        )}
      </div>

      {/* Bottom version */}
      <div style={{
        position: "absolute", bottom: 24, right: 32,
        fontSize: 9, color: "rgba(255,255,255,0.15)",
        letterSpacing: 3, fontFamily: "'Orbitron', monospace",
        zIndex: 3,
      }}>
        v4.0 // ALPHA
      </div>

      <style>{`
        @keyframes fadeIn { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:translateY(0); } }
        @keyframes blink  { 0%,100% { opacity:1; } 50% { opacity:0; } }
        @keyframes glitch-h {
          0%   { clip-path: inset(10% 0 80% 0); transform: translate(-4px, 0); }
          20%  { clip-path: inset(60% 0 20% 0); transform: translate(4px, 0); }
          40%  { clip-path: inset(30% 0 50% 0); transform: translate(-2px, 0); }
          60%  { clip-path: inset(80% 0 5%  0); transform: translate(2px, 0); }
          80%  { clip-path: inset(5%  0 90% 0); transform: translate(-4px, 0); }
          100% { clip-path: inset(50% 0 30% 0); transform: translate(0, 0); }
        }
      `}</style>
    </div>
  );
}

function SplashLogo({ glitch }: { glitch: boolean }) {
  return (
    <div style={{ position: "relative", width: 140, height: 140 }}>
      {/* Glitch layers */}
      {glitch && (
        <>
          <div style={{ position:"absolute", inset:0, animation:"glitch-h 0.15s steps(1) infinite", filter:"hue-rotate(180deg)", opacity:0.7 }}>
            <MainHex/>
          </div>
          <div style={{ position:"absolute", inset:0, animation:"glitch-h 0.15s steps(1) reverse infinite", filter:"hue-rotate(90deg)", opacity:0.5 }}>
            <MainHex/>
          </div>
        </>
      )}
      <MainHex pulse={!glitch}/>
    </div>
  );
}

function MainHex({ pulse = false }: { pulse?: boolean }) {
  return (
    <svg width="140" height="140" viewBox="0 0 120 120" fill="none"
      style={pulse ? { animation:"glow-pulse 2s infinite" } : {}}
      xmlns="http://www.w3.org/2000/svg">
      <defs>
        <filter id="sp-glow">
          <feGaussianBlur stdDeviation="3" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <filter id="sp-glow2">
          <feGaussianBlur stdDeviation="6" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>

      {/* Outer glow hex */}
      <polygon points="60,4 108,30 108,90 60,116 12,90 12,30"
        fill="none" stroke="#e8001a" strokeWidth="2.5" strokeOpacity="0.9"
        filter="url(#sp-glow2)"/>
      {/* Solid hex */}
      <polygon points="60,4 108,30 108,90 60,116 12,90 12,30"
        fill="rgba(232,0,26,0.06)" stroke="#e8001a" strokeWidth="2" strokeOpacity="1"/>
      {/* Inner hex */}
      <polygon points="60,18 96,39 96,81 60,102 24,81 24,39"
        fill="rgba(232,0,26,0.1)" stroke="#e8001a" strokeWidth="1" strokeOpacity="0.5"/>

      {/* Scan lines */}
      {[40,48,56,64,72,80].map(y => (
        <line key={y} x1="24" y1={y} x2="96" y2={y}
          stroke="#e8001a" strokeWidth="0.5" strokeOpacity="0.2"/>
      ))}

      {/* Crosshairs */}
      <line x1="0" y1="60" x2="12" y2="60" stroke="#e8001a" strokeWidth="3" filter="url(#sp-glow)"/>
      <line x1="108" y1="60" x2="120" y2="60" stroke="#e8001a" strokeWidth="3" filter="url(#sp-glow)"/>
      <line x1="60" y1="0"  x2="60" y2="12"  stroke="#e8001a" strokeWidth="3" filter="url(#sp-glow)"/>
      <line x1="60" y1="108" x2="60" y2="120" stroke="#e8001a" strokeWidth="3" filter="url(#sp-glow)"/>

      {/* Reticle ring */}
      <circle cx="60" cy="60" r="20" fill="none"
        stroke="#e8001a" strokeWidth="1.5" strokeOpacity="0.7"
        strokeDasharray="5 3"/>

      {/* Inner fill */}
      <circle cx="60" cy="60" r="14" fill="rgba(232,0,26,0.2)"/>

      {/* R */}
      <text x="60" y="72" textAnchor="middle"
        fontFamily="Orbitron,monospace" fontWeight="900" fontSize="28"
        fill="#ffffff" filter="url(#sp-glow)" letterSpacing="-1">R</text>

      {/* Center dot */}
      <circle cx="60" cy="60" r="3.5" fill="#e8001a" filter="url(#sp-glow)"/>
      <circle cx="60" cy="60" r="1.5" fill="#ffffff"/>

      {/* Corner dots */}
      {[[60,6],[60,114],[6,60],[114,60]].map(([x,y]) => (
        <circle key={`${x}-${y}`} cx={x} cy={y} r="3.5" fill="#e8001a" filter="url(#sp-glow)"/>
      ))}
    </svg>
  );
}
