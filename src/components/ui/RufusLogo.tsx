// src/components/ui/RufusLogo.tsx — Doxbin-style elite hacker logo
import React from "react";

export function RufusLogo({ size = 36, animate = true }: { size?: number; animate?: boolean }) {
  const id = `r${size}`;
  return (
    <svg width={size} height={size} viewBox="0 0 200 200" fill="none"
      style={{ flexShrink:0, ...(animate ? { filter:"drop-shadow(0 0 8px rgba(232,0,26,0.6))" } : {}) }}
      xmlns="http://www.w3.org/2000/svg">
      <defs>
        <filter id={`glow-${id}`} x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="3" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <filter id={`glow2-${id}`} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="6" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <linearGradient id={`rg-${id}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#ff2244"/>
          <stop offset="50%" stopColor="#e8001a"/>
          <stop offset="100%" stopColor="#8b0010"/>
        </linearGradient>
        <radialGradient id={`core-${id}`} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#e8001a" stopOpacity="0.25"/>
          <stop offset="100%" stopColor="#e8001a" stopOpacity="0"/>
        </radialGradient>
      </defs>

      {/* Background glow disc */}
      <circle cx="100" cy="100" r="90" fill={`url(#core-${id})`}/>

      {/* Outer hex — sharp, thick */}
      <polygon points="100,6 180,50 180,150 100,194 20,150 20,50"
        fill="none" stroke={`url(#rg-${id})`} strokeWidth="2.5" opacity="0.9"
        filter={`url(#glow-${id})`}/>

      {/* Mid hex */}
      <polygon points="100,22 164,60 164,140 100,178 36,140 36,60"
        fill="none" stroke="#e8001a" strokeWidth="1" opacity="0.35"/>

      {/* Inner hex — subtle fill */}
      <polygon points="100,38 148,65 148,135 100,162 52,135 52,65"
        fill="rgba(232,0,26,0.06)" stroke="#e8001a" strokeWidth="0.75" opacity="0.5"/>

      {/* Horizontal scan lines inside inner hex */}
      {[72,82,92,102,112,122,132].map((y,i) => (
        <line key={y} x1="52" y1={y} x2="148" y2={y}
          stroke="#e8001a" strokeWidth="0.5" opacity={0.06 + i*0.015}/>
      ))}

      {/* Diagonal corner ticks on outer hex */}
      <line x1="100" y1="6"   x2="100" y2="20"  stroke="#e8001a" strokeWidth="3" filter={`url(#glow-${id})`}/>
      <line x1="100" y1="180" x2="100" y2="194" stroke="#e8001a" strokeWidth="3" filter={`url(#glow-${id})`}/>
      <line x1="20"  y1="50"  x2="32"  y2="57"  stroke="#e8001a" strokeWidth="3" filter={`url(#glow-${id})`}/>
      <line x1="20"  y1="150" x2="32"  y2="143" stroke="#e8001a" strokeWidth="3" filter={`url(#glow-${id})`}/>
      <line x1="180" y1="50"  x2="168" y2="57"  stroke="#e8001a" strokeWidth="3" filter={`url(#glow-${id})`}/>
      <line x1="180" y1="150" x2="168" y2="143" stroke="#e8001a" strokeWidth="3" filter={`url(#glow-${id})`}/>

      {/* Cardinal crosshair lines — extend beyond hex */}
      <line x1="0"   y1="100" x2="20"  y2="100" stroke="#e8001a" strokeWidth="2" filter={`url(#glow-${id})`}/>
      <line x1="180" y1="100" x2="200" y2="100" stroke="#e8001a" strokeWidth="2" filter={`url(#glow-${id})`}/>

      {/* Targeting reticle */}
      <circle cx="100" cy="100" r="32"
        stroke="#e8001a" strokeWidth="1.5" fill="none" opacity="0.7"
        strokeDasharray="6 4"
        style={animate ? { animation:"spin-slow 12s linear infinite", transformOrigin:"100px 100px" } : {}}/>
      <circle cx="100" cy="100" r="22"
        stroke="#e8001a" strokeWidth="0.75" fill="none" opacity="0.4"/>

      {/* Inner glow fill */}
      <circle cx="100" cy="100" r="20" fill="rgba(232,0,26,0.12)"/>

      {/* Bold R — centred precisely */}
      <text x="100" y="118"
        textAnchor="middle" dominantBaseline="auto"
        fontFamily="Orbitron,monospace" fontWeight="900" fontSize="52"
        fill="#ffffff" filter={`url(#glow-${id})`} letterSpacing="-2">R</text>

      {/* Centre dot */}
      <circle cx="100" cy="100" r="3.5" fill="#e8001a" filter={`url(#glow2-${id})`}/>
      <circle cx="100" cy="100" r="1.5" fill="#fff"/>

      {/* Cardinal endpoint dots */}
      <circle cx="100" cy="6"   r="4" fill="#e8001a" filter={`url(#glow-${id})`}/>
      <circle cx="100" cy="194" r="4" fill="#e8001a" filter={`url(#glow-${id})`}/>
      <circle cx="20"  cy="50"  r="3" fill="#e8001a" opacity="0.7"/>
      <circle cx="20"  cy="150" r="3" fill="#e8001a" opacity="0.7"/>
      <circle cx="180" cy="50"  r="3" fill="#e8001a" opacity="0.7"/>
      <circle cx="180" cy="150" r="3" fill="#e8001a" opacity="0.7"/>

      {/* Corner bracket accents — top-left, top-right, bottom-left, bottom-right */}
      <path d="M8,30 L8,8 L30,8"   stroke="#e8001a" strokeWidth="2" fill="none" opacity="0.5"/>
      <path d="M192,30 L192,8 L170,8" stroke="#e8001a" strokeWidth="2" fill="none" opacity="0.5"/>
      <path d="M8,170 L8,192 L30,192" stroke="#e8001a" strokeWidth="2" fill="none" opacity="0.5"/>
      <path d="M192,170 L192,192 L170,192" stroke="#e8001a" strokeWidth="2" fill="none" opacity="0.5"/>
    </svg>
  );
}

export function RufusLogoLarge({ size = 200 }: { size?: number }) {
  return <RufusLogo size={size} animate={false}/>;
}
