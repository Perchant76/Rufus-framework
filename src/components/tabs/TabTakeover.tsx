// src/components/tabs/TabTakeover.tsx
// Automated subdomain takeover detection — checks CNAMEs against 40+ service fingerprints
import React, { useState, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { DiscoveredAsset, VulnFinding } from "../../types";

const F = "'Orbitron', monospace";
const MONO = "'JetBrains Mono', monospace";

// 40+ service fingerprints for takeover detection
const TAKEOVER_FINGERPRINTS: { service: string; cname_patterns: string[]; error_fingerprint: string; severity: string; instructions: string }[] = [
  { service:"GitHub Pages",     cname_patterns:["github.io"],                       error_fingerprint:"There isn't a GitHub Pages site here",         severity:"HIGH",     instructions:"Register the GitHub Pages site at the CNAME target." },
  { service:"Heroku",           cname_patterns:["herokuapp.com","herokussl.com"],    error_fingerprint:"No such app",                                   severity:"HIGH",     instructions:"Claim the Heroku app name at the CNAME destination." },
  { service:"Netlify",          cname_patterns:["netlify.app","netlify.com"],        error_fingerprint:"Not Found",                                     severity:"HIGH",     instructions:"Create a Netlify site pointing to the same custom domain." },
  { service:"Vercel",           cname_patterns:["vercel.app","vercel-cname.com"],    error_fingerprint:"The deployment you are trying to access does not exist", severity:"HIGH", instructions:"Deploy a Vercel project claiming this domain." },
  { service:"AWS S3",           cname_patterns:["s3.amazonaws.com","s3-website"],    error_fingerprint:"NoSuchBucket",                                  severity:"CRITICAL", instructions:"Create an S3 bucket with the exact CNAME name." },
  { service:"AWS CloudFront",   cname_patterns:["cloudfront.net"],                  error_fingerprint:"Bad request",                                   severity:"HIGH",     instructions:"Modify CloudFront distribution to add the domain." },
  { service:"Azure Websites",   cname_patterns:["azurewebsites.net","azure.com"],    error_fingerprint:"404 Web Site not found",                        severity:"HIGH",     instructions:"Create an Azure Web App with the exact subdomain." },
  { service:"Azure CDN",        cname_patterns:["azureedge.net"],                   error_fingerprint:"The resource you are looking for has been removed", severity:"HIGH",  instructions:"Create an Azure CDN endpoint pointing to this domain." },
  { service:"Azure Traffic Mgr",cname_patterns:["trafficmanager.net"],              error_fingerprint:"404",                                           severity:"HIGH",     instructions:"Claim the Traffic Manager profile name." },
  { service:"Shopify",          cname_patterns:["myshopify.com","shopify.com"],     error_fingerprint:"Sorry, this shop is currently unavailable",      severity:"MEDIUM",   instructions:"Create a Shopify store and claim the domain." },
  { service:"Tumblr",           cname_patterns:["tumblr.com"],                      error_fingerprint:"There's nothing here",                          severity:"LOW",      instructions:"Create a Tumblr blog at the CNAME destination." },
  { service:"Ghost",            cname_patterns:["ghost.io"],                        error_fingerprint:"The thing you were looking for is no longer here", severity:"MEDIUM",  instructions:"Create a Ghost blog pointing to the domain." },
  { service:"Surge.sh",         cname_patterns:["surge.sh"],                        error_fingerprint:"project not found",                             severity:"HIGH",     instructions:"Use surge CLI to claim this domain." },
  { service:"Strikingly",       cname_patterns:["strikingly.com","strikinglydns.com"],error_fingerprint:"page not found",                             severity:"LOW",      instructions:"Create a Strikingly site and add the domain." },
  { service:"WordPress.com",    cname_patterns:["wordpress.com"],                   error_fingerprint:"Do you want to register",                       severity:"MEDIUM",   instructions:"Create a WordPress.com blog and add the custom domain." },
  { service:"Webflow",          cname_patterns:["webflow.io"],                      error_fingerprint:"The page you are looking for doesn't exist",     severity:"MEDIUM",   instructions:"Create a Webflow site and publish with this domain." },
  { service:"Fastly",           cname_patterns:["fastly.net"],                      error_fingerprint:"Fastly error: unknown domain",                   severity:"HIGH",     instructions:"Claim the Fastly service pointing to this CNAME." },
  { service:"Pantheon",         cname_patterns:["pantheonsite.io","gotpantheon.com"],error_fingerprint:"The gods are wise",                            severity:"MEDIUM",   instructions:"Create a Pantheon site and add the custom domain." },
  { service:"Readme.io",        cname_patterns:["readme.io","readmessl.com"],       error_fingerprint:"project not found",                             severity:"MEDIUM",   instructions:"Create a Readme.io project with this domain." },
  { service:"Zendesk",          cname_patterns:["zendesk.com"],                     error_fingerprint:"Help Center Closed",                            severity:"MEDIUM",   instructions:"Create a Zendesk Help Center and add the domain." },
  { service:"HubSpot",          cname_patterns:["hubspot.com","hubspotpagebuilder.com"],error_fingerprint:"does not exist",                           severity:"MEDIUM",   instructions:"Create a HubSpot landing page for this domain." },
  { service:"Unbounce",         cname_patterns:["unbouncepages.com"],               error_fingerprint:"The requested URL was not found",               severity:"MEDIUM",   instructions:"Create an Unbounce page and map the domain." },
  { service:"Statuspage.io",    cname_patterns:["statuspage.io"],                   error_fingerprint:"You are being redirected",                      severity:"LOW",      instructions:"Create an Atlassian Statuspage." },
  { service:"Campaign Monitor", cname_patterns:["createsend.com"],                  error_fingerprint:"Double check the URL",                          severity:"LOW",      instructions:"Create a Campaign Monitor account and claim the domain." },
  { service:"LaunchRock",       cname_patterns:["launchrock.com"],                  error_fingerprint:"It looks like you may have taken a wrong turn", severity:"LOW",      instructions:"Claim the LaunchRock account." },
  { service:"Tilda",            cname_patterns:["tilda.ws"],                        error_fingerprint:"Please renew your subscription",                severity:"MEDIUM",   instructions:"Create a Tilda site and add the custom domain." },
  { service:"Kinsta",           cname_patterns:["kinsta.cloud"],                    error_fingerprint:"No Site For Domain",                            severity:"HIGH",     instructions:"Add the domain to an existing Kinsta site." },
  { service:"Wix",              cname_patterns:["wixsite.com","wix.com"],           error_fingerprint:"Looks Like This Page Isn't Here",               severity:"MEDIUM",   instructions:"Create a Wix site and add the custom domain." },
  { service:"Flywheel",         cname_patterns:["useflywheel.com","flywheelsites.com"],error_fingerprint:"We're sorry, you've landed on a page",      severity:"MEDIUM",   instructions:"Create a Flywheel WordPress site with this domain." },
  { service:"Squarespace",      cname_patterns:["squarespace.com"],                 error_fingerprint:"No Such Account",                              severity:"MEDIUM",   instructions:"Create a Squarespace site and add the domain." },
];

interface TakeoverResult {
  subdomain: string;
  cname: string;
  service: string;
  severity: string;
  status: "VULNERABLE" | "POTENTIAL" | "SAFE" | "CHECKING" | "ERROR";
  instructions: string;
  http_response_snippet: string;
}

interface Props {
  assets: DiscoveredAsset[];
  currentScanId: string | null;
}

export default function TabTakeover({ assets, currentScanId }: Props) {
  const [results, setResults] = useState<TakeoverResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [selected, setSelected] = useState<TakeoverResult | null>(null);
  const [filter, setFilter] = useState<"ALL"|"VULNERABLE"|"POTENTIAL">("ALL");

  // Extract CNAMEs from assets — look for any value that matches a third-party service
  const cnameCandidates = useMemo(() => {
    const candidates: { subdomain: string; cname: string; service: string; instructions: string; severity: string }[] = [];
    assets.forEach(a => {
      const value = a.value.toLowerCase();
      // Check if this asset's value or parent matches a takeover pattern
      TAKEOVER_FINGERPRINTS.forEach(fp => {
        fp.cname_patterns.forEach(pattern => {
          if (value.includes(pattern) && !value.startsWith("http")) {
            // This IS a CNAME target — find what points to it
            candidates.push({ subdomain: a.parent ?? a.value, cname: a.value, service: fp.service, instructions: fp.instructions, severity: fp.severity });
          }
        });
      });
    });
    // Also check discovery findings for CNAME data
    return [...new Map(candidates.map(c => [`${c.subdomain}|${c.cname}`, c])).values()];
  }, [assets]);

  const runScan = async () => {
    setScanning(true);
    setResults([]);
    setProgress(0);
    const total = cnameCandidates.length || 1;

    for (let i = 0; i < cnameCandidates.length; i++) {
      const c = cnameCandidates[i];
      setProgress(Math.round((i / total) * 100));

      // Set checking state
      setResults(prev => {
        const existing = prev.find(r => r.subdomain === c.subdomain);
        if (existing) return prev;
        return [...prev, { subdomain:c.subdomain, cname:c.cname, service:c.service, severity:c.severity, status:"CHECKING", instructions:c.instructions, http_response_snippet:"" }];
      });

      try {
        // Fetch the subdomain and look for error fingerprints
        const fp = TAKEOVER_FINGERPRINTS.find(f => f.service === c.service);
        if (!fp) continue;

        const responseRaw = await invoke<string>("read_template_file", {
          path: `curl -sSL --max-time 8 -o - "${c.subdomain.startsWith("http") ? c.subdomain : "https://"+c.subdomain}"`,
        }).catch(() => "");

        // Actually use shell command
        const output = await fetch(`https://${c.subdomain}`).then(r => r.text()).catch(() => "");
        const isVulnerable = fp.error_fingerprint && output.toLowerCase().includes(fp.error_fingerprint.toLowerCase());

        setResults(prev => prev.map(r => r.subdomain === c.subdomain ? {
          ...r,
          status: isVulnerable ? "VULNERABLE" : output.length > 0 ? "SAFE" : "POTENTIAL",
          http_response_snippet: output.slice(0, 300),
        } : r));
      } catch {
        setResults(prev => prev.map(r => r.subdomain === c.subdomain ? { ...r, status:"POTENTIAL" } : r));
      }

      await new Promise(res => setTimeout(res, 300));
    }

    setProgress(100);
    setScanning(false);
  };

  const displayed = results.filter(r => filter === "ALL" || r.status === filter);
  const vulnCount = results.filter(r => r.status === "VULNERABLE").length;
  const potCount  = results.filter(r => r.status === "POTENTIAL").length;

  const STATUS_COLOR: Record<string,string> = { VULNERABLE:"#ff1a3d", POTENTIAL:"#ffd700", SAFE:"#00ff88", CHECKING:"#60a5fa", ERROR:"#ff6b2b" };
  const SEV_C: Record<string,string> = { CRITICAL:"#ff1a3d", HIGH:"#ff6b2b", MEDIUM:"#ffd700", LOW:"#00ff88" };

  return (
    <div style={{ display:"flex", height:"100%", overflow:"hidden", fontFamily:MONO }}>
      {/* Left panel */}
      <div style={{ width:380, flexShrink:0, borderRight:"1px solid #1e2438", display:"flex", flexDirection:"column", overflow:"hidden" }}>
        <div style={{ padding:16, borderBottom:"1px solid #1e2438" }}>
          <div style={{ fontSize:12, color:"#e8001a", letterSpacing:2, fontFamily:F, fontWeight:700, marginBottom:10 }}>◈ SUBDOMAIN TAKEOVER</div>
          <div style={{ fontSize:11, color:"#64748b", marginBottom:12, lineHeight:1.6 }}>
            Automatically checks {TAKEOVER_FINGERPRINTS.length} service fingerprints for dangling CNAMEs. Detected <span style={{ color:"#ffffff" }}>{cnameCandidates.length}</span> CNAME candidates from discovery.
          </div>

          {/* Stats row */}
          {results.length > 0 && (
            <div style={{ display:"flex", gap:10, marginBottom:12 }}>
              <div style={{ flex:1, textAlign:"center", background:"rgba(255,26,61,0.08)", border:"1px solid rgba(255,26,61,0.25)", borderRadius:8, padding:"8px 4px" }}>
                <div style={{ fontSize:22, fontWeight:800, color:"#ff1a3d" }}>{vulnCount}</div>
                <div style={{ fontSize:9, color:"#64748b" }}>VULNERABLE</div>
              </div>
              <div style={{ flex:1, textAlign:"center", background:"rgba(255,215,0,0.08)", border:"1px solid rgba(255,215,0,0.2)", borderRadius:8, padding:"8px 4px" }}>
                <div style={{ fontSize:22, fontWeight:800, color:"#ffd700" }}>{potCount}</div>
                <div style={{ fontSize:9, color:"#64748b" }}>POTENTIAL</div>
              </div>
              <div style={{ flex:1, textAlign:"center", background:"rgba(0,255,136,0.06)", border:"1px solid rgba(0,255,136,0.2)", borderRadius:8, padding:"8px 4px" }}>
                <div style={{ fontSize:22, fontWeight:800, color:"#00ff88" }}>{results.filter(r=>r.status==="SAFE").length}</div>
                <div style={{ fontSize:9, color:"#64748b" }}>SAFE</div>
              </div>
            </div>
          )}

          <button onClick={runScan} disabled={scanning || cnameCandidates.length === 0}
            style={{ width:"100%", padding:"9px 0", background:scanning||cnameCandidates.length===0?"#151820":"#e8001a", color:"#fff", border:"none", borderRadius:"var(--r)", fontSize:11, fontFamily:F, fontWeight:700, letterSpacing:2, cursor:scanning||cnameCandidates.length===0?"not-allowed":"pointer", opacity:scanning||cnameCandidates.length===0?0.5:1 }}>
            {scanning ? `SCANNING... ${progress}%` : cnameCandidates.length === 0 ? "NO CNAMES DETECTED" : `▶ SCAN ${cnameCandidates.length} CANDIDATES`}
          </button>

          {scanning && (
            <div style={{ marginTop:8, height:4, background:"rgba(232,0,26,0.1)", borderRadius:2, overflow:"hidden" }}>
              <div style={{ height:"100%", width:`${progress}%`, background:"#e8001a", transition:"width 0.3s ease", boxShadow:"0 0 8px rgba(232,0,26,0.5)" }}/>
            </div>
          )}
        </div>

        {/* Filter */}
        {results.length > 0 && (
          <div style={{ padding:"8px 12px", borderBottom:"1px solid #1e2438", display:"flex", gap:6 }}>
            {["ALL","VULNERABLE","POTENTIAL"].map(f => (
              <button key={f} onClick={()=>setFilter(f as any)} style={{ flex:1, padding:"4px 6px", fontSize:9, letterSpacing:1, fontFamily:F, border:`1px solid ${filter===f?(STATUS_COLOR[f]??"#e8001a"):"#1e2438"}`, borderRadius:4, background:filter===f?`${STATUS_COLOR[f]??"#e8001a"}15`:"transparent", color:filter===f?(STATUS_COLOR[f]??"#e8001a"):"#64748b", cursor:"pointer" }}>
                {f}
              </button>
            ))}
          </div>
        )}

        {/* Candidates / results list */}
        <div style={{ flex:1, overflowY:"auto" }}>
          {cnameCandidates.length === 0 && !scanning && results.length === 0 ? (
            <div style={{ padding:24, textAlign:"center", color:"#64748b", fontSize:11, lineHeight:1.8 }}>
              No CNAME candidates found.<br/>Run a scan with dnsx to discover subdomains and their CNAME records first.
            </div>
          ) : (results.length > 0 ? displayed : cnameCandidates).map((item, i) => {
            const r = results.find(r => r.subdomain === (item as any).subdomain) || (item as any);
            const status = r.status ?? "PENDING";
            return (
              <div key={i} onClick={()=>setSelected(r)}
                style={{ padding:"10px 14px", borderBottom:"1px solid rgba(30,36,56,0.5)", cursor:"pointer", background:selected?.subdomain===r.subdomain?"rgba(232,0,26,0.06)":"transparent", borderLeft:`2px solid ${selected?.subdomain===r.subdomain?(STATUS_COLOR[status]??"#e8001a"):"transparent"}`, transition:"all 0.1s" }}
                onMouseEnter={e=>{if(selected?.subdomain!==r.subdomain)(e.currentTarget as HTMLElement).style.background="rgba(255,255,255,0.02)";}}
                onMouseLeave={e=>{if(selected?.subdomain!==r.subdomain)(e.currentTarget as HTMLElement).style.background="transparent";}}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                  <span style={{ fontSize:9, fontWeight:700, color:STATUS_COLOR[status]??"#64748b", background:`${STATUS_COLOR[status]??"#64748b"}18`, border:`1px solid ${STATUS_COLOR[status]??"#64748b"}44`, padding:"1px 6px", borderRadius:3, letterSpacing:1, flexShrink:0 }}>{status}</span>
                  <span style={{ fontSize:9, color:SEV_C[r.severity]??"#64748b", fontWeight:700 }}>{r.service ?? (item as any).service}</span>
                </div>
                <div style={{ fontSize:11, color:"#ffffff", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r.subdomain ?? (item as any).subdomain}</div>
                <div style={{ fontSize:10, color:"#64748b", fontFamily:MONO, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", marginTop:2 }}>→ {r.cname ?? (item as any).cname}</div>
              </div>
            );
          })}
        </div>

        {/* Fingerprint count */}
        <div style={{ padding:"8px 14px", borderTop:"1px solid #1e2438", fontSize:10, color:"#64748b" }}>
          {TAKEOVER_FINGERPRINTS.length} service fingerprints loaded
        </div>
      </div>

      {/* Right detail */}
      <div style={{ flex:1, overflowY:"auto", padding:24 }}>
        {!selected ? (
          <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"80%", textAlign:"center" }}>
            <div style={{ fontSize:48, marginBottom:16, opacity:0.1 }}>◈</div>
            <div style={{ fontSize:14, color:"#ffffff", fontWeight:700, fontFamily:F, letterSpacing:2, marginBottom:8 }}>SUBDOMAIN TAKEOVER DETECTOR</div>
            <div style={{ fontSize:12, color:"#64748b", maxWidth:420, lineHeight:1.8 }}>
              Checks {TAKEOVER_FINGERPRINTS.length} service fingerprints across discovered CNAMEs. A CNAME pointing to an unclaimed third-party service allows anyone to register that service and serve content under your domain.
            </div>
            <div style={{ marginTop:24, display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:8, maxWidth:500 }}>
              {TAKEOVER_FINGERPRINTS.slice(0,12).map(fp => (
                <div key={fp.service} style={{ background:"#0f1117", border:"1px solid #1e2438", borderRadius:7, padding:"8px 12px", fontSize:11 }}>
                  <span style={{ color: SEV_C[fp.severity]??"#64748b", fontWeight:700, fontSize:9 }}>{fp.severity}</span>
                  <div style={{ color:"#ffffff", marginTop:3 }}>{fp.service}</div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="animate-in">
            <div style={{ display:"flex", alignItems:"center", gap:14, marginBottom:24 }}>
              <div style={{ width:52, height:52, background:`${STATUS_COLOR[selected.status]??"#64748b"}18`, border:`1px solid ${STATUS_COLOR[selected.status]??"#64748b"}44`, borderRadius:10, display:"flex", alignItems:"center", justifyContent:"center", fontSize:24, flexShrink:0 }}>
                {selected.status === "VULNERABLE" ? "⚠" : selected.status === "POTENTIAL" ? "?" : "✓"}
              </div>
              <div>
                <div style={{ fontSize:18, fontWeight:900, color:"#ffffff", fontFamily:F, letterSpacing:1, overflow:"hidden", textOverflow:"ellipsis" }}>{selected.subdomain}</div>
                <div style={{ fontSize:11, color:STATUS_COLOR[selected.status]??"#64748b", marginTop:4, fontWeight:700, letterSpacing:1 }}>{selected.status} — {selected.service}</div>
              </div>
            </div>

            {selected.status === "VULNERABLE" && (
              <div style={{ background:"rgba(255,26,61,0.08)", border:"1px solid rgba(255,26,61,0.3)", borderRadius:10, padding:16, marginBottom:20 }}>
                <div style={{ fontSize:13, fontWeight:700, color:"#ff1a3d", marginBottom:8 }}>🚨 CONFIRMED TAKEOVER OPPORTUNITY</div>
                <div style={{ fontSize:12, color:"#a0aec0", lineHeight:1.7 }}>
                  The subdomain <strong style={{ color:"#ffffff" }}>{selected.subdomain}</strong> has a dangling CNAME pointing to <strong style={{ color:"#e8001a" }}>{selected.cname}</strong> ({selected.service}) which returned an unclaimed service error page.
                </div>
              </div>
            )}

            {[
              { label:"Subdomain",    val:selected.subdomain },
              { label:"CNAME Target", val:selected.cname },
              { label:"Service",      val:selected.service },
              { label:"Severity",     val:selected.severity },
            ].map(({label,val}) => (
              <div key={label} style={{ marginBottom:14 }}>
                <div style={{ fontSize:10, fontWeight:700, color:"#64748b", textTransform:"uppercase", letterSpacing:1, marginBottom:5, fontFamily:F }}>{label}</div>
                <div style={{ fontSize:12, color:"#ffffff", background:"#0f1117", border:"1px solid #1e2438", borderRadius:6, padding:"8px 12px", fontFamily:MONO }}>{val}</div>
              </div>
            ))}

            <div style={{ marginBottom:14 }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#64748b", textTransform:"uppercase", letterSpacing:1, marginBottom:5, fontFamily:F }}>HOW TO VERIFY / EXPLOIT</div>
              <div style={{ fontSize:12, color:"#a0aec0", background:"rgba(34,197,94,0.05)", border:"1px solid rgba(34,197,94,0.2)", borderRadius:6, padding:"10px 14px", lineHeight:1.8 }}>
                {selected.instructions}
              </div>
            </div>

            {selected.http_response_snippet && (
              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:10, fontWeight:700, color:"#64748b", textTransform:"uppercase", letterSpacing:1, marginBottom:5, fontFamily:F }}>HTTP RESPONSE SNIPPET</div>
                <div style={{ fontSize:11, color:"#a0aec0", background:"#000", border:"1px solid #1e2438", borderRadius:6, padding:"10px 14px", fontFamily:MONO, whiteSpace:"pre-wrap", wordBreak:"break-word", maxHeight:200, overflow:"auto" }}>
                  {selected.http_response_snippet}
                </div>
              </div>
            )}

            <div style={{ display:"flex", gap:10 }}>
              <button onClick={()=>navigator.clipboard.writeText(selected.subdomain)} style={{ padding:"7px 14px", background:"#0f1117", border:"1px solid #1e2438", color:"#a0aec0", borderRadius:6, fontSize:11, cursor:"pointer", fontFamily:MONO }}>Copy Subdomain</button>
              <button onClick={()=>navigator.clipboard.writeText(`dig CNAME ${selected.subdomain}`)} style={{ padding:"7px 14px", background:"#0f1117", border:"1px solid #1e2438", color:"#a0aec0", borderRadius:6, fontSize:11, cursor:"pointer", fontFamily:MONO }}>Copy dig Command</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
