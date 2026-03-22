// src/components/tabs/TabTechStacks.tsx
// Tech stack grouping — pivot discovered assets by technology
import React, { useState, useMemo } from "react";
import type { DiscoveredAsset, VulnFinding } from "../../types";

const F = "'Orbitron', monospace";
const MONO = "'JetBrains Mono', monospace";

// Technology category grouping
const TECH_CATEGORIES: Record<string, string[]> = {
  "CMS":           ["WordPress","Drupal","Joomla","Magento","Shopify","Ghost","Contentful","Strapi","Typo3","Sitecore","Umbraco"],
  "Web Server":    ["Apache","Nginx","IIS","LiteSpeed","Caddy","Apache Tomcat","Jetty","Gunicorn","uWSGI","Kestrel"],
  "Framework":     ["Laravel","Django","Rails","Express","Spring","ASP.NET","Symfony","Flask","FastAPI","Next.js","Nuxt","Angular","React","Vue"],
  "Database":      ["MySQL","PostgreSQL","MongoDB","Redis","Elasticsearch","MariaDB","CouchDB","SQLite","Oracle","MSSQL"],
  "Cloud/CDN":     ["Cloudflare","AWS","Fastly","Akamai","Azure","GCP","CloudFront","Vercel","Netlify"],
  "Language":      ["PHP","Python","Ruby","Java","Node.js",".NET","Go","Rust"],
  "Auth/Identity": ["OAuth","SAML","Okta","Auth0","Keycloak","LDAP","Active Directory"],
  "Security":      ["WAF","ModSecurity","Imperva","F5","Barracuda","Sucuri"],
  "Miscellaneous": [],
};

function getTechCategory(tech: string): string {
  const t = tech.toLowerCase();
  for (const [cat, techs] of Object.entries(TECH_CATEGORIES)) {
    if (cat === "Miscellaneous") continue;
    if (techs.some(x => t.includes(x.toLowerCase()))) return cat;
  }
  return "Miscellaneous";
}

// Known vulnerable versions per technology (simplified fingerprinting)
const VULN_VERSIONS: Record<string, { pattern: RegExp; title: string; severity: string; cve: string }[]> = {
  "apache": [
    { pattern: /2\.4\.(4[0-9]|[0-3][0-9])\b/i, title: "Apache Path Traversal Risk", severity: "HIGH", cve: "CVE-2021-41773/42013" },
    { pattern: /2\.4\.(1[0-9]|[1-9])\b/i, title: "Apache Outdated Version", severity: "MEDIUM", cve: "Multiple CVEs" },
  ],
  "nginx": [
    { pattern: /1\.(1[0-8]|[0-9])\.\d+\b/i, title: "Nginx Outdated Version", severity: "MEDIUM", cve: "Multiple CVEs" },
  ],
  "php": [
    { pattern: /[56]\.\d+\.\d+\b/i, title: "PHP End-of-Life Version", severity: "CRITICAL", cve: "Multiple EOL CVEs" },
    { pattern: /7\.[0-3]\.\d+\b/i,  title: "PHP EOL Version 7.x", severity: "HIGH", cve: "Multiple EOL CVEs" },
  ],
  "wordpress": [
    { pattern: /[1-5]\.\d+\.?\d*\b/i, title: "WordPress Outdated Version", severity: "HIGH", cve: "Multiple CVEs" },
  ],
  "iis": [
    { pattern: /[1-9]\.\d+\b/i, title: "IIS Server Detected", severity: "INFO", cve: "Review version" },
  ],
};

function checkVulnVersion(tech: string): { title: string; severity: string; cve: string } | null {
  for (const [key, checks] of Object.entries(VULN_VERSIONS)) {
    if (tech.toLowerCase().includes(key)) {
      for (const check of checks) {
        if (check.pattern.test(tech)) return { title: check.title, severity: check.severity, cve: check.cve };
      }
    }
  }
  return null;
}

interface Props {
  assets: DiscoveredAsset[];
  findings: VulnFinding[];
  isRunning: boolean;
  onRunNuclei?: (urls: string[], techFilter: string) => void;
}

export default function TabTechStacks({ assets, findings, isRunning, onRunNuclei }: Props) {
  const [selectedTech, setSelectedTech] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<"count"|"name">("count");

  // Build tech → assets map
  const techMap = useMemo(() => {
    const map: Record<string, DiscoveredAsset[]> = {};
    assets.forEach(a => {
      (a.tech_stack ?? []).forEach(tech => {
        if (!tech || tech.length < 2) return;
        const key = tech.trim();
        if (!map[key]) map[key] = [];
        if (!map[key].find(x => x.id === a.id)) map[key].push(a);
      });
    });
    return map;
  }, [assets]);

  const techList = useMemo(() => {
    let list = Object.entries(techMap).map(([tech, items]) => ({
      tech,
      count: items.length,
      category: getTechCategory(tech),
      vuln: checkVulnVersion(tech),
      urls: [...new Set(items.map(a => a.value))],
    }));
    if (categoryFilter !== "ALL") list = list.filter(t => t.category === categoryFilter);
    if (search) list = list.filter(t => t.tech.toLowerCase().includes(search.toLowerCase()));
    list.sort((a,b) => sortBy === "count" ? b.count - a.count : a.tech.localeCompare(b.tech));
    return list;
  }, [techMap, categoryFilter, search, sortBy]);

  const categories = useMemo(() => {
    const cats: Record<string, number> = { ALL: Object.keys(techMap).length };
    Object.keys(techMap).forEach(tech => {
      const cat = getTechCategory(tech);
      cats[cat] = (cats[cat] ?? 0) + 1;
    });
    return cats;
  }, [techMap]);

  const selectedAssets = selectedTech ? (techMap[selectedTech] ?? []) : [];
  const selectedVuln   = selectedTech ? techList.find(t => t.tech === selectedTech)?.vuln : null;

  const SEV_C: Record<string,string> = { CRITICAL:"#ff1a3d",HIGH:"#ff6b2b",MEDIUM:"#ffd700",LOW:"#00ff88",INFO:"#60a5fa" };

  return (
    <div style={{ display:"flex", height:"100%", overflow:"hidden", fontFamily:MONO }}>
      {/* Left panel */}
      <div style={{ width:360, flexShrink:0, borderRight:"1px solid #1e2438", display:"flex", flexDirection:"column", overflow:"hidden" }}>
        <div style={{ padding:16, borderBottom:"1px solid #1e2438" }}>
          <div style={{ fontSize:12, color:"#e8001a", letterSpacing:2, fontFamily:F, fontWeight:700, marginBottom:10 }}>
            ⬡ TECH STACK PIVOT
          </div>
          <div style={{ fontSize:11, color:"#64748b", marginBottom:12, lineHeight:1.6 }}>
            {Object.keys(techMap).length} technologies detected across {assets.filter(a=>a.tech_stack?.length).length} assets. Click a technology to see all affected hosts.
          </div>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Filter technologies..."
            style={{ width:"100%", background:"#0f1117", border:"1px solid #1e2438", color:"#ffffff", borderRadius:6, padding:"7px 10px", fontSize:11, outline:"none", fontFamily:MONO, boxSizing:"border-box", marginBottom:8 }}/>
          <div style={{ display:"flex", gap:6 }}>
            <button onClick={()=>setSortBy("count")} style={{ flex:1, padding:"5px", background:sortBy==="count"?"rgba(232,0,26,0.1)":"transparent", border:`1px solid ${sortBy==="count"?"rgba(232,0,26,0.4)":"#1e2438"}`, color:sortBy==="count"?"#e8001a":"#64748b", borderRadius:5, fontSize:9, fontFamily:F, letterSpacing:1, cursor:"pointer" }}>BY COUNT</button>
            <button onClick={()=>setSortBy("name")} style={{ flex:1, padding:"5px", background:sortBy==="name"?"rgba(232,0,26,0.1)":"transparent", border:`1px solid ${sortBy==="name"?"rgba(232,0,26,0.4)":"#1e2438"}`, color:sortBy==="name"?"#e8001a":"#64748b", borderRadius:5, fontSize:9, fontFamily:F, letterSpacing:1, cursor:"pointer" }}>A-Z</button>
          </div>
        </div>

        {/* Category filter */}
        <div style={{ padding:"8px 12px", borderBottom:"1px solid #1e2438", display:"flex", gap:4, flexWrap:"wrap" }}>
          {["ALL",...Object.keys(TECH_CATEGORIES)].filter(c => categories[c]).map(c => (
            <button key={c} onClick={()=>setCategoryFilter(c)} style={{ padding:"2px 8px", fontSize:9, letterSpacing:1, fontFamily:F, border:`1px solid ${categoryFilter===c?"rgba(232,0,26,0.5)":"#1e2438"}`, borderRadius:4, background:categoryFilter===c?"rgba(232,0,26,0.1)":"transparent", color:categoryFilter===c?"#e8001a":"#64748b", cursor:"pointer" }}>
              {c.toUpperCase()} {categories[c]?`(${categories[c]})`:null}
            </button>
          ))}
        </div>

        {/* Tech list */}
        <div style={{ flex:1, overflowY:"auto" }}>
          {assets.length === 0 ? (
            <div style={{ padding:32, textAlign:"center", color:"#64748b", fontSize:11, lineHeight:1.8 }}>
              No assets discovered yet.<br/>Run a scan to detect technologies.
            </div>
          ) : techList.length === 0 ? (
            <div style={{ padding:32, textAlign:"center", color:"#64748b", fontSize:11 }}>No tech matches filter</div>
          ) : techList.map(({ tech, count, category, vuln }) => (
            <div key={tech} onClick={()=>setSelectedTech(tech)}
              style={{ padding:"10px 14px", borderBottom:"1px solid rgba(30,36,56,0.5)", cursor:"pointer", background:selectedTech===tech?"rgba(232,0,26,0.06)":"transparent", borderLeft:`2px solid ${selectedTech===tech?"#e8001a":"transparent"}`, transition:"all 0.1s" }}
              onMouseEnter={e=>{if(selectedTech!==tech)(e.currentTarget as HTMLElement).style.background="rgba(255,255,255,0.02)";}}
              onMouseLeave={e=>{if(selectedTech!==tech)(e.currentTarget as HTMLElement).style.background="transparent";}}>
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <span style={{ fontSize:12, fontWeight:700, color:"#ffffff" }}>{tech}</span>
                    {vuln && (
                      <span style={{ fontSize:9, fontWeight:700, color:SEV_C[vuln.severity], background:`${SEV_C[vuln.severity]}22`, border:`1px solid ${SEV_C[vuln.severity]}44`, padding:"1px 5px", borderRadius:3, letterSpacing:1, flexShrink:0 }}>
                        {vuln.severity}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize:10, color:"#64748b", marginTop:2 }}>{category}</div>
                </div>
                <div style={{ textAlign:"center", flexShrink:0 }}>
                  <div style={{ fontSize:18, fontWeight:800, color:"#e8001a", lineHeight:1 }}>{count}</div>
                  <div style={{ fontSize:9, color:"#64748b" }}>hosts</div>
                </div>
              </div>
              {/* Mini bar */}
              <div style={{ height:2, background:"rgba(232,0,26,0.08)", borderRadius:1, marginTop:8, overflow:"hidden" }}>
                <div style={{ height:"100%", width:`${Math.min(100,(count / Math.max(...techList.map(t=>t.count)))*100)}%`, background: vuln ? SEV_C[vuln.severity] : "#e8001a", borderRadius:1, opacity:0.7 }}/>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right detail */}
      <div style={{ flex:1, overflowY:"auto", padding:24 }}>
        {!selectedTech ? (
          <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"80%", textAlign:"center" }}>
            <div style={{ fontSize:48, marginBottom:16, opacity:0.1 }}>⬡</div>
            <div style={{ fontSize:14, color:"#ffffff", fontWeight:700, fontFamily:F, letterSpacing:2, marginBottom:8 }}>TECH STACK PIVOT</div>
            <div style={{ fontSize:12, color:"#64748b", maxWidth:400, lineHeight:1.8 }}>
              Select a technology from the list to see all hosts running it, check for known vulnerable versions, and run targeted Nuclei templates against that specific tech stack.
            </div>
            {techList.length > 0 && (
              <div style={{ marginTop:32, display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10, maxWidth:520 }}>
                {techList.slice(0,9).map(({tech, count, vuln}) => (
                  <div key={tech} onClick={()=>setSelectedTech(tech)}
                    style={{ padding:"10px 14px", background:"#0f1117", border:`1px solid ${vuln?"rgba(255,107,43,0.3)":"#1e2438"}`, borderRadius:8, cursor:"pointer", textAlign:"center", transition:"all 0.15s" }}
                    onMouseEnter={e=>(e.currentTarget as HTMLElement).style.borderColor="#e8001a"}
                    onMouseLeave={e=>(e.currentTarget as HTMLElement).style.borderColor=vuln?"rgba(255,107,43,0.3)":"#1e2438"}>
                    <div style={{ fontSize:13, fontWeight:700, color:"#ffffff" }}>{tech}</div>
                    <div style={{ fontSize:10, color:"#64748b", marginTop:4 }}>{count} host{count!==1?"s":""}</div>
                    {vuln && <div style={{ fontSize:9, color:SEV_C[vuln.severity], marginTop:4 }}>{vuln.severity}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="animate-in">
            {/* Header */}
            <div style={{ display:"flex", alignItems:"center", gap:16, marginBottom:24 }}>
              <div style={{ width:48, height:48, background:"rgba(232,0,26,0.1)", border:"1px solid rgba(232,0,26,0.3)", borderRadius:10, display:"flex", alignItems:"center", justifyContent:"center", fontSize:22, flexShrink:0 }}>⬡</div>
              <div>
                <div style={{ fontSize:20, fontWeight:900, color:"#ffffff", fontFamily:F, letterSpacing:2 }}>{selectedTech}</div>
                <div style={{ fontSize:11, color:"#64748b", marginTop:4 }}>
                  {getTechCategory(selectedTech)} · {selectedAssets.length} host{selectedAssets.length!==1?"s":""} detected
                </div>
              </div>
              {selectedVuln && (
                <div style={{ marginLeft:"auto", padding:"8px 16px", background:`${SEV_C[selectedVuln.severity]}18`, border:`1px solid ${SEV_C[selectedVuln.severity]}44`, borderRadius:8 }}>
                  <div style={{ fontSize:10, fontWeight:700, color:SEV_C[selectedVuln.severity], letterSpacing:1 }}>{selectedVuln.severity}</div>
                  <div style={{ fontSize:11, color:"#a0aec0", marginTop:2 }}>{selectedVuln.title}</div>
                  <div style={{ fontSize:10, color:"#64748b", marginTop:1, fontFamily:MONO }}>{selectedVuln.cve}</div>
                </div>
              )}
            </div>

            {/* Vuln version warning */}
            {selectedVuln && (
              <div style={{ background:`${SEV_C[selectedVuln.severity]}10`, border:`1px solid ${SEV_C[selectedVuln.severity]}33`, borderRadius:10, padding:16, marginBottom:20 }}>
                <div style={{ fontSize:12, fontWeight:700, color:SEV_C[selectedVuln.severity], marginBottom:6, display:"flex", alignItems:"center", gap:8 }}>
                  ⚠ POTENTIAL VULNERABILITY DETECTED
                </div>
                <div style={{ fontSize:12, color:"#a0aec0", lineHeight:1.7 }}>
                  <strong style={{ color:"#ffffff" }}>{selectedVuln.title}</strong> — {selectedVuln.cve}<br/>
                  The detected version string matches a known vulnerable pattern. Run targeted Nuclei templates to confirm.
                </div>
              </div>
            )}

            {/* Targeted scan button */}
            <div style={{ background:"#0f1117", border:"1px solid #1e2438", borderRadius:10, padding:16, marginBottom:20, display:"flex", alignItems:"center", gap:16 }}>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:12, fontWeight:700, color:"#ffffff", marginBottom:4 }}>Run Targeted Nuclei Scan</div>
                <div style={{ fontSize:11, color:"#64748b" }}>
                  Execute Nuclei with <span style={{ color:"#a78bfa", fontFamily:MONO }}>-tags {selectedTech.toLowerCase().split(" ")[0]}</span> against all {selectedAssets.length} host{selectedAssets.length!==1?"s":""} running {selectedTech}
                </div>
              </div>
              <button onClick={() => onRunNuclei?.(techList.find(t=>t.tech===selectedTech)?.urls??[], selectedTech)}
                style={{ padding:"9px 20px", background:"rgba(167,139,250,0.1)", border:"1px solid rgba(167,139,250,0.4)", color:"#a78bfa", borderRadius:8, fontSize:11, fontFamily:F, letterSpacing:1, cursor:"pointer", whiteSpace:"nowrap" }}>
                ▶ SCAN {selectedAssets.length} HOSTS
              </button>
            </div>

            {/* Affected hosts table */}
            <div style={{ fontSize:10, color:"#64748b", letterSpacing:2, fontFamily:F, marginBottom:12 }}>
              AFFECTED HOSTS ({selectedAssets.length})
            </div>
            <div style={{ background:"#0f1117", border:"1px solid #1e2438", borderRadius:10, overflow:"hidden" }}>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead>
                  <tr style={{ borderBottom:"1px solid #1e2438" }}>
                    {["Host","IP","Status","Title","Scope"].map(h=>(
                      <th key={h} style={{ textAlign:"left", padding:"9px 14px", fontSize:9, fontWeight:700, textTransform:"uppercase", letterSpacing:1.5, color:"#64748b", fontFamily:F }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {selectedAssets.map(a => (
                    <tr key={a.id} style={{ borderBottom:"1px solid rgba(30,36,56,0.5)" }}
                      onMouseEnter={e=>(e.currentTarget as HTMLElement).style.background="rgba(255,255,255,0.02)"}
                      onMouseLeave={e=>(e.currentTarget as HTMLElement).style.background="transparent"}>
                      <td style={{ padding:"9px 14px", fontSize:11, color:"#ffffff", fontFamily:MONO, maxWidth:200, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{a.value}</td>
                      <td style={{ padding:"9px 14px", fontSize:10, color:"#a0aec0", fontFamily:MONO }}>{a.ip ?? "—"}</td>
                      <td style={{ padding:"9px 14px" }}>
                        {a.http_status ? (
                          <span style={{ fontSize:10, fontWeight:700, color: a.http_status < 300?"#00ff88":a.http_status<400?"#ffd700":a.http_status<500?"#ff6b2b":"#ff1a3d", fontFamily:MONO }}>
                            {a.http_status}
                          </span>
                        ) : <span style={{ color:"#64748b", fontSize:10 }}>—</span>}
                      </td>
                      <td style={{ padding:"9px 14px", fontSize:11, color:"#a0aec0", maxWidth:180, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{a.page_title ?? "—"}</td>
                      <td style={{ padding:"9px 14px" }}>
                        <span style={{ fontSize:9, fontWeight:700, color:a.in_scope?"#00ff88":"#ff1a3d", background:a.in_scope?"rgba(0,255,136,0.08)":"rgba(255,26,61,0.08)", border:`1px solid ${a.in_scope?"rgba(0,255,136,0.3)":"rgba(255,26,61,0.3)"}`, padding:"2px 7px", borderRadius:4, letterSpacing:1 }}>
                          {a.in_scope?"IN SCOPE":"OUT"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
