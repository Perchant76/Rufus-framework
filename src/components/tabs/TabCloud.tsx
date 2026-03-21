// src/components/tabs/TabCloud.tsx
import React, { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Card, SectionHdr, Btn } from "../ui";
import type { CloudAsset } from "../../types";

const PROVIDER_LABELS: Record<string, string> = {
  aws_s3: "AWS S3", azure_blob: "Azure Blob", gcp_storage: "GCP Storage",
};
const PROVIDER_COLORS: Record<string, string> = {
  aws_s3: "#ff9900", azure_blob: "#0078d4", gcp_storage: "#4285f4",
};

export default function TabCloud({ currentScanId }: { currentScanId: string | null }) {
  const [target, setTarget] = useState("");
  const [assets, setAssets] = useState<CloudAsset[]>([]);
  const [loading, setLoading] = useState(false);

  const enumerate = async () => {
    if (!target) return;
    setLoading(true);
    try {
      const results = await invoke<CloudAsset[]>("enumerate_cloud_assets", {
        target, scanId: currentScanId ?? "manual",
      });
      setAssets(results);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  const accessible = assets.filter(a => a.accessible);
  const takeover = assets.filter(a => a.takeover_candidate);
  const found = assets.filter(a => a.status > 0);

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ maxWidth: 960, paddingBottom: 60 }}>
        <SectionHdr title="Cloud Asset Enumeration" />
        <Card style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
            <input style={{ flex: 1, background: "var(--bg2)", border: "1px solid var(--border)", color: "var(--text)", fontFamily: "var(--font-mono)", fontSize: 12, borderRadius: "var(--r)", padding: "7px 10px", outline: "none" }}
              value={target} onChange={e => setTarget(e.target.value)} placeholder="target.com or company name" />
            <Btn variant="primary" onClick={enumerate} disabled={loading || !target}>
              {loading ? "Scanning…" : "Enumerate Cloud"}
            </Btn>
          </div>
          <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
            Checks AWS S3, Azure Blob, and GCP Storage permutations for exposed buckets and takeover candidates.
            Uses curl — no API keys required.
          </div>
        </Card>

        {assets.length > 0 && (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 16 }}>
              {[
                { n: found.length, l: "Responded", c: "var(--accent)" },
                { n: accessible.length, l: "Accessible", c: "var(--red)" },
                { n: takeover.length, l: "Takeover Candidates", c: "var(--yellow)" },
              ].map(s => (
                <div key={s.l} style={{ background: "var(--bg2)", border: "1px solid var(--border)", borderRadius: "var(--r)", padding: "14px 16px" }}>
                  <div style={{ fontFamily: "var(--font-ui)", fontSize: 28, fontWeight: 800, color: s.c }}>{s.n}</div>
                  <div style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginTop: 4 }}>{s.l}</div>
                </div>
              ))}
            </div>

            {takeover.length > 0 && (
              <>
                <SectionHdr title="⚠ Takeover Candidates" />
                {takeover.map(a => (
                  <Card key={a.id} style={{ marginBottom: 8, borderColor: "var(--yellow)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <span style={{ fontSize: 10, padding: "2px 7px", background: "rgba(255,171,0,.15)", color: "var(--yellow)", border: "1px solid rgba(255,171,0,.3)", borderRadius: 3, fontWeight: 700 }}>TAKEOVER</span>
                      <span style={{ fontSize: 12, color: "var(--accent)", flex: 1, fontFamily: "var(--font-mono)" }}>{a.url}</span>
                      <span style={{ fontSize: 10, color: PROVIDER_COLORS[a.provider] }}>{PROVIDER_LABELS[a.provider]}</span>
                    </div>
                  </Card>
                ))}
              </>
            )}

            {accessible.length > 0 && (
              <>
                <SectionHdr title="Accessible Assets" />
                {accessible.map(a => (
                  <Card key={a.id} style={{ marginBottom: 8, borderColor: "var(--red)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <span style={{ fontSize: 12, color: "#ff3b5c", fontWeight: 700 }}>{a.status}</span>
                      <span style={{ fontSize: 12, color: "var(--text-hi)", flex: 1, fontFamily: "var(--font-mono)" }}>{a.url}</span>
                      <span style={{ fontSize: 10, color: PROVIDER_COLORS[a.provider] }}>{PROVIDER_LABELS[a.provider]}</span>
                      <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{a.checked_at.slice(0, 19)}</span>
                    </div>
                  </Card>
                ))}
              </>
            )}
          </>
        )}

        {!loading && assets.length === 0 && (
          <div style={{ textAlign: "center", padding: "60px 0", color: "var(--text-dim)" }}>
            <div style={{ fontSize: 40, opacity: .2, marginBottom: 12 }}>☁️</div>
            <div style={{ fontSize: 12 }}>Enter a target to enumerate cloud storage assets.</div>
          </div>
        )}
        <div style={{ textAlign: "center", marginTop: 40, fontSize: 11, color: "var(--text-dim)", opacity: .5 }}>
          Build with ❤️ by Perchant
        </div>
      </div>
    </div>
  );
}
