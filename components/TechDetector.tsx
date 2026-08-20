"use client";

import { useState } from "react";
import { detectTechStack, TechDetectResult } from "@/lib/api";

export default function TechDetector() {
  const [url, setUrl]         = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [result, setResult]   = useState<TechDetectResult | null>(null);

  const handleDetect = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      setResult(await detectTechStack(url));
    } catch (err: any) {
      setError(err.message || "Tech detection failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-4xl space-y-5 animate-fadeIn">
      {/* Input Card */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-signal border border-cyan-500/30">
                STACK FINGERPRINTING
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🎯 Web Tech Stack &amp; CMS Fingerprint Detector
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Detect CMS platforms, web servers, JavaScript frameworks, CDN/WAF providers, analytics, and UI libraries.
            </p>
          </div>
        </div>

        <form onSubmit={handleDetect} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
          />
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="px-6 py-3 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15 whitespace-nowrap"
          >
            {loading ? "Detecting…" : "Detect Stack"}
          </button>
        </form>

        {/* Quick Samples */}
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-mist pt-1">
          <span>Try samples:</span>
          {["github.com", "cloudflare.com", "wordpress.org"].map((u) => (
            <button
              key={u}
              type="button"
              onClick={() => { setUrl(u); }}
              className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white transition"
            >
              {u}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-rose-500/10 border border-rose-500/25 rounded-xl text-sm font-mono text-rose-400 animate-fadeIn">
          <span className="shrink-0">⚠</span>
          <div>
            <div className="font-bold">Fingerprinting Error</div>
            <div className="text-[11px] text-rose-400/70 mt-0.5">{error}</div>
          </div>
          <button onClick={() => setError(null)} className="ml-auto text-rose-400/40 hover:text-rose-400 transition">✕</button>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="bg-panel border border-panelBorder rounded-2xl py-10 flex flex-col items-center gap-3">
          <div className="flex gap-1.5">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="w-1.5 h-1.5 rounded-full bg-cyan-signal animate-ping"
                style={{ animationDelay: `${i * 150}ms`, animationDuration: "1.2s" }}
              />
            ))}
          </div>
          <div className="text-xs font-mono text-cyan-signal animate-blink">
            Scanning HTML DOM, response headers, cookies, and script asset signatures…
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slideUp">
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-panelBorder/60 pb-4">
              <div>
                <span className="text-[9px] font-mono text-mist uppercase tracking-widest block">Target Web App</span>
                <div className="font-mono text-lg font-bold text-white break-all">{result.final_url}</div>
              </div>

              <div className="text-xs font-mono text-cyan-signal font-bold px-3 py-1 rounded-xl bg-cyan-signal/10 border border-cyan-signal/20">
                {result.total_detected} Technologies Identified
              </div>
            </div>

            {/* Grid of Technologies */}
            {result.technologies.length === 0 ? (
              <div className="text-center py-6 text-mist font-mono text-xs">
                No known technology stack signatures matched for this target.
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {result.technologies.map((tech, idx) => (
                  <div
                    key={idx}
                    className="bg-void/60 border border-panelBorder/50 p-4 rounded-xl flex items-center gap-3 hover:border-cyan-signal/30 transition font-mono"
                  >
                    <span className="text-2xl">{tech.icon}</span>
                    <div>
                      <span className="text-white font-bold text-sm block">{tech.name}</span>
                      <span className="text-mist text-[11px] block">{tech.category}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
