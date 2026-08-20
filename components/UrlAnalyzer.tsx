"use client";

import { useState } from "react";
import { analyzeUrl, UrlAnalysisResult } from "@/lib/api";

export default function UrlAnalyzer() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeUrl(url);
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to analyze URL");
    } finally {
      setLoading(false);
    }
  };

  const setSample = (sampleUrl: string) => {
    setUrl(sampleUrl);
  };

  return (
    <div className="w-full max-w-4xl space-y-6 animate-fadeIn">
      {/* Input Card */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
        <div>
          <h2 className="font-display text-lg sm:text-xl font-bold text-white flex items-center gap-2">
            <span>🔗 VirusTotal-Style URL Scanner & Threat Engine</span>
          </h2>
          <p className="text-xs sm:text-sm text-mist font-mono mt-1">
            Analyze any URL for phishing heuristics, redirect hops, malicious payloads, and multi-engine AV reputation.
          </p>
        </div>

        <form onSubmit={handleAnalyze} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="https://example.com/login?redirect=portal"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 px-4 py-3 bg-void border border-panelBorder rounded-xl text-white font-mono text-xs sm:text-sm focus:outline-none focus:border-cyan-signal"
          />
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="px-6 py-3 bg-cyan-signal text-void font-display font-bold text-xs sm:text-sm rounded-xl hover:bg-cyan-signal/90 transition shadow-md disabled:opacity-50"
          >
            {loading ? "Analyzing URL..." : "Analyze URL"}
          </button>
        </form>

        {/* Quick Sample Links */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs font-mono text-mist">
          <span>Try samples:</span>
          <button
            type="button"
            onClick={() => setSample("https://github.com/login")}
            className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white"
          >
            github.com/login
          </button>
          <button
            type="button"
            onClick={() => setSample("https://cloudflare.com")}
            className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white"
          >
            cloudflare.com
          </button>
          <button
            type="button"
            onClick={() => setSample("http://httpforever.com")}
            className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white"
          >
            httpforever.com
          </button>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 bg-crimson-risk/10 border border-crimson-risk/30 rounded-xl text-crimson-risk text-xs font-mono">
          {error}
        </div>
      )}

      {/* Loading animation */}
      {loading && (
        <div className="text-center py-10 space-y-2">
          <div className="font-mono text-sm text-cyan-signal animate-blink">
            Tracing redirect hops & querying 30+ antivirus threat databases...
          </div>
        </div>
      )}

      {/* Analysis Results */}
      {result && (
        <div className="space-y-6 animate-fadeIn">
          {/* Header Card */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-panelBorder/70 pb-3">
              <div>
                <span className="text-[10px] font-mono uppercase text-mist tracking-widest block">URL Target</span>
                <span className="font-mono text-sm sm:text-base font-bold text-white break-all">
                  {result.raw_url}
                </span>
                <div className="text-xs font-mono text-mist mt-1">
                  Resolved IP: <span className="text-cyan-signal">{result.ip || "Unresolved"}</span> • Status: HTTP {result.status_code || "N/A"}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <a
                  href={result.virustotal.vt_url_link}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1 text-xs font-mono rounded bg-void border border-cyan-signal/40 text-cyan-signal hover:bg-cyan-signal/10 transition shadow-sm"
                >
                  VirusTotal URL Graph ↗
                </a>
                <span className={`text-xs font-mono font-bold px-3 py-1 rounded ${
                  result.risk_score === 0 && result.virustotal.malicious_count === 0
                    ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                    : "bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse"
                }`}>
                  {result.risk_rating}
                </span>
              </div>
            </div>

            {/* Quick Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-center">
              <div className="bg-void/60 border border-panelBorder p-2.5 rounded-xl">
                <span className="text-[10px] text-mist block uppercase">Destination Server</span>
                <span className="text-xs font-bold text-white truncate block">{result.server || "Masked"}</span>
              </div>
              <div className="bg-void/60 border border-panelBorder p-2.5 rounded-xl">
                <span className="text-[10px] text-mist block uppercase">Content-Type</span>
                <span className="text-xs font-bold text-white truncate block">{result.content_type.split(";")[0]}</span>
              </div>
              <div className="bg-void/60 border border-panelBorder p-2.5 rounded-xl">
                <span className="text-[10px] text-mist block uppercase">Redirect Hops</span>
                <span className="text-xs font-bold text-cyan-signal">{result.redirect_hops_count}</span>
              </div>
              <div className="bg-void/60 border border-panelBorder p-2.5 rounded-xl">
                <span className="text-[10px] text-mist block uppercase">Multi-AV Score</span>
                <span className={`text-xs font-bold ${result.virustotal.malicious_count > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                  {result.virustotal.malicious_count} / {result.virustotal.total_engines} Flagged
                </span>
              </div>
            </div>
          </div>

          {/* Redirect Chain Trace */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
            <h3 className="font-display text-base font-bold text-white">
              Redirect Hop Trace ({result.redirect_chain.length} hops)
            </h3>
            <div className="space-y-2 font-mono text-xs">
              {result.redirect_chain.map((hop, idx) => (
                <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 bg-void/60 border border-panelBorder/70 p-3 rounded-xl">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-cyan-signal/20 text-cyan-signal text-[10px] flex items-center justify-center font-bold">
                      {hop.hop}
                    </span>
                    <span className="text-white break-all">{hop.url}</span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded self-start sm:self-auto ${
                    hop.status_code >= 200 && hop.status_code < 300
                      ? "bg-emerald-500/15 text-emerald-400"
                      : (hop.status_code >= 300 && hop.status_code < 400 ? "bg-amber-500/15 text-amber-300" : "bg-rose-500/15 text-rose-400")
                  }`}>
                    HTTP {hop.status_code}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Heuristics & Phishing Assessment */}
          {result.heuristics.length > 0 && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
              <h3 className="font-display text-base font-bold text-white">
                Heuristic & Phishing Analysis
              </h3>
              <div className="space-y-2">
                {result.heuristics.map((h, i) => (
                  <div key={i} className="bg-void/60 border border-panelBorder p-3 rounded-xl flex justify-between items-center text-xs font-mono">
                    <div>
                      <span className="text-white font-bold block">{h.type}</span>
                      <span className="text-mist text-[11px]">{h.details}</span>
                    </div>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                      {h.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* VirusTotal Engine Grid for URL */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
            <div className="flex justify-between items-center">
              <h3 className="font-display text-base font-bold text-white">
                Multi-AV Security Vendor Engine Matrix
              </h3>
              <span className="text-xs font-mono text-mist">
                {result.virustotal.total_engines} Engines Checked
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-60 overflow-y-auto pr-1">
              {result.virustotal.engine_results.map((eng, idx) => (
                <div key={idx} className="flex justify-between items-center bg-void/60 border border-panelBorder/70 px-3 py-2 rounded-lg text-xs font-mono">
                  <span className="text-white font-medium truncate max-w-[140px]">{eng.engine_name}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                    eng.category === "malicious"
                      ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                      : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                  }`}>
                    {eng.result.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
