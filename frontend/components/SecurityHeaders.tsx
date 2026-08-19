"use client";

import { useState } from "react";
import { auditSecurityHeaders, HeaderAuditResult } from "@/lib/api";

export default function SecurityHeaders() {
  const [url, setUrl]         = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [result, setResult]   = useState<HeaderAuditResult | null>(null);

  const handleAudit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      setResult(await auditSecurityHeaders(url));
    } catch (err: any) {
      setError(err.message || "Header audit failed");
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
                HEADER SCORECARD
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🛡️ HTTP Security Headers Audit &amp; Scorecard
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Audit CSP, HSTS, X-Frame-Options, MIME sniffing protection, Referrer Policy, and information leakage risks.
            </p>
          </div>
        </div>

        <form onSubmit={handleAudit} className="flex flex-col sm:flex-row gap-3">
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
            {loading ? "Auditing…" : "Audit Headers"}
          </button>
        </form>

        {/* Quick Samples */}
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-mist pt-1">
          <span>Try samples:</span>
          {["github.com", "google.com", "httpforever.com"].map((u) => (
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
            <div className="font-bold">Audit Error</div>
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
            Deconstructing HTTP response headers &amp; calculating security compliance score…
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slideUp">
          {/* Header Score Banner */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-panelBorder/60 pb-4">
              <div>
                <span className="text-[9px] font-mono text-mist uppercase tracking-widest block">Audit Target</span>
                <div className="font-mono text-lg font-bold text-white break-all">{result.final_url}</div>
                <div className="text-xs font-mono text-mist mt-1">
                  HTTP Status: <span className="text-cyan-signal font-bold">{result.status_code}</span>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-center font-mono">
                  <span className="text-[9px] text-mist block uppercase">SCORE</span>
                  <span className="text-xl font-bold text-cyan-signal">{result.score_percentage}%</span>
                </div>
                <div className={`px-4 py-2 rounded-2xl border font-mono font-extrabold text-2xl ${
                  result.grade.startsWith("A") ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" :
                  result.grade === "B" || result.grade === "C" ? "bg-amber-500/15 text-amber-300 border-amber-500/30" :
                  "bg-rose-500/15 text-rose-400 border-rose-500/30"
                }`}>
                  {result.grade}
                </div>
              </div>
            </div>

            {/* Header Checklist */}
            <div className="space-y-2">
              <span className="text-[10px] font-mono text-mist uppercase tracking-widest block mb-2">Security Header Assessment</span>
              {result.headers_audited.map((item, idx) => (
                <div
                  key={idx}
                  className={`p-3.5 rounded-xl border font-mono text-xs space-y-1.5 transition ${
                    item.present
                      ? "bg-void/60 border-emerald-500/25 hover:border-emerald-500/50"
                      : "bg-void/40 border-rose-500/20 hover:border-rose-500/40"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-white font-bold">{item.header}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                      item.present
                        ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                        : "bg-rose-500/15 text-rose-400 border-rose-500/30"
                    }`}>
                      {item.present ? "PASS ✓" : "MISSING ✕"}
                    </span>
                  </div>

                  <div className="text-[11px] text-mist leading-relaxed">{item.description}</div>

                  {item.present ? (
                    <div className="text-[11px] text-cyan-signal bg-void px-2.5 py-1 rounded border border-panelBorder/60 break-all">
                      {item.value}
                    </div>
                  ) : (
                    <div className="text-[10px] text-amber-300/80 bg-amber-500/10 px-2.5 py-1 rounded border border-amber-500/20">
                      💡 Recommended: <code className="text-white font-bold">{item.recommendation}</code>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Info Leaks */}
          {result.info_leaks.length > 0 && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 inline-block">
                ⚠️ INFORMATION LEAKAGE HEADERS
              </span>
              <div className="space-y-2 font-mono text-xs">
                {result.info_leaks.map((leak, i) => (
                  <div key={i} className="flex items-start justify-between gap-3 bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl">
                    <div>
                      <span className="text-white font-bold block">{leak.header}: <code className="text-cyan-signal">{leak.value}</code></span>
                      <span className="text-mist text-[11px] mt-0.5 block">{leak.risk}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
