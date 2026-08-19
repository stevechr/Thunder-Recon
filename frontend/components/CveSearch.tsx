"use client";

import { useState } from "react";
import { searchCveVulnerabilities, CveSearchResult } from "@/lib/api";

export default function CveSearch() {
  const [query, setQuery]     = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [result, setResult]   = useState<CveSearchResult | null>(null);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!query.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      setResult(await searchCveVulnerabilities(query));
    } catch (err: any) {
      setError(err.message || "CVE search failed");
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
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                NVD VULNERABILITY DATABASE
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🔍 CVE Vulnerability Search Engine
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Search National Vulnerability Database (NVD) by CVE ID (e.g. CVE-2021-44228) or software keyword (e.g. Log4j, OpenSSL, Apache).
            </p>
          </div>
        </div>

        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="CVE-2021-44228, Log4j, Spring, OpenSSL..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
          />
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="px-6 py-3 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15 whitespace-nowrap"
          >
            {loading ? "Searching…" : "Search CVEs"}
          </button>
        </form>

        {/* Quick Samples */}
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-mist pt-1">
          <span>Try popular CVEs:</span>
          {["CVE-2021-44228", "CVE-2023-4863", "Log4j", "Heartbleed"].map((kw) => (
            <button
              key={kw}
              type="button"
              onClick={() => { setQuery(kw); }}
              className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white transition"
            >
              {kw}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-rose-500/10 border border-rose-500/25 rounded-xl text-sm font-mono text-rose-400 animate-fadeIn">
          <span className="shrink-0">⚠</span>
          <div>
            <div className="font-bold">Search Error</div>
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
            Querying NVD (National Vulnerability Database) &amp; parsing CVSS scores…
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slideUp">
          <div className="flex items-center justify-between text-xs font-mono px-1">
            <span className="text-mist">Query: <strong className="text-white">{result.query}</strong></span>
            <span className="text-cyan-signal font-bold">{result.total_results} Vulnerability Records Found</span>
          </div>

          {result.cves.length === 0 ? (
            <div className="bg-panel border border-panelBorder rounded-2xl p-8 text-center text-mist font-mono text-xs">
              No matching CVE vulnerabilities found in the NVD database.
            </div>
          ) : (
            <div className="space-y-3">
              {result.cves.map((cve) => {
                const isCritical = cve.severity === "CRITICAL";
                const isHigh = cve.severity === "HIGH";
                const isMedium = cve.severity === "MEDIUM";

                return (
                  <div
                    key={cve.cve_id}
                    className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-3 hover:border-panelBorder/80 transition"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-panelBorder/60 pb-2.5">
                      <div className="flex items-center gap-2.5">
                        <span className="font-mono text-base font-bold text-white">{cve.cve_id}</span>
                        <span className="text-[10px] font-mono text-mist">Published: {cve.published}</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded-lg border ${
                          isCritical ? "bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse" :
                          isHigh ? "bg-rose-500/15 text-rose-400 border-rose-500/30" :
                          isMedium ? "bg-amber-500/15 text-amber-300 border-amber-500/30" :
                          "bg-slate-500/15 text-slate-300 border-slate-500/30"
                        }`}>
                          CVSS {cve.cvss_score} • {cve.severity}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs font-mono text-mist/90 leading-relaxed">
                      {cve.description}
                    </p>

                    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono pt-1">
                      <div className="flex items-center gap-3 text-mist">
                        <span>Vector: <strong className="text-white/80">{cve.attack_vector}</strong></span>
                      </div>
                      <a
                        href={cve.nvd_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-cyan-signal hover:underline flex items-center gap-1"
                      >
                        NVD Details ↗
                      </a>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
