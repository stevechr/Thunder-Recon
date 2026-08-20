"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ThreatData {
  url: string;
  host: string;
  is_malicious: boolean;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN";
  risk_sources: string[];
  heuristics: {
    url: string;
    hostname: string;
    scheme: string;
    tld: string;
    heuristic_score: number;
    risk_level: string;
    findings: string[];
  };
  urlhaus_url: {
    found: boolean;
    source?: string;
    url_status?: string;
    threat?: string;
    tags?: string[];
    date_added?: string;
    urlhaus_link?: string;
  };
  urlhaus_host: {
    found: boolean;
    source?: string;
    url_count?: number;
    recent_urls?: { url: string; url_status: string; threat: string; date_added: string }[];
  };
  redirect_chain: {
    chain: { url: string; status: number; location: string | null }[];
    hops: number;
    final_url?: string;
    domains_traversed?: string[];
    suspicious_patterns?: string[];
    is_suspicious?: boolean;
  };
  google_safe_browsing: {
    available: boolean;
    is_safe?: boolean;
    threats?: { type: string; platform: string; entry_type: string }[];
    reason?: string;
  };
}

export default function PhishingDetector() {
  const [targetUrl, setTargetUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ThreatData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/tools/phishing`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl.trim() }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Scan failed (HTTP ${res.status})`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to analyze URL threat.");
    } finally {
      setLoading(false);
    }
  };

  const getVerdictStyle = (verdict: string) => {
    if (verdict === "MALICIOUS") return "bg-red-500/20 text-red-400 border-red-500/40";
    if (verdict === "SUSPICIOUS") return "bg-amber-500/20 text-amber-400 border-amber-500/40";
    return "bg-emerald-500/20 text-emerald-400 border-emerald-500/40";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">🎣</span>
            Phishing & Malicious URL Scanner
          </h2>
          <p className="text-sm text-mist mt-1">
            Detect phishing sites, malicious redirects, URLhaus malware payloads, and IDN homograph impersonation.
          </p>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="Enter URL to check (e.g. http://suspicious-login-update.xyz/auth)"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="w-full bg-void/60 border border-border/80 focus:border-red-500/80 rounded-xl px-4 py-3 text-sm text-white placeholder-mist/40 outline-none transition"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !targetUrl.trim()}
            className="px-6 py-3 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-medium text-sm rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-red-600/20 cursor-pointer disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                Scanning Threat Databases...
              </>
            ) : (
              <>
                <span>🚨</span> Inspect URL
              </>
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm flex items-center gap-3">
          <span>⚠️</span> {error}
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Executive Verdict Banner */}
          <div className="p-6 rounded-2xl border bg-surface/90 border-border backdrop-blur-md space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <span className="text-xs uppercase tracking-wider font-semibold text-mist">Threat Assessment</span>
                <div className="flex items-center gap-3 mt-1">
                  <span className={`text-2xl font-black px-4 py-1 rounded-xl border ${getVerdictStyle(result.verdict)}`}>
                    {result.verdict === "MALICIOUS" ? "🚨 MALICIOUS URL" : result.verdict === "SUSPICIOUS" ? "⚠️ SUSPICIOUS ACTIVITY" : "✅ CLEAN / NO THREATS FOUND"}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="p-3 bg-void/60 border border-border rounded-xl text-center min-w-[120px]">
                  <div className="text-[10px] text-mist uppercase">Heuristic Risk</div>
                  <div className="text-xl font-bold text-white font-mono">{result.heuristics.heuristic_score} / 100</div>
                </div>
                <div className="p-3 bg-void/60 border border-border rounded-xl text-center min-w-[120px]">
                  <div className="text-[10px] text-mist uppercase">Redirect Hops</div>
                  <div className="text-xl font-bold text-white font-mono">{result.redirect_chain.hops}</div>
                </div>
              </div>
            </div>

            {result.risk_sources.length > 0 && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl">
                <div className="text-xs font-bold text-red-400 mb-1">Triggered Indicators:</div>
                <ul className="text-xs text-red-300/90 list-disc list-inside space-y-0.5">
                  {result.risk_sources.map((rs, i) => (
                    <li key={i}>{rs}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* 2-Column Grid: URLhaus & Heuristics */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* URLhaus Threat Intelligence */}
            <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <div className="flex items-center gap-2">
                  <span>🛡️</span>
                  <h3 className="font-bold text-white text-base">URLhaus (abuse.ch)</h3>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded font-bold border ${result.urlhaus_url.found ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"}`}>
                  {result.urlhaus_url.found ? "FLAGGED" : "NOT LISTED"}
                </span>
              </div>

              {result.urlhaus_url.found ? (
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between py-1 border-b border-border/20 text-mist">
                    <span>Threat Type:</span>
                    <span className="font-bold text-red-400">{result.urlhaus_url.threat || "Malicious Payload"}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-border/20 text-mist">
                    <span>URL Status:</span>
                    <span className="text-white font-mono">{result.urlhaus_url.url_status}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-border/20 text-mist">
                    <span>Date Added:</span>
                    <span className="text-white font-mono">{result.urlhaus_url.date_added}</span>
                  </div>
                  {result.urlhaus_url.tags && result.urlhaus_url.tags.length > 0 && (
                    <div className="pt-1">
                      <span className="text-mist block mb-1">Tags:</span>
                      <div className="flex flex-wrap gap-1">
                        {result.urlhaus_url.tags.map((t, idx) => (
                          <span key={idx} className="px-2 py-0.5 rounded bg-void text-mist text-[10px] border border-border">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-3 bg-void/50 border border-border rounded-xl text-xs text-mist">
                  The exact URL is not listed as active malware in the URLhaus public registry.
                  {result.urlhaus_host.found && (
                    <div className="mt-2 text-amber-400">
                      ⚠️ However, host <span className="font-mono font-bold">{result.host}</span> has {result.urlhaus_host.url_count} other reported malware URLs!
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Heuristic / Structural Analysis */}
            <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <div className="flex items-center gap-2">
                  <span>🔬</span>
                  <h3 className="font-bold text-white text-base">Lexical & Heuristic Flags</h3>
                </div>
                <span className="text-xs text-mist font-mono">
                  Score: {result.heuristics.heuristic_score}
                </span>
              </div>

              {result.heuristics.findings.length > 0 ? (
                <div className="space-y-2">
                  {result.heuristics.findings.map((f, idx) => (
                    <div key={idx} className="p-2.5 bg-void/60 border border-border rounded-xl text-xs text-mist flex items-start gap-2">
                      <span className="text-amber-400">⚠️</span>
                      <span>{f}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 bg-void/50 border border-border rounded-xl text-xs text-emerald-400">
                  No lexical anomalies, homoglyph characters, or high-risk TLDs detected.
                </div>
              )}
            </div>
          </div>

          {/* Redirect Chain Visualization */}
          <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-4">
            <h3 className="font-bold text-white text-base flex items-center gap-2">
              <span>🔀</span> HTTP Redirect Chain ({result.redirect_chain.hops} hops)
            </h3>

            {result.redirect_chain.chain.length > 0 ? (
              <div className="space-y-2">
                {result.redirect_chain.chain.map((hop, idx) => (
                  <div key={idx} className="p-3 bg-void/60 border border-border rounded-xl flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-3 overflow-hidden">
                      <span className="w-5 h-5 rounded-full bg-void border border-border flex items-center justify-center text-[10px] text-mist font-bold shrink-0">
                        {idx + 1}
                      </span>
                      <span className="truncate text-mist hover:text-white transition">{hop.url}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border shrink-0 ${hop.status < 300 ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-amber-500/10 text-amber-400 border-amber-500/20"}`}>
                      HTTP {hop.status}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-mist/60">No redirect chain recorded.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
