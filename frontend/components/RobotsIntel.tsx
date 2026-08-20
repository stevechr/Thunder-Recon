"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface SensitiveProbe {
  path: string;
  url: string;
  status: number;
  content_type: string;
  server: string;
  risk: "HIGH" | "MEDIUM" | "LOW";
  is_accessible: boolean;
}

interface RobotsIntelData {
  domain: string;
  robots: {
    found: boolean;
    url: string;
    raw?: string;
    rules: { user_agent: string; rules: { type: string; path: string }[] }[];
    sitemaps: string[];
    total_disallowed: number;
    all_disallowed_paths: string[];
    sensitive_paths: string[];
    error?: string;
  };
  sitemaps: {
    found: boolean;
    url: string;
    url_count: number;
    urls: { url: string; lastmod: string | null; changefreq: string | null; priority: string | null }[];
    sub_sitemaps: string[];
    is_index: boolean;
  }[];
  total_sitemap_urls: number;
  sensitive_probes: SensitiveProbe[];
  accessible_sensitive_paths: number;
  summary: {
    has_robots: boolean;
    disallowed_count: number;
    sensitive_paths_in_robots: number;
    sitemaps_found: number;
    total_urls_in_sitemaps: number;
    accessible_exposed_paths: number;
  };
}

export default function RobotsIntel() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RobotsIntelData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<"probes" | "robots" | "sitemaps">("probes");

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!clean) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/tools/crawl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: clean }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Crawl failed (HTTP ${res.status})`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to inspect robots and sitemaps.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">🤖</span>
            Robots.txt & Sitemap Intelligence
          </h2>
          <p className="text-sm text-mist mt-1">
            Parse crawler directives, extract hidden sitemap URLs, and probe 30+ sensitive admin & backup routes.
          </p>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="e.g. github.com or example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-full bg-void/60 border border-border/80 focus:border-emerald-500/80 rounded-xl px-4 py-3 text-sm text-white placeholder-mist/40 outline-none transition"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium text-sm rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-emerald-600/20 cursor-pointer disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                Crawling Endpoints...
              </>
            ) : (
              <>
                <span>🕷️</span> Crawl & Probe Routes
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
          {/* Summary Dashboard Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-surface/80 border border-border rounded-xl">
              <div className="text-xs text-mist mb-1">robots.txt</div>
              <div className={`text-xl font-bold font-mono ${result.summary.has_robots ? "text-emerald-400" : "text-mist"}`}>
                {result.summary.has_robots ? "FOUND (200)" : "NOT FOUND"}
              </div>
              <div className="text-[10px] text-mist/60 mt-0.5">{result.summary.disallowed_count} Disallow rules</div>
            </div>

            <div className="p-4 bg-surface/80 border border-border rounded-xl">
              <div className="text-xs text-mist mb-1">Sitemaps Discovered</div>
              <div className="text-xl font-bold text-cyan-400 font-mono">{result.summary.sitemaps_found}</div>
              <div className="text-[10px] text-mist/60 mt-0.5">{result.total_sitemap_urls} indexed URLs</div>
            </div>

            <div className={`p-4 rounded-xl border ${result.summary.sensitive_paths_in_robots > 0 ? "bg-amber-500/10 border-amber-500/30" : "bg-surface/80 border-border"}`}>
              <div className="text-xs text-mist mb-1">Sensitive Paths in robots</div>
              <div className={`text-xl font-bold font-mono ${result.summary.sensitive_paths_in_robots > 0 ? "text-amber-400" : "text-emerald-400"}`}>
                {result.summary.sensitive_paths_in_robots}
              </div>
              <div className="text-[10px] text-mist/60 mt-0.5">Admin / backup / config clues</div>
            </div>

            <div className={`p-4 rounded-xl border ${result.accessible_sensitive_paths > 0 ? "bg-red-500/10 border-red-500/30" : "bg-surface/80 border-border"}`}>
              <div className="text-xs text-mist mb-1">Active Exposed Endpoints</div>
              <div className={`text-xl font-bold font-mono ${result.accessible_sensitive_paths > 0 ? "text-red-400" : "text-emerald-400"}`}>
                {result.accessible_sensitive_paths}
              </div>
              <div className="text-[10px] text-mist/60 mt-0.5">HTTP 200 on sensitive paths</div>
            </div>
          </div>

          {/* Subtabs Selector */}
          <div className="flex gap-2 border-b border-border/40 pb-3">
            {[
              { key: "probes", label: `🎯 Exposed Path Probes (${result.sensitive_probes.length})` },
              { key: "robots", label: `📜 robots.txt Rules (${result.robots.total_disallowed})` },
              { key: "sitemaps", label: `🗺️ Sitemaps (${result.total_sitemap_urls} URLs)` },
            ].map((t) => (
              <button
                key={t.key}
                onClick={() => setActiveSubTab(t.key as any)}
                className={`text-xs px-3.5 py-2 rounded-xl font-medium transition ${
                  activeSubTab === t.key
                    ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                    : "bg-surface/60 text-mist hover:text-white border border-transparent"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Probes View */}
          {activeSubTab === "probes" && (
            <div className="space-y-4">
              {result.sensitive_probes.length > 0 ? (
                <div className="bg-surface/80 border border-border rounded-2xl overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-void/70 border-b border-border text-mist uppercase text-[10px] tracking-wider font-sans">
                        <tr>
                          <th className="py-3 px-4">Probe Path</th>
                          <th className="py-3 px-4">HTTP Status</th>
                          <th className="py-3 px-4">Content-Type</th>
                          <th className="py-3 px-4">Exposure Level</th>
                          <th className="py-3 px-4 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/40">
                        {result.sensitive_probes.map((p, idx) => (
                          <tr key={idx} className="hover:bg-void/30 transition">
                            <td className="py-3 px-4 text-white font-bold">{p.path}</td>
                            <td className="py-3 px-4">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                  p.status === 200
                                    ? "bg-red-500/20 text-red-400 border-red-500/30"
                                    : p.status === 403
                                    ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                                    : "bg-mist/10 text-mist border-mist/20"
                                }`}
                              >
                                HTTP {p.status}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-mist truncate max-w-xs">{p.content_type || "N/A"}</td>
                            <td className="py-3 px-4 font-sans">
                              {p.is_accessible ? (
                                <span className="text-red-400 font-bold flex items-center gap-1">
                                  <span>🚨</span> EXPOSED (200 OK)
                                </span>
                              ) : (
                                <span className="text-mist flex items-center gap-1">
                                  <span>🔒</span> Restricted ({p.status})
                                </span>
                              )}
                            </td>
                            <td className="py-3 px-4 text-right">
                              <a
                                href={p.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs px-2.5 py-1 rounded bg-void hover:bg-void/80 border border-border text-emerald-400 font-sans transition inline-block"
                              >
                                Open ↗
                              </a>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center bg-surface/40 border border-border/40 rounded-2xl text-mist text-xs">
                  None of the tested sensitive paths (e.g. .env, /admin, backup files) were reachable on the target.
                </div>
              )}
            </div>
          )}

          {/* robots.txt View */}
          {activeSubTab === "robots" && (
            <div className="space-y-4">
              {result.robots.found ? (
                <>
                  {result.robots.sensitive_paths.length > 0 && (
                    <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl space-y-2">
                      <div className="text-xs font-bold text-amber-400 flex items-center gap-2">
                        <span>⚠️</span> Sensitive Paths Disclosed in Disallow Directives:
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {result.robots.sensitive_paths.map((sp, i) => (
                          <span key={i} className="px-2.5 py-1 bg-void font-mono text-xs text-amber-300 rounded border border-border">
                            {sp}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-3">
                    <h3 className="font-bold text-white text-sm">Raw robots.txt Content</h3>
                    <pre className="p-4 bg-void/80 border border-border rounded-xl font-mono text-xs text-mist overflow-x-auto max-h-96">
                      {result.robots.raw}
                    </pre>
                  </div>
                </>
              ) : (
                <div className="p-8 text-center bg-surface/40 border border-border/40 rounded-2xl text-mist text-xs">
                  No robots.txt file was found for {result.domain}.
                </div>
              )}
            </div>
          )}

          {/* Sitemaps View */}
          {activeSubTab === "sitemaps" && (
            <div className="space-y-4">
              {result.sitemaps.length > 0 ? (
                result.sitemaps.map((sm, idx) => (
                  <div key={idx} className="bg-surface/80 border border-border rounded-2xl p-5 space-y-3">
                    <div className="flex items-center justify-between border-b border-border/40 pb-3">
                      <div className="flex items-center gap-2">
                        <span>🗺️</span>
                        <span className="font-mono text-xs text-cyan-400 break-all">{sm.url}</span>
                      </div>
                      <span className="text-xs px-2.5 py-0.5 rounded bg-void border border-border text-mist font-mono">
                        {sm.url_count} URLs
                      </span>
                    </div>

                    <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                      {sm.urls.map((u, i) => (
                        <div key={i} className="p-2 bg-void/50 border border-border rounded-lg text-xs font-mono flex items-center justify-between">
                          <span className="text-mist truncate mr-3">{u.url}</span>
                          {u.lastmod && <span className="text-[10px] text-mist/60 shrink-0 font-sans">{u.lastmod.split("T")[0]}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center bg-surface/40 border border-border/40 rounded-2xl text-mist text-xs">
                  No sitemaps found via robots.txt or default locations (/sitemap.xml).
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
