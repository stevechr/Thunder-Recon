"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface BucketResult {
  provider: string;
  bucket: string;
  url: string;
  path_url: string;
  status: number;
  state: string;
  is_public: boolean;
  risk: "CRITICAL" | "INFO" | "LOW";
}

interface BucketData {
  domain: string;
  brand: string;
  names_tested: number;
  total_probes: number;
  buckets_found: number;
  open_buckets: number;
  private_buckets: number;
  results: BucketResult[];
}

export default function BucketFinder() {
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BucketData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [providerFilter, setProviderFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<"all" | "open" | "private">("all");

  const sessionToken = (() => {
    try {
      const u = localStorage.getItem("thunder_recon_auth_user");
      return u ? JSON.parse(u)?.session_token : null;
    } catch {
      return null;
    }
  })();

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!clean) return;
    if (!authorized) {
      setError("You must confirm you are authorized to search for buckets for this target.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/tools/buckets`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          domain: clean,
          authorized: true,
          session_token: sessionToken,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Search failed (HTTP ${res.status})`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to search for cloud buckets.");
    } finally {
      setLoading(false);
    }
  };

  const filteredResults = result?.results.filter((b) => {
    if (providerFilter !== "all" && !b.provider.toLowerCase().includes(providerFilter.toLowerCase())) {
      return false;
    }
    if (statusFilter === "open" && !b.is_public) return false;
    if (statusFilter === "private" && b.is_public) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">🪣</span>
            Cloud Storage Exposure Finder
          </h2>
          <p className="text-sm text-mist mt-1">
            Search for exposed or misconfigured AWS S3, Google Cloud Storage, Azure Blob, and DO Spaces buckets.
          </p>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="e.g. acme.com or acmecorp"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-full bg-void/60 border border-border/80 focus:border-cyan-500/80 rounded-xl px-4 py-3 text-sm text-white placeholder-mist/40 outline-none transition"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !domain.trim() || !authorized}
            className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium text-sm rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20 cursor-pointer disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                Probing Cloud Providers...
              </>
            ) : (
              <>
                <span>🔍</span> Find Cloud Buckets
              </>
            )}
          </button>
        </div>

        {/* Authorization checkbox */}
        <label className="flex items-start gap-2.5 cursor-pointer text-xs text-mist select-none">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-0.5 rounded border-border bg-void/80 text-cyan-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
          />
          <span>
            I confirm that I own or have explicit permission to test cloud storage assets associated with this organization.
          </span>
        </label>
      </form>

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm flex items-center gap-3">
          <span>⚠️</span> {error}
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-surface/80 border border-border rounded-xl">
              <div className="text-xs text-mist mb-1">Names Tested</div>
              <div className="text-2xl font-bold text-white font-mono">{result.names_tested}</div>
              <div className="text-[10px] text-mist/60 mt-0.5">{result.total_probes} HTTP probes</div>
            </div>

            <div className="p-4 bg-surface/80 border border-border rounded-xl">
              <div className="text-xs text-mist mb-1">Buckets Discovered</div>
              <div className="text-2xl font-bold text-cyan-400 font-mono">{result.buckets_found}</div>
              <div className="text-[10px] text-mist/60 mt-0.5">Across 4 providers</div>
            </div>

            <div className={`p-4 rounded-xl border ${result.open_buckets > 0 ? "bg-red-500/10 border-red-500/30" : "bg-surface/80 border-border"}`}>
              <div className="text-xs text-mist mb-1">Publicly Open (HTTP 200)</div>
              <div className={`text-2xl font-bold font-mono ${result.open_buckets > 0 ? "text-red-400" : "text-emerald-400"}`}>
                {result.open_buckets}
              </div>
              <div className="text-[10px] text-mist/60 mt-0.5">{result.open_buckets > 0 ? "⚠️ Immediate leak risk" : "No open buckets found"}</div>
            </div>

            <div className="p-4 bg-surface/80 border border-border rounded-xl">
              <div className="text-xs text-mist mb-1">Private / Protected (403)</div>
              <div className="text-2xl font-bold text-mist font-mono">{result.private_buckets}</div>
              <div className="text-[10px] text-mist/60 mt-0.5">Existent but authenticated</div>
            </div>
          </div>

          {/* Filters Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-surface/60 border border-border/60 rounded-xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-mist font-medium">Filter:</span>
              {(["all", "open", "private"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`text-xs px-3 py-1.5 rounded-lg border transition ${
                    statusFilter === s
                      ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/40 font-bold"
                      : "bg-void/40 text-mist border-border/60 hover:text-white"
                  }`}
                >
                  {s === "all" ? "All Discovered" : s === "open" ? "🚨 Open Only" : "🔒 Private Only"}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <select
                value={providerFilter}
                onChange={(e) => setProviderFilter(e.target.value)}
                className="bg-void border border-border rounded-lg px-2.5 py-1 text-xs text-mist outline-none"
              >
                <option value="all">All Providers</option>
                <option value="s3">AWS S3</option>
                <option value="google">Google Cloud</option>
                <option value="azure">Azure Blob</option>
                <option value="spaces">DigitalOcean Spaces</option>
              </select>
            </div>
          </div>

          {/* Results Table */}
          {filteredResults && filteredResults.length > 0 ? (
            <div className="bg-surface/80 border border-border rounded-2xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-void/70 border-b border-border text-mist uppercase text-[10px] tracking-wider">
                    <tr>
                      <th className="py-3 px-4">Provider</th>
                      <th className="py-3 px-4">Bucket Name</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Exposure</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40 font-mono">
                    {filteredResults.map((b, i) => (
                      <tr key={i} className="hover:bg-void/30 transition">
                        <td className="py-3 px-4 font-sans text-white font-medium flex items-center gap-2">
                          <span>
                            {b.provider.includes("AWS") ? "🟧" : b.provider.includes("Google") ? "🟦" : b.provider.includes("Azure") ? "🔷" : "🌊"}
                          </span>
                          {b.provider}
                        </td>
                        <td className="py-3 px-4 text-cyan-300 break-all">{b.bucket}</td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              b.status === 200
                                ? "bg-red-500/20 text-red-400 border-red-500/30"
                                : "bg-mist/10 text-mist border-mist/20"
                            }`}
                          >
                            HTTP {b.status} ({b.state})
                          </span>
                        </td>
                        <td className="py-3 px-4 font-sans">
                          {b.is_public ? (
                            <span className="text-red-400 font-bold flex items-center gap-1">
                              <span>🚨</span> PUBLIC READ
                            </span>
                          ) : (
                            <span className="text-mist flex items-center gap-1">
                              <span>🔒</span> Protected
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <a
                            href={b.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs px-2.5 py-1 rounded bg-void hover:bg-void/80 border border-border text-cyan-400 hover:text-cyan-300 font-sans transition inline-block"
                          >
                            Visit URL ↗
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
              No matching cloud storage buckets found for this filter.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
