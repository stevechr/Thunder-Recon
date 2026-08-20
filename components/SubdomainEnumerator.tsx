"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface SubdomainResult {
  subdomain: string;
  ip?: string;
  resolved: boolean;
  cname?: string;
  takeover_candidate?: string;
  http_status?: number;
  https?: boolean;
  redirect?: string;
  server?: string;
  source: string;
}

interface SubdomainData {
  domain: string;
  total_discovered: number;
  live_count: number;
  takeover_candidates: number;
  passive_ct_names: number;
  wordlist_size: number;
  subdomains: SubdomainResult[];
}

function getStatusColor(status?: number | null) {
  if (!status) return "text-mist/40";
  if (status < 300) return "text-emerald-400";
  if (status < 400) return "text-amber-400";
  if (status < 500) return "text-orange-400";
  return "text-crimson-risk";
}

function getStatusBg(status?: number | null) {
  if (!status) return "bg-mist/10 border-mist/20";
  if (status < 300) return "bg-emerald-500/10 border-emerald-500/30";
  if (status < 400) return "bg-amber-500/10 border-amber-500/30";
  return "bg-red-500/10 border-red-500/30";
}

export default function SubdomainEnumerator() {
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SubdomainData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "live" | "takeover">("all");
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState(false);

  const sessionToken = (() => {
    try {
      const u = localStorage.getItem("thunder_recon_auth_user");
      return u ? JSON.parse(u)?.session_token : null;
    } catch { return null; }
  })();

  const handleScan = async () => {
    if (!domain.trim()) return;
    if (!authorized) { setError("You must confirm you are authorized to scan this domain."); return; }
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/tools/subdomains`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({ domain: domain.trim(), authorized: true, session_token: sessionToken }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      setResult(await res.json());
    } catch (e: any) {
      setError(e.message || "Enumeration failed");
    } finally { setLoading(false); }
  };

  const exportCSV = () => {
    if (!result) return;
    const header = "Subdomain,IP,HTTP Status,HTTPS,CNAME,Takeover,Server,Source";
    const rows = result.subdomains.map(s =>
      [s.subdomain, s.ip || "", s.http_status || "", s.https ? "Yes" : "No",
       s.cname || "", s.takeover_candidate || "", s.server || "", s.source].join(",")
    );
    const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `subdomains_${result.domain}.csv`; a.click();
  };

  const copyAll = () => {
    if (!result) return;
    const text = result.subdomains.map(s => s.subdomain).join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  };

  const filtered = result?.subdomains.filter(s => {
    if (filter === "live" && !s.http_status) return false;
    if (filter === "takeover" && !s.takeover_candidate) return false;
    if (search && !s.subdomain.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  }) || [];

  return (
    <div className="w-full max-w-5xl space-y-5 animate-fadeIn">
      {/* Header */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-5">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                PASSIVE CT + ACTIVE DNS
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-500/20 text-orange-300 border border-orange-500/30">
                TAKEOVER DETECTION
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🕸️ Subdomain Enumerator
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Dual-source discovery: crt.sh certificate transparency logs + concurrent DNS brute-force.
              Live HTTP probing + cloud takeover candidate detection.
            </p>
          </div>
        </div>

        {/* Input */}
        <div className="space-y-3">
          <div className="flex gap-3 flex-col sm:flex-row">
            <input
              type="text"
              placeholder="example.com"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleScan()}
              className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
            />
            <button
              onClick={handleScan}
              disabled={loading || !domain.trim() || !authorized}
              className="px-6 py-3 bg-cyan-signal text-void rounded-xl font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap"
            >
              {loading ? "Enumerating..." : "⚡ Enumerate"}
            </button>
          </div>

          <label className="flex items-center gap-2.5 text-xs font-mono text-mist cursor-pointer group">
            <div
              onClick={() => setAuthorized(!authorized)}
              className={`w-4 h-4 rounded border flex items-center justify-center transition cursor-pointer ${authorized ? "bg-cyan-signal border-cyan-signal" : "border-panelBorder group-hover:border-cyan-signal/50"}`}
            >
              {authorized && <span className="text-void text-[10px] font-bold">✓</span>}
            </div>
            <span onClick={() => setAuthorized(!authorized)}>
              I confirm I own or am authorized to enumerate this domain
            </span>
          </label>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-crimson-risk text-sm border border-crimson-risk/30 bg-crimson-risk/10 rounded-xl px-4 py-3 font-mono">
            ⚠ {error}
          </div>
        )}

        {loading && (
          <div className="flex flex-col items-center py-10 gap-4">
            <div className="flex gap-1.5">
              {[0,1,2,3,4].map(i => (
                <div key={i} className="w-1.5 h-1.5 rounded-full bg-cyan-signal animate-ping"
                  style={{ animationDelay: `${i*120}ms`, animationDuration: "1.4s" }} />
              ))}
            </div>
            <p className="font-mono text-xs text-cyan-signal animate-pulse">
              Querying crt.sh CT logs + running DNS brute-force (this may take 30–60s)...
            </p>
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-fadeIn">
          {/* Stats Row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "Total Discovered", value: result.total_discovered, color: "text-white" },
              { label: "Live Subdomains", value: result.live_count, color: "text-emerald-400" },
              { label: "Takeover Risks", value: result.takeover_candidates, color: result.takeover_candidates > 0 ? "text-red-400" : "text-mist/50" },
              { label: "CT Log Names", value: result.passive_ct_names, color: "text-cyan-signal" },
            ].map(stat => (
              <div key={stat.label} className="bg-panel border border-panelBorder rounded-xl p-4 text-center">
                <div className={`font-display font-extrabold text-2xl ${stat.color}`}>{stat.value}</div>
                <div className="text-[10px] font-mono text-mist mt-1">{stat.label}</div>
              </div>
            ))}
          </div>

          {/* Takeover Alert */}
          {result.takeover_candidates > 0 && (
            <div className="flex items-start gap-3 p-4 bg-red-500/10 border border-red-500/40 rounded-xl font-mono text-sm text-red-300">
              <span className="text-xl">⚠️</span>
              <div>
                <div className="font-bold text-red-400">{result.takeover_candidates} Subdomain Takeover Candidate{result.takeover_candidates > 1 ? "s" : ""} Detected!</div>
                <div className="text-xs text-red-300/80 mt-1">
                  CNAME records point to unclaimed cloud services. These subdomains may be hijackable.
                </div>
              </div>
            </div>
          )}

          {/* Filter + Search + Export */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-4 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div className="flex gap-1.5">
                {(["all", "live", "takeover"] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition border ${
                      filter === f
                        ? "bg-cyan-signal text-void border-cyan-signal"
                        : "bg-void border-panelBorder text-mist hover:text-white"
                    }`}
                  >
                    {f === "all" ? `All (${result.total_discovered})` : f === "live" ? `Live (${result.live_count})` : `Takeover (${result.takeover_candidates})`}
                  </button>
                ))}
              </div>
              <div className="flex gap-2">
                <button onClick={copyAll} className="px-3 py-1.5 text-xs font-mono border border-panelBorder text-mist hover:text-white rounded-lg transition">
                  {copied ? "✓ Copied" : "📋 Copy All"}
                </button>
                <button onClick={exportCSV} className="px-3 py-1.5 text-xs font-mono border border-cyan-signal/40 text-cyan-signal hover:bg-cyan-signal/10 rounded-lg transition">
                  ⬇ Export CSV
                </button>
              </div>
            </div>

            <input
              type="text"
              placeholder="Search subdomains..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-void border border-panelBorder rounded-xl px-4 py-2.5 text-xs font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
            />

            {/* Table */}
            <div className="overflow-x-auto rounded-xl border border-panelBorder">
              <table className="w-full text-xs font-mono">
                <thead className="bg-void/60">
                  <tr className="text-left text-[10px] text-mist uppercase tracking-wider">
                    <th className="px-4 py-3">Subdomain</th>
                    <th className="px-3 py-3">IP</th>
                    <th className="px-3 py-3">Status</th>
                    <th className="px-3 py-3">Server</th>
                    <th className="px-3 py-3">Source</th>
                    <th className="px-3 py-3">Flags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-panelBorder/40">
                  {filtered.length === 0 ? (
                    <tr><td colSpan={6} className="px-4 py-8 text-center text-mist/50">No results match the current filter.</td></tr>
                  ) : filtered.map((s, i) => (
                    <tr key={i} className={`hover:bg-void/40 transition ${s.takeover_candidate ? "bg-red-500/5" : ""}`}>
                      <td className="px-4 py-2.5">
                        <a
                          href={`https://${s.subdomain}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-cyan-signal hover:underline truncate block max-w-xs"
                        >
                          {s.subdomain}
                        </a>
                      </td>
                      <td className="px-3 py-2.5 text-mist/80">{s.ip || "—"}</td>
                      <td className="px-3 py-2.5">
                        {s.http_status ? (
                          <span className={`font-bold ${getStatusColor(s.http_status)}`}>
                            {s.http_status}
                          </span>
                        ) : <span className="text-mist/40">—</span>}
                      </td>
                      <td className="px-3 py-2.5 text-mist/70 truncate max-w-[120px]">{s.server || "—"}</td>
                      <td className="px-3 py-2.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${s.source === "crt.sh" ? "bg-violet-500/20 text-violet-300" : "bg-cyan-signal/10 text-cyan-signal"}`}>
                          {s.source}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 space-x-1">
                        {s.takeover_candidate && (
                          <span className="px-1.5 py-0.5 bg-red-500/20 text-red-300 border border-red-500/30 rounded text-[10px] font-bold">
                            ⚠️ TAKEOVER: {s.takeover_candidate}
                          </span>
                        )}
                        {s.https && <span className="text-emerald-400">🔒</span>}
                        {s.redirect && <span className="text-amber-400" title={`→ ${s.redirect}`}>↪</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
