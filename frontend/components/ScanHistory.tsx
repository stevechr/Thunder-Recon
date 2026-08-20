"use client";

import { useState, useEffect } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ScanRecord {
  id: number;
  domain: string;
  email: string | null;
  ip: string | null;
  risk_score: number;
  created_at: string;
}

function RiskBadge({ score }: { score: number }) {
  let label = "CRITICAL"; let color = "text-red-400 bg-red-500/15 border-red-500/30";
  if (score <= 30) { label = "LOW"; color = "text-emerald-400 bg-emerald-500/15 border-emerald-500/30"; }
  else if (score <= 55) { label = "MEDIUM"; color = "text-amber-400 bg-amber-500/15 border-amber-500/30"; }
  else if (score <= 75) { label = "HIGH"; color = "text-orange-400 bg-orange-500/15 border-orange-500/30"; }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-lg border text-[10px] font-mono font-bold ${color}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
      {label} ({score})
    </span>
  );
}

function MiniSparkline({ scores }: { scores: number[] }) {
  if (scores.length < 2) return null;
  const max = 100, min = 0;
  const w = 80, h = 24;
  const pts = scores.map((s, i) => {
    const x = (i / (scores.length - 1)) * w;
    const y = h - ((s - min) / (max - min)) * h;
    return `${x},${y}`;
  }).join(" ");
  const last = scores[scores.length - 1];
  const color = last <= 30 ? "#34d399" : last <= 55 ? "#fbbf24" : last <= 75 ? "#fb923c" : "#f87171";
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="opacity-80">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

export default function ScanHistory() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterDomain, setFilterDomain] = useState("");
  const [filterRisk, setFilterRisk] = useState<"all" | "low" | "medium" | "high" | "critical">("all");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detailData, setDetailData] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const email = (() => {
    try {
      const u = localStorage.getItem("thunder_recon_auth_user");
      return u ? JSON.parse(u)?.email : null;
    } catch { return null; }
  })();

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    setLoading(true); setError(null);
    try {
      const url = new URL(`${API_BASE}/api/scan/history`);
      url.searchParams.set("limit", "50");
      if (email) url.searchParams.set("email", email);
      const res = await fetch(url.toString());
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setRecords(await res.json());
    } catch (e: any) {
      setError(e.message || "Failed to load history");
    } finally { setLoading(false); }
  };

  const loadDetail = async (id: number) => {
    if (selectedId === id) { setSelectedId(null); setDetailData(null); return; }
    setSelectedId(id); setDetailLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan/history/${id}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setDetailData(await res.json());
    } catch { setDetailData(null); }
    finally { setDetailLoading(false); }
  };

  // Group by domain to compute sparklines
  const domainMap = new Map<string, number[]>();
  [...records].reverse().forEach(r => {
    if (!domainMap.has(r.domain)) domainMap.set(r.domain, []);
    domainMap.get(r.domain)!.push(r.risk_score);
  });

  const filtered = records.filter(r => {
    if (filterDomain && !r.domain.includes(filterDomain.toLowerCase())) return false;
    if (filterRisk !== "all") {
      const s = r.risk_score;
      if (filterRisk === "low" && s > 30) return false;
      if (filterRisk === "medium" && (s <= 30 || s > 55)) return false;
      if (filterRisk === "high" && (s <= 55 || s > 75)) return false;
      if (filterRisk === "critical" && s <= 75) return false;
    }
    return true;
  });

  const exportCSV = () => {
    const header = "ID,Domain,IP,Email,Risk Score,Scanned At";
    const rows = filtered.map(r =>
      [r.id, r.domain, r.ip || "", r.email || "", r.risk_score, r.created_at].join(",")
    );
    const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "thunder_recon_history.csv"; a.click();
  };

  const avg = records.length ? Math.round(records.reduce((a, r) => a + r.risk_score, 0) / records.length) : 0;
  const highRisk = records.filter(r => r.risk_score > 75).length;

  return (
    <div className="w-full max-w-5xl space-y-5 animate-fadeIn">
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-5">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/30">
                SCAN INTELLIGENCE
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white">📊 Scan History Dashboard</h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Review past reconnaissance scans, track risk trends, and drill into full scan reports.
            </p>
          </div>
          <div className="flex gap-2">
            <button onClick={fetchHistory} className="px-4 py-2 text-xs font-mono border border-panelBorder text-mist hover:text-white rounded-xl transition">
              ↻ Refresh
            </button>
            <button onClick={exportCSV} className="px-4 py-2 text-xs font-mono border border-cyan-signal/40 text-cyan-signal hover:bg-cyan-signal/10 rounded-xl transition">
              ⬇ Export CSV
            </button>
          </div>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Scans", value: records.length, color: "text-white" },
            { label: "Unique Domains", value: domainMap.size, color: "text-cyan-signal" },
            { label: "Avg Risk Score", value: avg, color: avg > 75 ? "text-red-400" : avg > 55 ? "text-orange-400" : avg > 30 ? "text-amber-400" : "text-emerald-400" },
            { label: "Critical Risk", value: highRisk, color: highRisk > 0 ? "text-red-400" : "text-mist/50" },
          ].map(s => (
            <div key={s.label} className="bg-void/60 border border-panelBorder rounded-xl p-4 text-center">
              <div className={`font-display font-extrabold text-2xl ${s.color}`}>{s.value}</div>
              <div className="text-[10px] font-mono text-mist mt-1">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex gap-3 flex-col sm:flex-row">
          <input
            type="text"
            placeholder="Filter by domain..."
            value={filterDomain}
            onChange={e => setFilterDomain(e.target.value)}
            className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-2.5 text-xs font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
          />
          <select
            value={filterRisk}
            onChange={e => setFilterRisk(e.target.value as any)}
            className="bg-void border border-panelBorder rounded-xl px-4 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-cyan-signal/60 transition"
          >
            <option value="all">All Risk Levels</option>
            <option value="low">Low (0–30)</option>
            <option value="medium">Medium (31–55)</option>
            <option value="high">High (56–75)</option>
            <option value="critical">Critical (76+)</option>
          </select>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-amber-400 text-sm border border-amber-400/30 bg-amber-400/10 rounded-xl px-4 py-3 font-mono">
            ⚠ {error} — Make sure the backend is running and you are logged in.
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="flex gap-1.5">
              {[0,1,2].map(i => (
                <div key={i} className="w-2 h-2 rounded-full bg-cyan-signal animate-ping"
                  style={{ animationDelay: `${i*150}ms` }} />
              ))}
            </div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 text-mist/50 font-mono text-sm">
            {records.length === 0 ? "No scan history found. Run your first Domain Recon scan!" : "No records match your filter."}
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map(r => {
              const sparkScores = domainMap.get(r.domain) || [];
              const isExpanded = selectedId === r.id;
              return (
                <div key={r.id} className="border border-panelBorder rounded-xl overflow-hidden">
                  <div
                    className="flex items-center justify-between px-4 py-3 bg-void/40 hover:bg-void/70 cursor-pointer transition gap-3 flex-wrap"
                    onClick={() => loadDetail(r.id)}
                  >
                    <div className="flex items-center gap-3 flex-wrap min-w-0">
                      <span className="text-[10px] font-mono text-mist/50 shrink-0">#{r.id}</span>
                      <span className="font-mono text-sm text-white font-semibold truncate">{r.domain}</span>
                      {r.ip && <span className="text-[11px] font-mono text-mist/60 hidden sm:block">{r.ip}</span>}
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <MiniSparkline scores={sparkScores} />
                      <RiskBadge score={r.risk_score} />
                      <span className="text-[10px] font-mono text-mist/50 hidden sm:block">
                        {new Date(r.created_at).toLocaleString()}
                      </span>
                      <span className={`text-xs text-mist/60 transition-transform ${isExpanded ? "rotate-180" : ""}`}>▼</span>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="px-4 py-4 bg-void/20 border-t border-panelBorder/60 space-y-3">
                      {detailLoading ? (
                        <div className="text-center font-mono text-xs text-mist py-4">Loading scan data...</div>
                      ) : detailData ? (
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                          <div className="bg-panel/60 p-3 rounded-xl border border-panelBorder space-y-1">
                            <div className="text-[10px] text-mist uppercase tracking-wider font-bold">Domain Info</div>
                            <div className="text-white">{detailData.domain}</div>
                            <div className="text-mist/70">IP: {detailData.ip || "—"}</div>
                            <div className="text-mist/70">Ports: {detailData.ports?.length || 0} open</div>
                          </div>
                          <div className="bg-panel/60 p-3 rounded-xl border border-panelBorder space-y-1">
                            <div className="text-[10px] text-mist uppercase tracking-wider font-bold">SSL / Security</div>
                            <div className="text-white">{detailData.ssl?.grade || detailData.ssl?.valid ? "✅ Valid SSL" : "❌ SSL Issues"}</div>
                            <div className="text-mist/70">Protocol: {detailData.ssl?.protocol || "—"}</div>
                          </div>
                          <div className="bg-panel/60 p-3 rounded-xl border border-panelBorder space-y-1">
                            <div className="text-[10px] text-mist uppercase tracking-wider font-bold">Risk Assessment</div>
                            <RiskBadge score={r.risk_score} />
                            <div className="text-mist/70 text-[10px] mt-1">Scanned: {new Date(r.created_at).toLocaleString()}</div>
                          </div>
                        </div>
                      ) : (
                        <div className="text-center font-mono text-xs text-mist/50 py-4">Could not load full scan data.</div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
