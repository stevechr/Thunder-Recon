"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface AsnResult {
  query: string;
  query_type: "asn" | "ip";
  ip_info?: any;
  details?: any;
  prefixes?: any;
  peers?: any;
  internet_exchanges?: any;
}

function InfoRow({ label, value }: { label: string; value?: string | number | null }) {
  if (!value) return null;
  return (
    <div className="flex justify-between items-start gap-4 py-2 border-b border-panelBorder/40 last:border-0">
      <span className="text-[11px] font-mono text-mist uppercase tracking-wider font-bold shrink-0">{label}</span>
      <span className="text-xs font-mono text-white text-right break-all">{String(value)}</span>
    </div>
  );
}

export default function AsnIntelligence() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AsnResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "prefixes" | "peers" | "ix">("overview");

  const handleLookup = async () => {
    if (!query.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/tools/asn`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query.trim() }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      setResult(await res.json());
    } catch (e: any) {
      setError(e.message || "Lookup failed");
    } finally { setLoading(false); }
  };

  const d = result?.details;
  const p = result?.prefixes;
  const peers = result?.peers;
  const ix = result?.internet_exchanges;

  return (
    <div className="w-full max-w-4xl space-y-5 animate-fadeIn">
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
              BGP VIEW • FREE API • NO KEY REQUIRED
            </span>
          </div>
          <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
            🌍 ASN & BGP Intelligence
          </h2>
          <p className="text-xs text-mist font-mono mt-1 max-w-xl">
            Lookup any IP or ASN — BGP prefixes, peering relationships, Internet Exchange presence, and abuse contacts.
          </p>
        </div>

        <div className="flex gap-3 flex-col sm:flex-row">
          <input
            type="text"
            placeholder="8.8.8.8 or AS15169 or 15169"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleLookup()}
            className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
          />
          <button
            onClick={handleLookup}
            disabled={loading || !query.trim()}
            className="px-6 py-3 bg-cyan-signal text-void rounded-xl font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-40"
          >
            {loading ? "Querying..." : "🔍 Lookup"}
          </button>
        </div>

        {/* Quick examples */}
        <div className="flex gap-2 flex-wrap">
          <span className="text-[10px] font-mono text-mist/50">Examples:</span>
          {["8.8.8.8", "1.1.1.1", "AS15169", "AS13335", "AS16509"].map(ex => (
            <button
              key={ex}
              onClick={() => { setQuery(ex); }}
              className="text-[10px] font-mono px-2 py-0.5 rounded bg-void border border-panelBorder text-cyan-signal hover:bg-cyan-signal/10 transition"
            >
              {ex}
            </button>
          ))}
        </div>

        {error && (
          <div className="flex items-center gap-2 text-crimson-risk text-sm border border-crimson-risk/30 bg-crimson-risk/10 rounded-xl px-4 py-3 font-mono">
            ⚠ {error}
          </div>
        )}

        {loading && (
          <div className="flex justify-center py-10">
            <div className="flex gap-1.5">
              {[0,1,2].map(i => (
                <div key={i} className="w-2 h-2 rounded-full bg-cyan-signal animate-ping"
                  style={{ animationDelay: `${i*150}ms` }} />
              ))}
            </div>
          </div>
        )}
      </div>

      {result && d && (
        <div className="space-y-4 animate-fadeIn">
          {/* ASN Header Card */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div>
                <div className="font-display font-extrabold text-2xl text-white">AS{d.asn}</div>
                <div className="font-mono font-bold text-cyan-signal text-lg">{d.name}</div>
                <div className="text-xs font-mono text-mist mt-1 max-w-lg">{d.description_short}</div>
              </div>
              <div className="flex items-center gap-3">
                {d.country_code && (
                  <span className="text-2xl" title={d.country_code}>
                    {d.country_code}
                  </span>
                )}
                <div className="text-right">
                  <div className="text-[10px] font-mono text-mist">COUNTRY</div>
                  <div className="font-mono font-bold text-white">{d.country_code || "—"}</div>
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="bg-panel border border-panelBorder rounded-2xl shadow-xl overflow-hidden">
            <div className="flex border-b border-panelBorder">
              {([
                { key: "overview", label: "📋 Overview" },
                { key: "prefixes", label: `🌐 Prefixes (${p?.ipv4_count || 0})` },
                { key: "peers", label: `🔗 Peers (${peers?.ipv4_peers_count || 0})` },
                { key: "ix", label: `🏢 IX (${ix?.ix_count || 0})` },
              ] as const).map(tab => (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className={`px-4 py-3 text-xs font-mono font-semibold transition border-b-2 -mb-px ${
                    activeTab === tab.key
                      ? "text-cyan-signal border-cyan-signal bg-cyan-signal/5"
                      : "text-mist border-transparent hover:text-white"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="p-5">
              {activeTab === "overview" && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <InfoRow label="ASN" value={`AS${d.asn}`} />
                    <InfoRow label="Name" value={d.name} />
                    <InfoRow label="Country" value={d.country_code} />
                    <InfoRow label="Website" value={d.website} />
                    <InfoRow label="Traffic Est." value={d.traffic_estimation} />
                    <InfoRow label="Traffic Ratio" value={d.traffic_ratio} />
                    <InfoRow label="Last Updated" value={d.date_updated} />
                  </div>
                  <div className="space-y-3">
                    {d.email_contacts?.length > 0 && (
                      <div className="bg-void/60 p-3 rounded-xl border border-panelBorder space-y-1">
                        <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold mb-2">Email Contacts</div>
                        {d.email_contacts.map((e: string) => (
                          <div key={e} className="font-mono text-xs text-cyan-signal">{e}</div>
                        ))}
                      </div>
                    )}
                    {d.abuse_contacts?.length > 0 && (
                      <div className="bg-red-500/5 p-3 rounded-xl border border-red-500/20 space-y-1">
                        <div className="text-[10px] font-mono text-red-400 uppercase tracking-wider font-bold mb-2">Abuse Contacts</div>
                        {d.abuse_contacts.map((e: string) => (
                          <div key={e} className="font-mono text-xs text-red-300">{e}</div>
                        ))}
                      </div>
                    )}
                    {result.query_type === "ip" && result.ip_info?.rir_allocation && (
                      <div className="bg-void/60 p-3 rounded-xl border border-panelBorder space-y-1">
                        <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold mb-2">RIR Allocation</div>
                        <InfoRow label="RIR" value={result.ip_info.rir_allocation.rir_name} />
                        <InfoRow label="Prefix" value={result.ip_info.rir_allocation.prefix} />
                        <InfoRow label="Allocated" value={result.ip_info.rir_allocation.date_allocated} />
                      </div>
                    )}
                  </div>
                </div>
              )}

              {activeTab === "prefixes" && p && (
                <div className="space-y-3">
                  <div className="flex gap-4 text-xs font-mono text-mist">
                    <span>IPv4 Prefixes: <span className="text-white font-bold">{p.ipv4_count}</span></span>
                    <span>IPv6 Prefixes: <span className="text-white font-bold">{p.ipv6_count}</span></span>
                  </div>
                  <div className="overflow-x-auto rounded-xl border border-panelBorder">
                    <table className="w-full text-xs font-mono">
                      <thead className="bg-void/60">
                        <tr className="text-left text-[10px] text-mist uppercase tracking-wider">
                          <th className="px-4 py-3">Prefix</th>
                          <th className="px-3 py-3">Name</th>
                          <th className="px-3 py-3">Country</th>
                          <th className="px-3 py-3">CIDR</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-panelBorder/40">
                        {p.ipv4_prefixes?.map((pr: any, i: number) => (
                          <tr key={i} className="hover:bg-void/40 transition">
                            <td className="px-4 py-2.5 font-bold text-cyan-signal">{pr.prefix}</td>
                            <td className="px-3 py-2.5 text-mist/80 truncate max-w-[200px]">{pr.name || "—"}</td>
                            <td className="px-3 py-2.5">{pr.country_code || "—"}</td>
                            <td className="px-3 py-2.5 text-mist/60">/{pr.cidr}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === "peers" && peers && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold mb-3">
                      IPv4 Peers ({peers.ipv4_peers_count})
                    </div>
                    <div className="space-y-1.5 max-h-80 overflow-y-auto">
                      {peers.ipv4_peers?.map((p: any) => (
                        <div key={p.asn} className="bg-void/50 p-2.5 rounded-lg border border-panelBorder/50 font-mono text-xs">
                          <span className="text-cyan-signal font-bold">AS{p.asn}</span>
                          <span className="text-mist/70 ml-2">{p.name}</span>
                          {p.country_code && <span className="text-mist/40 ml-1">({p.country_code})</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold mb-3">
                      IPv6 Peers ({peers.ipv6_peers_count})
                    </div>
                    <div className="space-y-1.5 max-h-80 overflow-y-auto">
                      {peers.ipv6_peers?.map((p: any) => (
                        <div key={p.asn} className="bg-void/50 p-2.5 rounded-lg border border-panelBorder/50 font-mono text-xs">
                          <span className="text-cyan-signal font-bold">AS{p.asn}</span>
                          <span className="text-mist/70 ml-2">{p.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "ix" && ix && (
                <div className="space-y-3">
                  <div className="text-xs font-mono text-mist">
                    Member of <span className="text-white font-bold">{ix.ix_count}</span> Internet Exchange{ix.ix_count !== 1 ? "s" : ""}
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {ix.exchanges?.map((e: any) => (
                      <div key={e.ix_id} className="bg-void/60 p-3 rounded-xl border border-panelBorder space-y-1 font-mono text-xs">
                        <div className="font-bold text-white">{e.name_full || e.name}</div>
                        <div className="text-mist/70">{e.city}, {e.country_code}</div>
                        {e.speed && <div className="text-cyan-signal">{(e.speed / 1000).toFixed(0)} Gbps</div>}
                        {e.ipv4_address && <div className="text-mist/60">IPv4: {e.ipv4_address}</div>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
