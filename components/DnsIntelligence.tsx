"use client";

import { useState } from "react";
import { inspectDnsRecords, DnsInspectResult } from "@/lib/api";

export default function DnsIntelligence() {
  const [domain, setDomain]   = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [result, setResult]   = useState<DnsInspectResult | null>(null);
  const [activeTab, setActiveTab] = useState<string>("A");

  const handleInspect = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const data = await inspectDnsRecords(domain);
      setResult(data);
      // Select first non-empty record type
      const firstType = Object.keys(data.records).find((k) => data.records[k].length > 0) || "A";
      setActiveTab(firstType);
    } catch (err: any) {
      setError(err.message || "DNS inspection failed");
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
                DNS MAPPER &amp; AUDITOR
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              📡 Deep DNS Record &amp; Security Audit
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Query A, AAAA, MX, NS, TXT, CAA, SOA, CNAME records, verify DNSSEC validation, and audit mail security policies.
            </p>
          </div>
        </div>

        <form onSubmit={handleInspect} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
          />
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="px-6 py-3 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15 whitespace-nowrap"
          >
            {loading ? "Querying…" : "Inspect DNS"}
          </button>
        </form>

        {/* Quick Samples */}
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-mist pt-1">
          <span>Try samples:</span>
          {["cloudflare.com", "google.com", "microsoft.com", "github.com"].map((d) => (
            <button
              key={d}
              type="button"
              onClick={() => { setDomain(d); }}
              className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white transition"
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-rose-500/10 border border-rose-500/25 rounded-xl text-sm font-mono text-rose-400 animate-fadeIn">
          <span className="shrink-0">⚠</span>
          <div>
            <div className="font-bold">DNS Query Error</div>
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
            Resolving DNS zone records &amp; performing DNSSEC validation checks…
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slideUp">
          {/* Header Banner */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-panelBorder/60 pb-4">
              <div>
                <span className="text-[9px] font-mono text-mist uppercase tracking-widest block">DNS Zone Target</span>
                <div className="font-mono text-2xl font-bold text-white">{result.domain}</div>
                <div className="text-xs font-mono text-mist mt-1">
                  Total Records: <span className="text-cyan-signal font-bold">{result.total_records}</span>
                </div>
              </div>

              <div>
                <span className={`text-xs font-mono font-bold px-3 py-1 rounded-xl border ${
                  result.dnssec_enabled
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/25"
                    : "bg-amber-500/15 text-amber-300 border-amber-500/30"
                }`}>
                  DNSSEC: {result.dnssec_enabled ? "ENABLED & VALIDATED ✓" : "NOT ENABLED ⚠️"}
                </span>
              </div>
            </div>

            {/* DNS Records Tab Switcher */}
            <div className="flex bg-void border border-panelBorder rounded-xl p-1 gap-1 overflow-x-auto">
              {Object.keys(result.records).map((rtype) => {
                const count = result.records[rtype].length;
                return (
                  <button
                    key={rtype}
                    onClick={() => setActiveTab(rtype)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition whitespace-nowrap ${
                      activeTab === rtype
                        ? "bg-cyan-signal text-void shadow-sm"
                        : count > 0
                        ? "text-white/80 hover:bg-panelBorder/40"
                        : "text-mist/40"
                    }`}
                  >
                    {rtype} ({count})
                  </button>
                );
              })}
            </div>

            {/* Active Record List */}
            <div className="space-y-2 pt-1 font-mono text-xs">
              {result.records[activeTab]?.length === 0 ? (
                <div className="text-center py-6 text-mist/50">No {activeTab} records found for this domain.</div>
              ) : (
                result.records[activeTab]?.map((item, idx) => (
                  <div key={idx} className="bg-void/60 border border-panelBorder/50 px-3.5 py-2.5 rounded-xl break-all">
                    {typeof item === "object" ? (
                      <pre className="text-cyan-signal text-[11px] overflow-x-auto whitespace-pre-wrap">
                        {JSON.stringify(item, null, 2)}
                      </pre>
                    ) : (
                      <span className="text-white font-medium">{item}</span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Mail Security Audit */}
          {result.mail_security.findings.length > 0 && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 inline-block">
                ⚠️ MAIL SECURITY &amp; POLICY AUDIT
              </span>
              <div className="space-y-2 font-mono text-xs">
                {result.mail_security.findings.map((f, i) => (
                  <div key={i} className="flex items-start justify-between gap-3 bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl">
                    <div>
                      <span className="text-white font-bold block">{f.title}</span>
                      <span className="text-mist text-[11px] mt-0.5 block">{f.detail}</span>
                    </div>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 shrink-0">
                      {f.level}
                    </span>
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
