"use client";

import { useState } from "react";
import { lookupWhois, WhoisResult } from "@/lib/api";

export default function WhoisLookup() {
  const [domain, setDomain]   = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [result, setResult]   = useState<WhoisResult | null>(null);

  const handleLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      setResult(await lookupWhois(domain));
    } catch (err: any) {
      setError(err.message || "WHOIS lookup failed");
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
                REGISTRAR INTEL
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🕵️ WHOIS &amp; Domain Registration Intelligence
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Inspect domain registration details, registrar name, domain age, expiry countdowns, name servers, and abuse contacts.
            </p>
          </div>
        </div>

        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row gap-3">
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
            {loading ? "Querying…" : "WHOIS Lookup"}
          </button>
        </form>

        {/* Quick Samples */}
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-mist pt-1">
          <span>Try samples:</span>
          {["google.com", "microsoft.com", "github.com"].map((d) => (
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
            <div className="font-bold">WHOIS Error</div>
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
            Querying official WHOIS registry servers &amp; parsing domain creation dates…
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slideUp">
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-panelBorder/60 pb-4">
              <div>
                <span className="text-[9px] font-mono text-mist uppercase tracking-widest block">Domain Target</span>
                <div className="font-mono text-2xl font-bold text-white">{result.domain}</div>
                <div className="text-xs font-mono text-mist mt-1">
                  Registrar: <span className="text-cyan-signal font-bold">{result.registrar}</span>
                </div>
              </div>

              {result.is_recently_registered && (
                <span className="text-xs font-mono font-bold px-3 py-1 rounded-xl border bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse">
                  ⚠️ RECENTLY REGISTERED (&lt;30 days old)
                </span>
              )}
            </div>

            {/* Metrics */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">DOMAIN AGE</span>
                <span className="text-white font-bold block text-sm">
                  {result.domain_age_days ? `${result.domain_age_days.toLocaleString()} days` : "Unknown"}
                </span>
                <span className="text-mist text-[11px] block">Created: {result.creation_date}</span>
              </div>

              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">EXPIRATION</span>
                <span className="text-white font-bold block text-sm">
                  {result.days_to_expiry ? `${result.days_to_expiry.toLocaleString()} days remaining` : "Unknown"}
                </span>
                <span className="text-mist text-[11px] block">Expires: {result.expiration_date}</span>
              </div>

              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">ABUSE CONTACT</span>
                <span className="text-cyan-signal font-bold block truncate">
                  {result.abuse_emails[0] || "Not Listed"}
                </span>
                <span className="text-mist text-[11px] block">Updated: {result.updated_date}</span>
              </div>
            </div>

            {/* Name Servers */}
            {result.name_servers.length > 0 && (
              <div className="space-y-1.5 pt-2">
                <span className="text-[9px] font-mono text-mist uppercase tracking-widest block">Authoritative Name Servers</span>
                <div className="flex flex-wrap gap-1.5">
                  {result.name_servers.map((ns, i) => (
                    <span key={i} className="text-xs font-mono bg-void border border-panelBorder/60 px-2.5 py-1 rounded text-white/90">
                      {ns}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
