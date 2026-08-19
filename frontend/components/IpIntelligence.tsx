"use client";

import { useState } from "react";
import { lookupIpIntel, IpIntelResult } from "@/lib/api";

export default function IpIntelligence() {
  const [target, setTarget]   = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [result, setResult]   = useState<IpIntelResult | null>(null);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!target.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      setResult(await lookupIpIntel(target));
    } catch (err: any) {
      setError(err.message || "IP lookup failed");
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
                THREAT GEOLOCATION
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🌐 IP Geolocation &amp; Threat Intelligence
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Inspect any IP address or domain for geographic location, ASN / ISP details, reverse DNS, VPN/Tor proxy detection, and threat score.
            </p>
          </div>
        </div>

        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="Enter IP (e.g. 8.8.8.8) or domain (e.g. cloudflare.com)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
          />
          <button
            type="submit"
            disabled={loading || !target.trim()}
            className="px-6 py-3 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15 whitespace-nowrap"
          >
            {loading ? "Locating…" : "Lookup IP"}
          </button>
        </form>

        {/* Quick Samples */}
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-mist pt-1">
          <span>Try samples:</span>
          {["1.1.1.1", "8.8.8.8", "github.com", "93.184.216.34"].map((ip) => (
            <button
              key={ip}
              type="button"
              onClick={() => { setTarget(ip); }}
              className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white transition"
            >
              {ip}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-rose-500/10 border border-rose-500/25 rounded-xl text-sm font-mono text-rose-400 animate-fadeIn">
          <span className="shrink-0">⚠</span>
          <div>
            <div className="font-bold">Lookup Error</div>
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
            Tracing satellite coordinates, ASN registry, and proxy intelligence databases…
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slideUp">
          {/* Main Target Banner */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-panelBorder/60 pb-4">
              <div>
                <span className="text-[9px] font-mono text-mist uppercase tracking-widest block">Resolved IP Address</span>
                <div className="font-mono text-2xl font-bold text-white flex items-center gap-2">
                  <span>{result.resolved_ip}</span>
                  {result.country_code && (
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-void border border-panelBorder text-cyan-signal">
                      {result.country_code}
                    </span>
                  )}
                </div>
                <div className="text-xs font-mono text-mist mt-1">
                  PTR / Reverse DNS: <span className="text-white/80">{result.reverse_dns}</span>
                </div>
              </div>

              <div className="flex flex-col items-start sm:items-end gap-1">
                <span className={`text-xs font-mono font-bold px-3 py-1 rounded-xl border ${
                  result.risk_score >= 40
                    ? "bg-rose-500/15 text-rose-400 border-rose-500/30"
                    : result.risk_score >= 20
                    ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/25"
                }`}>
                  THREAT SCORE: {result.risk_score}/100 • {result.threat_rating}
                </span>
              </div>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">GEOLOCATION</span>
                <span className="text-white font-bold block">{result.city}, {result.region}</span>
                <span className="text-mist text-[11px] block">{result.country} ({result.timezone})</span>
              </div>

              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">NETWORK OPERATOR</span>
                <span className="text-white font-bold block truncate">{result.isp}</span>
                <span className="text-cyan-signal text-[11px] block truncate">{result.asn}</span>
              </div>

              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">NODE TYPE</span>
                <div className="flex flex-wrap gap-1.5 pt-0.5">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                    result.is_proxy ? "bg-rose-500/20 text-rose-400 border-rose-500/40" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/25"
                  }`}>
                    {result.is_proxy ? "VPN / PROXY" : "DIRECT / CLEAN"}
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                    result.is_hosting ? "bg-amber-500/15 text-amber-300 border-amber-500/30" : "bg-void text-mist border-panelBorder"
                  }`}>
                    {result.is_hosting ? "DATACENTER" : "RESIDENTIAL"}
                  </span>
                </div>
              </div>
            </div>

            {/* Coordinates / Map Pin Info */}
            <div className="flex items-center justify-between bg-void/40 px-4 py-2.5 rounded-xl border border-panelBorder/40 text-xs font-mono">
              <span className="text-mist">GPS Coordinates:</span>
              <span className="text-cyan-signal font-bold">
                {result.latitude.toFixed(4)}, {result.longitude.toFixed(4)}
              </span>
            </div>
          </div>

          {/* Threat Factors */}
          {result.threat_factors.length > 0 && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 inline-block">
                ⚠️ ANOMALY INDICATORS
              </span>
              <div className="space-y-2 font-mono text-xs">
                {result.threat_factors.map((tf, i) => (
                  <div key={i} className="flex items-start justify-between gap-3 bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl">
                    <div>
                      <span className="text-white font-bold block">{tf.type}</span>
                      <span className="text-mist text-[11px] mt-0.5 block">{tf.detail}</span>
                    </div>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 shrink-0">
                      {tf.severity}
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
