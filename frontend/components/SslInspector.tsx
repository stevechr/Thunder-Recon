"use client";

import { useState } from "react";
import { inspectSslCert, SslInspectResult } from "@/lib/api";

export default function SslInspector() {
  const [target, setTarget]   = useState("");
  const [port, setPort]       = useState(443);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [result, setResult]   = useState<SslInspectResult | null>(null);

  const handleInspect = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!target.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      setResult(await inspectSslCert(target, port));
    } catch (err: any) {
      setError(err.message || "SSL inspection failed");
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
                TLS AUDITOR
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🔐 SSL / TLS Certificate Inspector
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Inspect SSL/TLS certificate chains, SANs, cipher suites, expiration countdowns, and security vulnerability grades.
            </p>
          </div>
        </div>

        <form onSubmit={handleInspect} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
          />
          <input
            type="number"
            value={port}
            onChange={(e) => setPort(Number(e.target.value) || 443)}
            className="w-24 bg-void border border-panelBorder rounded-xl px-3 py-3 text-sm font-mono text-white text-center focus:outline-none focus:border-cyan-signal/60 transition"
            placeholder="443"
          />
          <button
            type="submit"
            disabled={loading || !target.trim()}
            className="px-6 py-3 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15 whitespace-nowrap"
          >
            {loading ? "Inspecting…" : "Audit SSL"}
          </button>
        </form>

        {/* Quick Samples */}
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-mist pt-1">
          <span>Try samples:</span>
          {["github.com", "google.com", "badssl.com", "expired.badssl.com"].map((host) => (
            <button
              key={host}
              type="button"
              onClick={() => { setTarget(host); setPort(443); }}
              className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white transition"
            >
              {host}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-rose-500/10 border border-rose-500/25 rounded-xl text-sm font-mono text-rose-400 animate-fadeIn">
          <span className="shrink-0">⚠</span>
          <div>
            <div className="font-bold">SSL Inspection Error</div>
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
            Parsing X.509 ASN.1 structure &amp; evaluating cipher security grade…
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slideUp">
          {/* Grade & General Info */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-panelBorder/60 pb-4">
              <div>
                <span className="text-[9px] font-mono text-mist uppercase tracking-widest block">Target Host</span>
                <div className="font-mono text-2xl font-bold text-white flex items-center gap-2">
                  <span>{result.hostname}</span>
                  <span className="text-xs font-mono text-mist">:{result.port}</span>
                </div>
                <div className="text-xs font-mono text-mist mt-1">
                  Issued to: <span className="text-cyan-signal font-bold">{result.subject_cn}</span>
                </div>
              </div>

              <div className="flex flex-col items-start sm:items-end gap-1">
                <div className={`px-4 py-2 rounded-2xl border font-mono font-extrabold text-xl ${
                  result.grade.startsWith("A") ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" :
                  result.grade === "B" || result.grade === "C" ? "bg-amber-500/15 text-amber-300 border-amber-500/30" :
                  "bg-rose-500/15 text-rose-400 border-rose-500/30"
                }`}>
                  GRADE: {result.grade}
                </div>
              </div>
            </div>

            {/* Metrics */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">ISSUER CA</span>
                <span className="text-white font-bold block truncate">{result.issuer_cn}</span>
                <span className="text-mist text-[11px] block truncate">Serial: {result.serial_number}</span>
              </div>

              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">EXPIRATION COUNTDOWN</span>
                <span className={`font-bold block text-sm ${result.is_expired ? "text-rose-400" : result.days_until_expiry < 30 ? "text-amber-300" : "text-emerald-400"}`}>
                  {result.is_expired ? `EXPIRED (${Math.abs(result.days_until_expiry)} days ago)` : `${result.days_until_expiry} days remaining`}
                </span>
                <span className="text-mist text-[11px] block">Valid to: {result.valid_to.slice(0, 10)}</span>
              </div>

              <div className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1">
                <span className="text-[9px] text-mist block uppercase tracking-widest">CIPHER &amp; PROTOCOL</span>
                <span className="text-white font-bold block truncate">{result.protocol_version}</span>
                <span className="text-cyan-signal text-[11px] block truncate">{result.cipher_suite} ({result.cipher_bits}-bit)</span>
              </div>
            </div>

            {/* SANs Tag Cloud */}
            {result.sans.length > 0 && (
              <div className="space-y-1.5 pt-2">
                <div className="text-[9px] font-mono text-mist uppercase tracking-widest">
                  Subject Alternative Names (SANs) — {result.total_sans} domains
                </div>
                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto pr-1">
                  {result.sans.map((san, i) => (
                    <span key={i} className="text-[11px] font-mono bg-void border border-panelBorder/60 px-2 py-0.5 rounded text-white/80">
                      {san}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Security Findings */}
          {result.security_checks.length > 0 && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 inline-block">
                ⚠️ SECURITY AUDIT FINDINGS
              </span>
              <div className="space-y-2 font-mono text-xs">
                {result.security_checks.map((chk, i) => (
                  <div key={i} className="flex items-start justify-between gap-3 bg-rose-500/8 border border-rose-500/25 p-3.5 rounded-xl">
                    <div>
                      <span className="text-rose-400 font-bold block">{chk.issue}</span>
                      <span className="text-mist text-[11px] mt-0.5 block">{chk.details}</span>
                    </div>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 shrink-0">
                      {chk.severity}
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
