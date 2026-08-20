"use client";

import { useState } from "react";

interface DiffCategory {
  category: string;
  icon: string;
  items: {
    name: string;
    targetA: string;
    targetB: string;
    diffStatus: "MATCH" | "MODIFIED" | "ADDED" | "REMOVED" | "REGRESSION";
    riskNote?: string;
  }[];
}

export default function AttackSurfaceDiff() {
  const [targetA, setTargetA] = useState("api.production.target.com");
  const [targetB, setTargetB] = useState("api.staging.target.com");
  const [loading, setLoading] = useState(false);
  const [diffRun, setDiffRun] = useState(false);
  const [filter, setFilter] = useState<"all" | "changes" | "regressions">("all");

  const sampleDiffs: DiffCategory[] = [
    {
      category: "Network Perimeter & Ports",
      icon: "🔌",
      items: [
        { name: "Port 80 (HTTP)", targetA: "Open (Redirects 301)", targetB: "Open (HTTP 200)", diffStatus: "MODIFIED", riskNote: "Target B does not enforce automatic HTTPS redirect." },
        { name: "Port 443 (HTTPS)", targetA: "Open (TLS 1.3)", targetB: "Open (TLS 1.2 / 1.3)", diffStatus: "MATCH" },
        { name: "Port 8080 (Debug Alt)", targetA: "Filtered / Closed", targetB: "OPEN (Sprint Boot Actuator)", diffStatus: "REGRESSION", riskNote: "🚨 Unauthenticated actuator metrics exposed on Staging perimeter." },
        { name: "Port 22 (SSH)", targetA: "Filtered", targetB: "Filtered", diffStatus: "MATCH" },
        { name: "Port 3306 (MySQL)", targetA: "Closed", targetB: "Closed", diffStatus: "MATCH" },
      ],
    },
    {
      category: "HTTP Security Headers",
      icon: "📋",
      items: [
        { name: "Strict-Transport-Security (HSTS)", targetA: "max-age=31536000; includeSubdomains", targetB: "MISSING", diffStatus: "REGRESSION", riskNote: "Missing HSTS on Target B enables SSL stripping." },
        { name: "Content-Security-Policy (CSP)", targetA: "default-src 'self'", targetB: "MISSING", diffStatus: "REGRESSION", riskNote: "Target B vulnerable to Cross-Site Scripting (XSS)." },
        { name: "X-Frame-Options", targetA: "DENY", targetB: "SAMEORIGIN", diffStatus: "MODIFIED" },
        { name: "X-Content-Type-Options", targetA: "nosniff", targetB: "nosniff", diffStatus: "MATCH" },
      ],
    },
    {
      category: "Email Authentication (DNS)",
      icon: "📧",
      items: [
        { name: "SPF Policy", targetA: "v=spf1 include:_spf.google.com -all", targetB: "v=spf1 include:_spf.google.com ~all", diffStatus: "MODIFIED", riskNote: "Target B uses softfail (~all) instead of strict hardfail (-all)." },
        { name: "DMARC Enforcement", targetA: "p=reject; pct=100", targetB: "p=none", diffStatus: "REGRESSION", riskNote: "Target B DMARC policy is set to monitoring-only." },
        { name: "DKIM Key Size", targetA: "RSA 2048-bit", targetB: "RSA 2048-bit", diffStatus: "MATCH" },
      ],
    },
    {
      category: "TLS & Cryptography",
      icon: "🔐",
      items: [
        { name: "SSL Issuer", targetA: "DigiCert Global Root G2", targetB: "Let's Encrypt Authority X3", diffStatus: "MODIFIED" },
        { name: "Certificate Validity Days Remaining", targetA: "214 Days", targetB: "12 Days", diffStatus: "REGRESSION", riskNote: "⚠️ Staging SSL certificate will expire in less than 2 weeks." },
        { name: "TLS 1.0 / 1.1 Support", targetA: "Disabled", targetB: "Disabled", diffStatus: "MATCH" },
      ],
    },
  ];

  const handleRunDiff = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetA.trim() || !targetB.trim()) return;

    setLoading(true);
    setTimeout(() => {
      setDiffRun(true);
      setLoading(false);
    }, 600);
  };

  const getStatusBadge = (status: string) => {
    if (status === "REGRESSION") return "bg-red-500/20 text-red-400 border-red-500/40";
    if (status === "MODIFIED") return "bg-amber-500/20 text-amber-400 border-amber-500/40";
    if (status === "ADDED") return "bg-cyan-500/20 text-cyan-400 border-cyan-500/40";
    if (status === "REMOVED") return "bg-purple-500/20 text-purple-400 border-purple-500/40";
    return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
  };

  const totalRegressions = sampleDiffs.flatMap(c => c.items).filter(i => i.diffStatus === "REGRESSION").length;
  const totalModifications = sampleDiffs.flatMap(c => c.items).filter(i => i.diffStatus === "MODIFIED").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">⚖️</span>
            Attack Surface Diff & Configuration Drift Engine
          </h2>
          <p className="text-sm text-mist mt-1">
            Compare attack surfaces between Production vs Staging environments or track temporal configuration drift.
          </p>
        </div>
      </div>

      {/* Inputs Form */}
      <form onSubmit={handleRunDiff} className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-[10px] uppercase font-bold text-mist block mb-1">Baseline Target (A) — e.g. Production</label>
            <input
              type="text"
              value={targetA}
              onChange={(e) => setTargetA(e.target.value)}
              placeholder="e.g. app.target.com"
              className="w-full bg-void/60 border border-border focus:border-cyan-500/80 rounded-xl px-4 py-2.5 text-xs text-white font-mono outline-none"
            />
          </div>
          <div>
            <label className="text-[10px] uppercase font-bold text-mist block mb-1">Comparison Target (B) — e.g. Staging or New Release</label>
            <input
              type="text"
              value={targetB}
              onChange={(e) => setTargetB(e.target.value)}
              placeholder="e.g. staging.target.com"
              className="w-full bg-void/60 border border-border focus:border-cyan-500/80 rounded-xl px-4 py-2.5 text-xs text-white font-mono outline-none"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || !targetA.trim() || !targetB.trim()}
          className="w-full sm:w-auto px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20 cursor-pointer"
        >
          {loading ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
              Computing Attack Surface Diff...
            </>
          ) : (
            <>
              <span>⚡</span> Run Attack Surface Diff
            </>
          )}
        </button>
      </form>

      {diffRun && (
        <div className="space-y-6 animate-fadeIn">
          {/* Executive Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-2xl">
              <span className="text-xs text-mist font-bold">Security Regressions</span>
              <div className="text-3xl font-black text-red-400 font-mono mt-1">{totalRegressions}</div>
              <p className="text-[11px] text-red-300/80 mt-0.5">Missing protections on Target B</p>
            </div>

            <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-2xl">
              <span className="text-xs text-mist font-bold">Configuration Drift</span>
              <div className="text-3xl font-black text-amber-400 font-mono mt-1">{totalModifications}</div>
              <p className="text-[11px] text-amber-300/80 mt-0.5">Differences in headers, policies, or ports</p>
            </div>

            <div className="p-4 bg-surface/80 border border-border rounded-2xl">
              <span className="text-xs text-mist font-bold">Parity Score</span>
              <div className="text-3xl font-black text-cyan-400 font-mono mt-1">71%</div>
              <p className="text-[11px] text-mist mt-0.5">Configuration alignment index</p>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex gap-2">
            {[
              { key: "all", label: "All Items" },
              { key: "changes", label: "⚡ All Discrepancies" },
              { key: "regressions", label: "🚨 Security Regressions Only" },
            ].map((f) => (
              <button
                key={f.key}
                onClick={() => setFilter(f.key as any)}
                className={`text-xs px-3 py-1.5 rounded-lg border transition ${
                  filter === f.key
                    ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/40 font-bold"
                    : "bg-surface text-mist border-border hover:text-white"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Diff Tables per Category */}
          <div className="space-y-5">
            {sampleDiffs.map((cat, idx) => {
              const filteredItems = cat.items.filter((i) => {
                if (filter === "regressions") return i.diffStatus === "REGRESSION";
                if (filter === "changes") return i.diffStatus !== "MATCH";
                return true;
              });

              if (filteredItems.length === 0) return null;

              return (
                <div key={idx} className="bg-surface/80 border border-border rounded-2xl overflow-hidden">
                  <div className="p-4 bg-void/60 border-b border-border flex items-center justify-between">
                    <div className="flex items-center gap-2 font-bold text-white text-sm">
                      <span>{cat.icon}</span>
                      <span>{cat.category}</span>
                    </div>
                    <span className="text-xs font-mono text-mist">{filteredItems.length} checked</span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-void/40 border-b border-border/60 text-mist text-[10px] uppercase tracking-wider font-sans">
                        <tr>
                          <th className="py-2.5 px-4 w-1/4">Control / Metric</th>
                          <th className="py-2.5 px-4 w-1/4 text-cyan-400">{targetA} (A)</th>
                          <th className="py-2.5 px-4 w-1/4 text-violet-400">{targetB} (B)</th>
                          <th className="py-2.5 px-4 text-right">Drift Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/40">
                        {filteredItems.map((item, i) => (
                          <tr key={i} className="hover:bg-void/30 transition">
                            <td className="py-3 px-4 font-sans">
                              <div className="font-bold text-white">{item.name}</div>
                              {item.riskNote && <div className="text-[10px] text-amber-400/90 mt-0.5 font-sans">{item.riskNote}</div>}
                            </td>
                            <td className="py-3 px-4 text-mist break-all">{item.targetA}</td>
                            <td className="py-3 px-4 text-mist break-all">{item.targetB}</td>
                            <td className="py-3 px-4 text-right font-sans">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(item.diffStatus)}`}>
                                {item.diffStatus}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
