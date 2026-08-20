"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface WafResult {
  domain: string;
  waf_detection: {
    waf_detected: string[];
    waf_protected: boolean;
    payload_blocked: boolean;
    server_banner: string;
    x_powered_by?: string;
    probe_results: { probe_header: string; status: number; blocked: boolean }[];
    response_headers: Record<string, string>;
  };
  http_methods: {
    methods_tested: number;
    risky_methods_found: string[];
    has_risky_methods: boolean;
    results: { method: string; status: number | null; allowed: boolean; risky: boolean }[];
  };
  cors_check: {
    cors_header: string;
    allow_credentials: string;
    is_wildcard: boolean;
    reflects_evil_origin: boolean;
    dangerous_combination: boolean;
    severity: string;
    findings: string[];
  };
  rate_limit: {
    burst_size: number;
    elapsed_seconds: number;
    rate_limited_count: number;
    blocked_count: number;
    rate_limiting_detected: boolean;
    avg_latency_ms: number;
    status_distribution: Record<string, number>;
  };
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    CRITICAL: "text-red-400 bg-red-500/15 border-red-500/30",
    HIGH: "text-orange-400 bg-orange-500/15 border-orange-500/30",
    MEDIUM: "text-amber-400 bg-amber-500/15 border-amber-500/30",
    LOW: "text-blue-400 bg-blue-500/15 border-blue-500/30",
    OK: "text-emerald-400 bg-emerald-500/15 border-emerald-500/30",
  };
  return (
    <span className={`px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${map[severity] || "text-mist bg-mist/10 border-mist/20"}`}>
      {severity}
    </span>
  );
}

function MethodBadge({ method, status, allowed, risky }: { method: string; status: number | null; allowed: boolean; risky: boolean }) {
  return (
    <div className={`p-2 rounded-xl border font-mono text-xs text-center transition ${
      !allowed ? "bg-void/30 border-panelBorder/40 text-mist/40" :
      risky ? "bg-red-500/10 border-red-500/40 text-red-300" :
      "bg-emerald-500/5 border-emerald-500/20 text-emerald-400"
    }`}>
      <div className="font-bold">{method}</div>
      <div className="text-[10px] opacity-70">{status ?? "—"}</div>
      {risky && <div className="text-[10px] text-red-400 font-bold mt-0.5">⚠️ RISKY</div>}
    </div>
  );
}

export default function WafTester() {
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<WafResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sessionToken = (() => {
    try {
      const u = localStorage.getItem("thunder_recon_auth_user");
      return u ? JSON.parse(u)?.session_token : null;
    } catch { return null; }
  })();

  const handleTest = async () => {
    if (!domain.trim() || !authorized) {
      if (!authorized) setError("You must confirm authorization before probing.");
      return;
    }
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/tools/waf`, {
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
      setError(e.message || "WAF test failed");
    } finally { setLoading(false); }
  };

  const waf = result?.waf_detection;
  const methods = result?.http_methods;
  const cors = result?.cors_check;
  const rl = result?.rate_limit;

  return (
    <div className="w-full max-w-4xl space-y-5 animate-fadeIn">
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
              ACTIVE PROBING • AUTHORIZED ONLY
            </span>
          </div>
          <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
            🛡️ WAF / Firewall Tester
          </h2>
          <p className="text-xs text-mist font-mono mt-1 max-w-xl">
            WAF vendor detection, HTTP method fuzzing, CORS misconfiguration, rate-limit detection,
            and server disclosure analysis. Only use on domains you own or have written authorization for.
          </p>
        </div>

        <div className="space-y-3">
          <div className="flex gap-3">
            <input
              type="text"
              placeholder="example.com"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleTest()}
              className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-red-400/60 transition"
            />
            <button
              onClick={handleTest}
              disabled={loading || !domain.trim() || !authorized}
              className="px-6 py-3 bg-red-500 text-white rounded-xl font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-40 whitespace-nowrap"
            >
              {loading ? "Testing..." : "🛡️ Run Test"}
            </button>
          </div>

          <label className="flex items-center gap-2.5 text-xs font-mono text-mist cursor-pointer group">
            <div
              onClick={() => setAuthorized(!authorized)}
              className={`w-4 h-4 rounded border flex items-center justify-center transition cursor-pointer ${authorized ? "bg-red-500 border-red-500" : "border-panelBorder group-hover:border-red-500/50"}`}
            >
              {authorized && <span className="text-white text-[10px] font-bold">✓</span>}
            </div>
            <span onClick={() => setAuthorized(!authorized)}>
              I confirm I own or am authorized to probe this domain
            </span>
          </label>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-crimson-risk text-sm border border-crimson-risk/30 bg-crimson-risk/10 rounded-xl px-4 py-3 font-mono">
            ⚠ {error}
          </div>
        )}

        {loading && (
          <div className="flex flex-col items-center py-8 gap-3">
            <div className="flex gap-1.5">
              {[0,1,2,3].map(i => (
                <div key={i} className="w-2 h-2 rounded-full bg-red-400 animate-ping"
                  style={{ animationDelay: `${i*120}ms` }} />
              ))}
            </div>
            <p className="font-mono text-xs text-red-300 animate-pulse">
              Running WAF probes, HTTP method fuzzer, CORS check, and rate-limit burst...
            </p>
          </div>
        )}
      </div>

      {result && (
        <div className="space-y-4 animate-fadeIn">
          {/* Overview Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-panel border border-panelBorder rounded-xl p-4 text-center">
              <div className="font-display font-extrabold text-lg text-white">
                {waf?.waf_detected?.[0] !== "None detected" ? waf?.waf_detected?.[0] : "—"}
              </div>
              <div className="text-[10px] font-mono text-mist mt-1">WAF Detected</div>
            </div>
            <div className={`bg-panel border rounded-xl p-4 text-center ${waf?.payload_blocked ? "border-red-500/40" : "border-panelBorder"}`}>
              <div className={`font-display font-extrabold text-lg ${waf?.payload_blocked ? "text-red-400" : "text-emerald-400"}`}>
                {waf?.payload_blocked ? "BLOCKED" : "PASSED"}
              </div>
              <div className="text-[10px] font-mono text-mist mt-1">Payload Probes</div>
            </div>
            <div className={`bg-panel border rounded-xl p-4 text-center ${cors?.severity !== "OK" ? "border-amber-500/40" : "border-panelBorder"}`}>
              <SeverityBadge severity={cors?.severity || "OK"} />
              <div className="text-[10px] font-mono text-mist mt-2">CORS Status</div>
            </div>
            <div className={`bg-panel border rounded-xl p-4 text-center ${rl?.rate_limiting_detected ? "border-emerald-500/40" : "border-amber-500/40"}`}>
              <div className={`font-display font-extrabold text-lg ${rl?.rate_limiting_detected ? "text-emerald-400" : "text-amber-400"}`}>
                {rl?.rate_limiting_detected ? "YES" : "NONE"}
              </div>
              <div className="text-[10px] font-mono text-mist mt-1">Rate Limiting</div>
            </div>
          </div>

          {/* WAF Details */}
          {waf && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-4">
              <h3 className="font-display font-bold text-white flex items-center gap-2">🛡️ WAF Detection</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
                <div className="space-y-2">
                  <div className="flex justify-between py-2 border-b border-panelBorder/40">
                    <span className="text-mist font-bold uppercase text-[10px] tracking-wider">Vendors</span>
                    <span className="text-white font-bold">{waf.waf_detected?.join(", ")}</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-panelBorder/40">
                    <span className="text-mist font-bold uppercase text-[10px] tracking-wider">Server</span>
                    <span className="text-white">{waf.server_banner}</span>
                  </div>
                  {waf.x_powered_by && (
                    <div className="flex justify-between py-2 border-b border-panelBorder/40">
                      <span className="text-mist font-bold uppercase text-[10px] tracking-wider">X-Powered-By</span>
                      <span className="text-amber-400">{waf.x_powered_by}</span>
                    </div>
                  )}
                </div>
                <div>
                  <div className="text-[10px] text-mist uppercase tracking-wider font-bold mb-2">Probe Results</div>
                  <div className="space-y-1.5">
                    {waf.probe_results?.map((p, i) => (
                      <div key={i} className={`flex items-center justify-between p-2 rounded-lg border text-[11px] ${p.blocked ? "bg-red-500/10 border-red-500/30 text-red-300" : "bg-void/50 border-panelBorder/50 text-mist"}`}>
                        <span>{p.probe_header}</span>
                        <span className={`font-bold ${p.blocked ? "text-red-400" : "text-emerald-400"}`}>
                          {p.status} {p.blocked ? "⛔ BLOCKED" : "✓"}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* HTTP Methods */}
          {methods && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="font-display font-bold text-white">⚙️ HTTP Method Fuzzer</h3>
                {methods.has_risky_methods && (
                  <span className="text-xs font-mono text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded">
                    ⚠️ Risky methods: {methods.risky_methods_found.join(", ")}
                  </span>
                )}
              </div>
              <div className="grid grid-cols-4 sm:grid-cols-8 gap-2">
                {methods.results?.map(r => (
                  <MethodBadge key={r.method} {...r} />
                ))}
              </div>
            </div>
          )}

          {/* CORS + Rate Limit */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {cors && (
              <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-3">
                <h3 className="font-display font-bold text-white flex items-center justify-between">
                  🔗 CORS Check <SeverityBadge severity={cors.severity} />
                </h3>
                <div className="font-mono text-xs space-y-2">
                  <div className="flex justify-between py-1.5 border-b border-panelBorder/40">
                    <span className="text-mist">CORS Header</span>
                    <span className="text-white">{cors.cors_header}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-panelBorder/40">
                    <span className="text-mist">Allow Credentials</span>
                    <span className={cors.allow_credentials === "true" ? "text-amber-400" : "text-white"}>{cors.allow_credentials}</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-panelBorder/40">
                    <span className="text-mist">Reflects Evil Origin</span>
                    <span className={cors.reflects_evil_origin ? "text-red-400 font-bold" : "text-emerald-400"}>
                      {cors.reflects_evil_origin ? "YES ⚠️" : "No ✓"}
                    </span>
                  </div>
                  {cors.findings?.length > 0 && (
                    <div className="mt-2 p-3 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-300 text-[11px]">
                      {cors.findings[0]}
                    </div>
                  )}
                </div>
              </div>
            )}

            {rl && (
              <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-3">
                <h3 className="font-display font-bold text-white">⚡ Rate Limit Probe</h3>
                <div className="font-mono text-xs space-y-2">
                  <div className="flex justify-between py-1.5 border-b border-panelBorder/40">
                    <span className="text-mist">Burst Size</span>
                    <span className="text-white">{rl.burst_size} requests</span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-panelBorder/40">
                    <span className="text-mist">Rate Limited</span>
                    <span className={rl.rate_limiting_detected ? "text-emerald-400 font-bold" : "text-amber-400"}>
                      {rl.rate_limited_count} / {rl.burst_size} {rl.rate_limiting_detected ? "✓ Protected" : "⚠ Not detected"}
                    </span>
                  </div>
                  <div className="flex justify-between py-1.5 border-b border-panelBorder/40">
                    <span className="text-mist">Avg Latency</span>
                    <span className="text-white">{rl.avg_latency_ms}ms</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-mist">Elapsed</span>
                    <span className="text-white">{rl.elapsed_seconds}s</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {Object.entries(rl.status_distribution || {}).map(([status, count]) => (
                      <span key={status} className="px-2 py-0.5 rounded bg-void border border-panelBorder text-[10px] font-mono text-mist">
                        HTTP {status}: <span className="text-white font-bold">{count}</span>
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
