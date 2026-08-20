"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface EmailSecurityData {
  domain: string;
  overall_grade: "A" | "B" | "C" | "D" | "F";
  spf: {
    found: boolean;
    record: string | null;
    grade: string;
    issues: string[];
    mechanisms: string[];
    all_qualifier: string | null;
    lookup_count?: number;
  };
  dkim: {
    found: boolean;
    selectors_found: {
      selector: string;
      record: string;
      algorithm: string;
      estimated_key_bits: number | null;
      is_revoked: boolean;
    }[];
    selectors_probed: number;
    grade: string;
    issues: string[];
  };
  dmarc: {
    found: boolean;
    record: string | null;
    grade: string;
    policy: string | null;
    subdomain_policy: string | null;
    pct: number | null;
    rua: string | null;
    ruf: string | null;
    issues: string[];
  };
  mx_records: { host: string; priority: number }[];
  has_mx: boolean;
  all_issues: string[];
  issue_count: number;
}

const GRADE_STYLES: Record<string, { badge: string; border: string; text: string }> = {
  A: { badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40", border: "border-emerald-500/30", text: "text-emerald-400" },
  B: { badge: "bg-cyan-500/20 text-cyan-400 border-cyan-500/40", border: "border-cyan-500/30", text: "text-cyan-400" },
  C: { badge: "bg-amber-500/20 text-amber-400 border-amber-500/40", border: "border-amber-500/30", text: "text-amber-400" },
  D: { badge: "bg-orange-500/20 text-orange-400 border-orange-500/40", border: "border-orange-500/30", text: "text-orange-400" },
  F: { badge: "bg-red-500/20 text-red-400 border-red-500/40", border: "border-red-500/30", text: "text-red-400" },
};

export default function EmailSecurity() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EmailSecurityData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!cleanDomain) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/tools/email-security`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: cleanDomain }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Scan failed (HTTP ${res.status})`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to analyze email security.");
    } finally {
      setLoading(false);
    }
  };

  const getGradeStyle = (grade: string = "F") => GRADE_STYLES[grade] || GRADE_STYLES["F"];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-violet-500/10 border border-violet-500/20 text-violet-400">📧</span>
            Email Security & Spoofing Defense
          </h2>
          <p className="text-sm text-mist mt-1">
            Audit SPF, DKIM, DMARC, and MX records to evaluate domain impersonation & spoof resistance.
          </p>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="e.g. google.com, proton.me, paypal.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-full bg-void/60 border border-border/80 focus:border-violet-500/80 rounded-xl px-4 py-3 text-sm text-white placeholder-mist/40 outline-none transition"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="px-6 py-3 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white font-medium text-sm rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-violet-600/20 cursor-pointer disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                Auditing DNS...
              </>
            ) : (
              <>
                <span>🛡️</span> Check Email Defense
              </>
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm flex items-center gap-3">
          <span>⚠️</span> {error}
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Executive Overview Card */}
          <div className={`p-6 rounded-2xl border ${getGradeStyle(result.overall_grade).border} bg-surface/90 backdrop-blur-md relative overflow-hidden`}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <span className="text-xs uppercase tracking-wider font-semibold text-mist">Email Protection Grade</span>
                  <span className="text-xs px-2.5 py-0.5 rounded-full bg-void/60 border border-border text-mist font-mono">
                    {result.domain}
                  </span>
                </div>
                <div className="text-3xl font-black text-white flex items-center gap-4">
                  <span className={`text-5xl font-black px-4 py-1.5 rounded-2xl border ${getGradeStyle(result.overall_grade).badge}`}>
                    {result.overall_grade}
                  </span>
                  <div>
                    <div className="text-base font-semibold text-white">
                      {result.overall_grade === "A" && "Excellent Anti-Spoofing Posture"}
                      {result.overall_grade === "B" && "Good Defense, Minor Gaps"}
                      {result.overall_grade === "C" && "Vulnerable to Partial Spoofing"}
                      {result.overall_grade === "D" && "High Spoofing Risk"}
                      {result.overall_grade === "F" && "Completely Unprotected (Trivial to Spoof)"}
                    </div>
                    <div className="text-xs text-mist mt-0.5">
                      {result.issue_count === 0 ? "No configuration warnings found." : `${result.issue_count} warning(s) detected.`}
                    </div>
                  </div>
                </div>
              </div>

              {/* Protocol status chips */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 bg-void/50 border border-border rounded-xl text-center">
                  <div className="text-xs text-mist mb-1">SPF</div>
                  <div className={`text-sm font-bold ${result.spf.found ? "text-emerald-400" : "text-red-400"}`}>
                    {result.spf.found ? `Grade ${result.spf.grade}` : "Missing"}
                  </div>
                </div>
                <div className="p-3 bg-void/50 border border-border rounded-xl text-center">
                  <div className="text-xs text-mist mb-1">DKIM</div>
                  <div className={`text-sm font-bold ${result.dkim.found ? "text-emerald-400" : "text-red-400"}`}>
                    {result.dkim.found ? `${result.dkim.selectors_found.length} Key(s)` : "Missing"}
                  </div>
                </div>
                <div className="p-3 bg-void/50 border border-border rounded-xl text-center">
                  <div className="text-xs text-mist mb-1">DMARC</div>
                  <div className={`text-sm font-bold ${result.dmarc.found ? "text-emerald-400" : "text-red-400"}`}>
                    {result.dmarc.found ? result.dmarc.policy?.toUpperCase() : "Missing"}
                  </div>
                </div>
              </div>
            </div>

            {/* Issues list if any */}
            {result.all_issues.length > 0 && (
              <div className="mt-5 pt-5 border-t border-border/40">
                <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2">Findings & Recommendations</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {result.all_issues.map((iss, i) => (
                    <div key={i} className="text-xs text-mist/90 bg-void/40 border border-border/40 p-2.5 rounded-lg flex items-start gap-2">
                      <span className="text-amber-400 mt-0.5">⚠️</span>
                      <span>{iss}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* 3 Columns: SPF, DKIM, DMARC */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* SPF Card */}
            <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-lg">📜</span>
                  <h3 className="font-bold text-white text-base">SPF Record</h3>
                </div>
                <span className={`text-xs font-bold px-2 py-0.5 rounded border ${getGradeStyle(result.spf.grade).badge}`}>
                  Grade {result.spf.grade}
                </span>
              </div>

              {result.spf.found ? (
                <>
                  <div className="p-3 bg-void/80 border border-border rounded-xl font-mono text-xs text-emerald-400 break-all">
                    {result.spf.record}
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-border/20 text-mist">
                      <span>All Qualifier:</span>
                      <span className="font-mono text-white font-semibold">{result.spf.all_qualifier || "None"}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-border/20 text-mist">
                      <span>Mechanisms:</span>
                      <span className="font-mono text-white font-semibold">{result.spf.mechanisms.length}</span>
                    </div>
                    <div className="flex justify-between py-1 text-mist">
                      <span>DNS Lookups:</span>
                      <span className="font-mono text-white font-semibold">{result.spf.lookup_count ?? "N/A"} / 10 limit</span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-xs text-red-400">
                  No SPF record published. Anyone on the internet can forge emails claiming to be from @{result.domain}.
                </div>
              )}
            </div>

            {/* DKIM Card */}
            <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🔑</span>
                  <h3 className="font-bold text-white text-base">DKIM Signatures</h3>
                </div>
                <span className={`text-xs font-bold px-2 py-0.5 rounded border ${getGradeStyle(result.dkim.grade).badge}`}>
                  Grade {result.dkim.grade}
                </span>
              </div>

              {result.dkim.found ? (
                <div className="space-y-3">
                  <div className="text-xs text-mist">
                    Found {result.dkim.selectors_found.length} active selector(s) out of {result.dkim.selectors_probed} common probed.
                  </div>
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {result.dkim.selectors_found.map((s, idx) => (
                      <div key={idx} className="p-2.5 bg-void/70 border border-border rounded-xl space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-mono text-cyan-400 font-bold">{s.selector}._domainkey</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-void border border-border text-mist">
                            {s.estimated_key_bits ? `~${s.estimated_key_bits} bit` : s.algorithm}
                          </span>
                        </div>
                        <div className="font-mono text-[10px] text-mist/60 truncate">{s.record}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs text-amber-400">
                  No standard DKIM selectors detected via common probing. If customized, emails may still be signed with non-standard selector names.
                </div>
              )}
            </div>

            {/* DMARC Card */}
            <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🛡️</span>
                  <h3 className="font-bold text-white text-base">DMARC Policy</h3>
                </div>
                <span className={`text-xs font-bold px-2 py-0.5 rounded border ${getGradeStyle(result.dmarc.grade).badge}`}>
                  Grade {result.dmarc.grade}
                </span>
              </div>

              {result.dmarc.found ? (
                <>
                  <div className="p-3 bg-void/80 border border-border rounded-xl font-mono text-xs text-violet-400 break-all">
                    {result.dmarc.record}
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-border/20 text-mist">
                      <span>Enforcement:</span>
                      <span className={`font-mono font-bold ${result.dmarc.policy === "reject" ? "text-emerald-400" : result.dmarc.policy === "quarantine" ? "text-amber-400" : "text-orange-400"}`}>
                        p={result.dmarc.policy} ({result.dmarc.pct}%)
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-border/20 text-mist">
                      <span>Subdomain Policy:</span>
                      <span className="font-mono text-white font-semibold">sp={result.dmarc.subdomain_policy}</span>
                    </div>
                    <div className="flex justify-between py-1 text-mist">
                      <span>RUA Reporting:</span>
                      <span className="font-mono text-white truncate max-w-[140px]">{result.dmarc.rua ? result.dmarc.rua.replace("mailto:", "") : "None"}</span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-xs text-red-400">
                  No DMARC policy found. Receiving mail servers have no instructions on how to handle failed authentication emails.
                </div>
              )}
            </div>
          </div>

          {/* MX Records Section */}
          <div className="bg-surface/80 border border-border rounded-2xl p-5">
            <h3 className="text-base font-bold text-white mb-3 flex items-center gap-2">
              <span>📬</span> Mail Exchange (MX) Servers ({result.mx_records.length})
            </h3>
            {result.mx_records.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                {result.mx_records.map((mx, i) => (
                  <div key={i} className="p-3 bg-void/60 border border-border rounded-xl flex items-center justify-between text-xs">
                    <span className="font-mono text-mist truncate mr-2">{mx.host}</span>
                    <span className="px-2 py-0.5 rounded bg-violet-500/10 text-violet-400 font-bold border border-violet-500/20 shrink-0">
                      Priority {mx.priority}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-mist/60">No MX records configured for this domain.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
