"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface MailboxVerification {
  email: string;
  status: "DELIVERABLE" | "RISKY" | "UNDELIVERABLE";
  verdict: string;
  score: number;
  is_valid_format: boolean;
  domain: string;
  user: string;
  is_disposable: boolean;
  is_free: boolean;
  is_role: boolean;
  has_mx: boolean;
  mx_records: { host: string; priority: number; fallback?: boolean }[];
  smtp_ping: {
    connected: boolean;
    status: string;
    banner?: string;
    primary_host?: string;
  };
  issues: string[];
}

interface EmailSecurityData {
  domain: string;
  query: string;
  is_email_address: boolean;
  mailbox_verification?: MailboxVerification | null;
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
  bimi?: {
    found: boolean;
    record: string | null;
    status: string;
  };
  mta_sts?: {
    found: boolean;
    record: string | null;
    status: string;
  };
  mx_records: { host: string; priority: number; fallback?: boolean }[];
  has_mx: boolean;
  all_issues: string[];
  issue_count: number;
}

const GRADE_STYLES: Record<string, { badge: string; border: string; text: string }> = {
  A: { badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40", border: "border-emerald-500/30", text: "text-emerald-400" },
  B: { badge: "bg-cyan-500/20 text-cyan-400 border-cyan-500/40", border: "border-cyan-500/30", text: "text-cyan-400" },
  C: { badge: "bg-amber-500/20 text-amber-400 border-amber-500/40", border: "border-amber-500/30", text: "text-amber-400" },
  D: { badge: "bg-orange-500/20 text-orange-400 border-orange-500/40", border: "border-orange-500/30", text: "text-orange-400" },
  F: { badge: "bg-rose-500/20 text-rose-400 border-rose-500/40", border: "border-rose-500/30", text: "text-rose-400" },
};

export default function EmailSecurity() {
  const [inputQuery, setInputQuery] = useState("");
  const [activeTab, setActiveTab] = useState<"verifier" | "anti_spoof">("verifier");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EmailSecurityData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (overrideTarget?: string) => {
    const target = (overrideTarget || inputQuery).trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!target) return;

    if (overrideTarget) {
      setInputQuery(overrideTarget);
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/tools/email-security`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: target, email: target, target: target }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Scan failed (HTTP ${res.status})`);
      }

      const data: EmailSecurityData = await res.json();
      setResult(data);

      if (data.is_email_address) {
        setActiveTab("verifier");
      }
    } catch (err: any) {
      setError(err.message || "Failed to analyze email security & deliverability.");
    } finally {
      setLoading(false);
    }
  };

  const getGradeStyle = (grade: string = "F") => GRADE_STYLES[grade] || GRADE_STYLES["F"];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5 font-display">
            <span className="p-2 rounded-xl bg-violet-500/10 border border-violet-500/20 text-violet-400">📧</span>
            Email Verification & Anti-Spoofing Intelligence
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Validate deliverability of email mailboxes, detect disposable burner accounts, test SMTP handshakes, and audit SPF/DKIM/DMARC anti-spoofing postures.
          </p>
        </div>

        {/* Mode Selector Chips */}
        <div className="flex bg-white/[0.04] p-1 rounded-xl border border-white/10 shrink-0">
          <button
            onClick={() => setActiveTab("verifier")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "verifier"
                ? "bg-violet-500/20 text-violet-300 border border-violet-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            ✉️ Mailbox Verifier
          </button>
          <button
            onClick={() => setActiveTab("anti_spoof")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "anti_spoof"
                ? "bg-violet-500/20 text-violet-300 border border-violet-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            🛡️ Domain DNS Defense
          </button>
        </div>
      </div>

      {/* Input Form */}
      <div className="cyber-card rounded-2xl p-5 border border-white/10 bg-[#0C1220]/90 backdrop-blur-md space-y-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400 text-sm">
              {inputQuery.includes("@") ? "✉️" : "🌐"}
            </div>
            <input
              type="text"
              placeholder={activeTab === "verifier" ? "Enter target email address (e.g. security@microsoft.com, user@tempmail.com)" : "Enter domain name (e.g. google.com, cloudflare.com, proton.me)"}
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              className="w-full bg-[#060D1E]/80 border border-white/15 focus:border-violet-500/80 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-slate-500 outline-none transition"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !inputQuery.trim()}
            className="px-6 py-3 bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-500 hover:to-indigo-500 disabled:opacity-50 text-white font-medium text-sm rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-violet-600/25 cursor-pointer disabled:cursor-not-allowed shrink-0"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                <span>Verifying Mail...</span>
              </>
            ) : (
              <>
                <span>⚡</span>
                <span>{inputQuery.includes("@") ? "Verify Mailbox" : "Run Mail Audit"}</span>
              </>
            )}
          </button>
        </form>

        {/* Quick Example Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-400">
          <span className="text-slate-500 font-mono text-[11px]">Quick Tests:</span>
          {[
            { label: "Valid: security@apple.com", target: "security@apple.com" },
            { label: "Valid: contact@google.com", target: "contact@google.com" },
            { label: "Disposable: fake@mailinator.com", target: "fake@mailinator.com" },
            { label: "Domain: cloudflare.com", target: "cloudflare.com" },
          ].map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleScan(preset.target)}
              className="px-2.5 py-1 rounded-lg bg-white/[0.04] hover:bg-white/10 border border-white/10 hover:border-violet-400/40 text-slate-300 text-[11px] font-mono transition"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 text-sm flex items-center gap-3 animate-fadeIn">
          <span>⚠️</span> {error}
        </div>
      )}

      {result && (
        <div className="space-y-6 animate-fadeIn">

          {/* ── SECTION 1: MAILBOX DELIVERABILITY & VERIFICATION CARD (If email queried) ── */}
          {result.mailbox_verification && (
            <div className="cyber-card rounded-2xl p-6 border border-violet-500/30 bg-[#0C1220]/95 backdrop-blur-md shadow-2xl relative overflow-hidden space-y-6">
              
              {/* Header Strip */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-5">
                <div>
                  <div className="flex items-center gap-2.5">
                    <span className="text-xs uppercase tracking-wider font-semibold text-violet-400 font-mono">Mailbox Verification Verdict</span>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-white/5 border border-white/10 text-slate-300 font-mono">
                      {result.mailbox_verification.email}
                    </span>
                  </div>
                  <div className="text-2xl font-bold text-white mt-1 flex items-center gap-3">
                    <span className="font-mono text-cyan-300">{result.mailbox_verification.user}</span>
                    <span className="text-slate-500">@</span>
                    <span className="font-mono text-violet-300">{result.mailbox_verification.domain}</span>
                  </div>
                </div>

                {/* Main Deliverability Status Badge */}
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">Quality Score</div>
                    <div className="text-2xl font-black font-mono text-white">
                      <span className={result.mailbox_verification.score >= 75 ? "text-emerald-400" : result.mailbox_verification.score >= 45 ? "text-amber-400" : "text-rose-400"}>
                        {result.mailbox_verification.score}
                      </span>
                      <span className="text-xs text-slate-500">/100</span>
                    </div>
                  </div>

                  <div className={`px-4 py-2 rounded-xl font-bold text-sm border flex items-center gap-2 ${
                    result.mailbox_verification.status === "DELIVERABLE"
                      ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40 shadow-lg shadow-emerald-500/10"
                      : result.mailbox_verification.status === "RISKY"
                      ? "bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-lg shadow-amber-500/10"
                      : "bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-lg shadow-rose-500/10"
                  }`}>
                    <span>{result.mailbox_verification.status === "DELIVERABLE" ? "✅" : result.mailbox_verification.status === "RISKY" ? "⚠️" : "❌"}</span>
                    <span>{result.mailbox_verification.status}</span>
                  </div>
                </div>
              </div>

              {/* 6-Point Verification Matrix Badges */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {/* 1. Syntax */}
                <div className="p-3.5 bg-white/[0.02] border border-white/10 rounded-xl space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">RFC Syntax</div>
                  <div className={`text-xs font-bold ${result.mailbox_verification.is_valid_format ? "text-emerald-400" : "text-rose-400"}`}>
                    {result.mailbox_verification.is_valid_format ? "✓ Valid Format" : "✗ Illegal Syntax"}
                  </div>
                </div>

                {/* 2. MX Server */}
                <div className="p-3.5 bg-white/[0.02] border border-white/10 rounded-xl space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Mail Exchanger</div>
                  <div className={`text-xs font-bold ${result.mailbox_verification.has_mx ? "text-emerald-400" : "text-rose-400"}`}>
                    {result.mailbox_verification.has_mx ? `✓ ${result.mailbox_verification.mx_records.length} MX Server(s)` : "✗ No MX Found"}
                  </div>
                </div>

                {/* 3. Disposable */}
                <div className="p-3.5 bg-white/[0.02] border border-white/10 rounded-xl space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Burner / Temp</div>
                  <div className={`text-xs font-bold ${result.mailbox_verification.is_disposable ? "text-rose-400" : "text-emerald-400"}`}>
                    {result.mailbox_verification.is_disposable ? "🚨 Burner Temp Mail" : "✓ Permanent"}
                  </div>
                </div>

                {/* 4. Provider Type */}
                <div className="p-3.5 bg-white/[0.02] border border-white/10 rounded-xl space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Provider Type</div>
                  <div className="text-xs font-bold text-cyan-300">
                    {result.mailbox_verification.is_free ? "Free Webmail" : "Custom Domain"}
                  </div>
                </div>

                {/* 5. Role Account */}
                <div className="p-3.5 bg-white/[0.02] border border-white/10 rounded-xl space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Role Account</div>
                  <div className={`text-xs font-bold ${result.mailbox_verification.is_role ? "text-amber-400" : "text-slate-300"}`}>
                    {result.mailbox_verification.is_role ? "⚠️ Role/Group Mail" : "✓ Individual"}
                  </div>
                </div>

                {/* 6. SMTP Ping */}
                <div className="p-3.5 bg-white/[0.02] border border-white/10 rounded-xl space-y-1">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">SMTP Ping</div>
                  <div className={`text-xs font-bold ${result.mailbox_verification.smtp_ping.connected ? "text-emerald-400" : "text-amber-400"}`}>
                    {result.mailbox_verification.smtp_ping.connected ? "✓ Port 25/587 OK" : "⚡ Filtered/Offline"}
                  </div>
                </div>
              </div>

              {/* SMTP Connection & Findings Callout */}
              {result.mailbox_verification.smtp_ping.banner && (
                <div className="p-3 bg-[#060D1E] border border-white/10 rounded-xl font-mono text-xs text-slate-300 flex items-center justify-between gap-2 overflow-x-auto">
                  <span className="text-violet-400 font-bold shrink-0">SMTP Banner:</span>
                  <span className="text-slate-400 truncate">{result.mailbox_verification.smtp_ping.banner}</span>
                  <span className="text-emerald-400 font-bold shrink-0 text-[11px]">ACTIVE</span>
                </div>
              )}

              {/* Issues Warnings */}
              {result.mailbox_verification.issues.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider font-mono">Deliverability Alerts</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {result.mailbox_verification.issues.map((iss, i) => (
                      <div key={i} className="text-xs text-slate-300 bg-amber-500/10 border border-amber-500/20 p-2.5 rounded-xl flex items-start gap-2">
                        <span className="text-amber-400">⚠️</span>
                        <span>{iss}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── SECTION 2: DOMAIN EXECUTIVE OVERVIEW CARD ── */}
          <div className={`p-6 rounded-2xl border ${getGradeStyle(result.overall_grade).border} cyber-card bg-[#0C1220]/90 backdrop-blur-md relative overflow-hidden`}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 font-mono">Domain Anti-Spoofing Defense Posture</span>
                  <span className="text-xs px-2.5 py-0.5 rounded-full bg-white/5 border border-white/10 text-cyan-300 font-mono font-bold">
                    {result.domain}
                  </span>
                </div>
                <div className="text-3xl font-black text-white flex items-center gap-4">
                  <span className={`text-4xl sm:text-5xl font-black px-4 py-1.5 rounded-2xl border font-mono ${getGradeStyle(result.overall_grade).badge}`}>
                    {result.overall_grade}
                  </span>
                  <div>
                    <div className="text-base font-semibold text-white">
                      {result.overall_grade === "A" && "Fortified Anti-Spoofing Posture"}
                      {result.overall_grade === "B" && "Good Protection, Minor Hardening Recommended"}
                      {result.overall_grade === "C" && "Vulnerable to Partial Spoofing & Phishing"}
                      {result.overall_grade === "D" && "High Spoofing Risk (Permissive Policies)"}
                      {result.overall_grade === "F" && "Completely Unprotected (Trivial to Impersonate)"}
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      {result.issue_count === 0 ? "All authentication records properly published." : `${result.issue_count} security warning(s) detected across SPF, DKIM, or DMARC.`}
                    </div>
                  </div>
                </div>
              </div>

              {/* Protocol Status Chips */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-3 bg-[#060D1E]/80 border border-white/10 rounded-xl text-center">
                  <div className="text-[10px] text-slate-400 font-mono mb-0.5">SPF RECORD</div>
                  <div className={`text-sm font-bold font-mono ${result.spf.found ? "text-emerald-400" : "text-rose-400"}`}>
                    {result.spf.found ? `Grade ${result.spf.grade}` : "Missing"}
                  </div>
                </div>
                <div className="p-3 bg-[#060D1E]/80 border border-white/10 rounded-xl text-center">
                  <div className="text-[10px] text-slate-400 font-mono mb-0.5">DKIM KEYS</div>
                  <div className={`text-sm font-bold font-mono ${result.dkim.found ? "text-emerald-400" : "text-amber-400"}`}>
                    {result.dkim.found ? `${result.dkim.selectors_found.length} Key(s)` : "Unpublished"}
                  </div>
                </div>
                <div className="p-3 bg-[#060D1E]/80 border border-white/10 rounded-xl text-center">
                  <div className="text-[10px] text-slate-400 font-mono mb-0.5">DMARC POLICY</div>
                  <div className={`text-sm font-bold font-mono ${result.dmarc.found ? "text-emerald-400" : "text-rose-400"}`}>
                    {result.dmarc.found ? `p=${result.dmarc.policy}` : "Missing"}
                  </div>
                </div>
                <div className="p-3 bg-[#060D1E]/80 border border-white/10 rounded-xl text-center">
                  <div className="text-[10px] text-slate-400 font-mono mb-0.5">BIMI & TLS</div>
                  <div className={`text-sm font-bold font-mono ${result.bimi?.found || result.mta_sts?.found ? "text-cyan-300" : "text-slate-400"}`}>
                    {result.bimi?.found ? "BIMI Active" : result.mta_sts?.found ? "MTA-STS Active" : "Standard"}
                  </div>
                </div>
              </div>
            </div>

            {/* Issues list if any */}
            {result.all_issues.length > 0 && (
              <div className="mt-5 pt-5 border-t border-white/10">
                <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-2 font-mono">Domain Infrastructure Findings</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {result.all_issues.map((iss, i) => (
                    <div key={i} className="text-xs text-slate-300 bg-white/[0.02] border border-white/10 p-2.5 rounded-xl flex items-start gap-2">
                      <span className="text-amber-400 mt-0.5">⚠️</span>
                      <span>{iss}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ── SECTION 3: PROTOCOL DRILL-DOWN (SPF, DKIM, DMARC) ── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            
            {/* SPF Card */}
            <div className="cyber-card rounded-2xl p-5 border border-white/10 bg-[#0C1220]/90 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-lg">📜</span>
                  <h3 className="font-bold text-white text-sm sm:text-base font-display">SPF Record</h3>
                </div>
                <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded border ${getGradeStyle(result.spf.grade).badge}`}>
                  Grade {result.spf.grade}
                </span>
              </div>

              {result.spf.found ? (
                <>
                  <div className="p-3 bg-[#060D1E] border border-white/10 rounded-xl font-mono text-xs text-emerald-400 break-all leading-relaxed">
                    {result.spf.record}
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-white/5 text-slate-400">
                      <span>All Qualifier:</span>
                      <span className="font-mono text-white font-semibold">{result.spf.all_qualifier || "None"}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-white/5 text-slate-400">
                      <span>Authorized Mechanisms:</span>
                      <span className="font-mono text-white font-semibold">{result.spf.mechanisms.length}</span>
                    </div>
                    <div className="flex justify-between py-1 text-slate-400">
                      <span>DNS Lookups:</span>
                      <span className="font-mono text-white font-semibold">{result.spf.lookup_count ?? "N/A"} / 10 limit</span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs text-rose-400">
                  No SPF record published. Anyone on the internet can forge emails claiming to be from @{result.domain}.
                </div>
              )}
            </div>

            {/* DKIM Card */}
            <div className="cyber-card rounded-2xl p-5 border border-white/10 bg-[#0C1220]/90 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🔑</span>
                  <h3 className="font-bold text-white text-sm sm:text-base font-display">DKIM Signatures</h3>
                </div>
                <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded border ${getGradeStyle(result.dkim.grade).badge}`}>
                  Grade {result.dkim.grade}
                </span>
              </div>

              {result.dkim.found ? (
                <div className="space-y-3">
                  <div className="text-xs text-slate-400">
                    Found {result.dkim.selectors_found.length} active selector(s) out of {result.dkim.selectors_probed} common probed.
                  </div>
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {result.dkim.selectors_found.map((s, idx) => (
                      <div key={idx} className="p-2.5 bg-[#060D1E] border border-white/10 rounded-xl space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-mono text-cyan-400 font-bold">{s.selector}._domainkey</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-slate-300 font-mono">
                            {s.estimated_key_bits ? `~${s.estimated_key_bits} bit` : s.algorithm}
                          </span>
                        </div>
                        <div className="font-mono text-[10px] text-slate-400 truncate">{s.record}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs text-amber-400">
                  No standard DKIM selectors detected via common probing. If customized, emails may still be signed with custom selector names.
                </div>
              )}
            </div>

            {/* DMARC Card */}
            <div className="cyber-card rounded-2xl p-5 border border-white/10 bg-[#0C1220]/90 space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-lg">🛡️</span>
                  <h3 className="font-bold text-white text-sm sm:text-base font-display">DMARC Policy</h3>
                </div>
                <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded border ${getGradeStyle(result.dmarc.grade).badge}`}>
                  Grade {result.dmarc.grade}
                </span>
              </div>

              {result.dmarc.found ? (
                <>
                  <div className="p-3 bg-[#060D1E] border border-white/10 rounded-xl font-mono text-xs text-violet-400 break-all leading-relaxed">
                    {result.dmarc.record}
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-white/5 text-slate-400">
                      <span>Enforcement:</span>
                      <span className={`font-mono font-bold ${result.dmarc.policy === "reject" ? "text-emerald-400" : result.dmarc.policy === "quarantine" ? "text-amber-400" : "text-rose-400"}`}>
                        p={result.dmarc.policy} ({result.dmarc.pct}%)
                      </span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-white/5 text-slate-400">
                      <span>Subdomain Policy:</span>
                      <span className="font-mono text-white font-semibold">sp={result.dmarc.subdomain_policy}</span>
                    </div>
                    <div className="flex justify-between py-1 text-slate-400">
                      <span>RUA Reporting:</span>
                      <span className="font-mono text-white truncate max-w-[140px]">{result.dmarc.rua ? result.dmarc.rua.replace("mailto:", "") : "None"}</span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs text-rose-400">
                  No DMARC policy found. Mail servers have no instructions on how to handle failed authentication emails.
                </div>
              )}
            </div>
          </div>

          {/* ── SECTION 4: MX ROUTING MATRIX & ENCRYPTION ── */}
          <div className="cyber-card rounded-2xl p-5 border border-white/10 bg-[#0C1220]/90">
            <h3 className="text-base font-bold text-white mb-3 flex items-center gap-2 font-display">
              <span>📬</span> Mail Exchange (MX) Exchangers & Route Routing ({result.mx_records.length})
            </h3>
            {result.mx_records.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                {result.mx_records.map((mx, i) => (
                  <div key={i} className="p-3 bg-[#060D1E] border border-white/10 rounded-xl flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-300 truncate mr-2">{mx.host}</span>
                    <span className="px-2 py-0.5 rounded bg-violet-500/10 text-violet-400 font-bold border border-violet-500/20 shrink-0 font-mono">
                      Priority {mx.priority}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-slate-500 font-mono">No MX records configured for this domain. Domain cannot receive incoming mail.</div>
            )}
          </div>

        </div>
      )}
    </div>
  );
}
