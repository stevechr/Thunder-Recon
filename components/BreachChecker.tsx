"use client";

import { useState } from "react";
import { checkEmailBreach, checkPasswordPwned, EmailBreachResult, PasswordPwnedResult } from "@/lib/api";

type Tab = "email" | "password";

function RiskBadge({ level, pwned }: { level: string; pwned: boolean }) {
  return (
    <span className={`inline-block px-3 py-1 text-xs font-mono font-bold rounded-full ${
      pwned ? "bg-crimson-risk text-white" : "bg-emerald-500 text-void"
    }`}>
      {level}
    </span>
  );
}

export default function BreachChecker() {
  const [activeTab, setActiveTab]       = useState<Tab>("email");
  const [emailInput, setEmailInput]     = useState("");
  const [passwordInput, setPasswordInput] = useState("");
  const [emailResult, setEmailResult]   = useState<EmailBreachResult | null>(null);
  const [passwordResult, setPasswordResult] = useState<PasswordPwnedResult | null>(null);
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState<string | null>(null);
  const [showPw, setShowPw]             = useState(false);

  const resetState = () => { setError(null); setEmailResult(null); setPasswordResult(null); };

  const handleEmailSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailInput.trim()) return;
    setLoading(true); resetState();
    try { setEmailResult(await checkEmailBreach(emailInput.trim())); }
    catch (err: any) { setError(err.message || "Failed to query breach database"); }
    finally { setLoading(false); }
  };

  const handlePasswordCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passwordInput) return;
    setLoading(true); resetState();
    try { setPasswordResult(await checkPasswordPwned(passwordInput)); }
    catch (err: any) { setError(err.message || "Failed to check password hash"); }
    finally { setLoading(false); }
  };

  return (
    <div className="w-full max-w-4xl space-y-5 animate-fadeIn">

      {/* Header */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl">
        <div className="flex items-start justify-between gap-4 flex-wrap mb-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-crimson-risk/20 text-rose-300 border border-crimson-risk/30">
                BREACH INTELLIGENCE
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white">⚡ Advanced Breach &amp; Leak Engine</h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-lg">
              Search 15B+ leaked credentials, compromised identity records, and pwned passwords across 770+ breach compilations.
            </p>
          </div>
          {/* Tab toggle */}
          <div className="flex bg-void border border-panelBorder rounded-xl p-1 gap-1">
            {([
              { key: "email",    label: "📧 Email & Identity" },
              { key: "password", label: "🔑 Password (k-Anon)" },
            ] as const).map(t => (
              <button key={t.key}
                onClick={() => { setActiveTab(t.key); resetState(); }}
                className={`px-4 py-2 rounded-lg text-xs font-mono font-semibold transition ${
                  activeTab === t.key ? "bg-cyan-signal text-void shadow-sm" : "text-mist hover:text-white"
                }`}>
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* Email tab */}
        {activeTab === "email" && (
          <form onSubmit={handleEmailSearch} className="flex flex-col sm:flex-row gap-3">
            <input
              type="email" value={emailInput}
              onChange={e => setEmailInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleEmailSearch(e as any)}
              placeholder="target@example.com"
              className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
            />
            <button type="submit" disabled={loading || !emailInput.trim()}
              className="px-6 py-3 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15 whitespace-nowrap">
              {loading ? "Searching…" : "Deep Search"}
            </button>
          </form>
        )}

        {/* Password tab */}
        {activeTab === "password" && (
          <div className="space-y-3">
            <form onSubmit={handlePasswordCheck} className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <input
                  type={showPw ? "text" : "password"}
                  value={passwordInput}
                  onChange={e => setPasswordInput(e.target.value)}
                  placeholder="Enter password to check safely"
                  className="w-full bg-void border border-panelBorder rounded-xl px-4 py-3 pr-16 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
                />
                <button type="button" onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-3 text-xs font-mono text-mist hover:text-white transition px-1.5 py-0.5 rounded bg-void border border-panelBorder/60">
                  {showPw ? "Hide" : "Show"}
                </button>
              </div>
              <button type="submit" disabled={loading || !passwordInput}
                className="px-6 py-3 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15 whitespace-nowrap">
                {loading ? "Hashing…" : "Check Password"}
              </button>
            </form>
            <div className="text-[11px] font-mono text-mist/50 flex items-center gap-1.5">
              <span>🔒</span>
              <span><strong className="text-mist/80">k-Anonymity:</strong> Only the first 5 chars of your SHA-1 hash are sent. Your password never leaves your device.</span>
            </div>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-rose-500/10 border border-rose-500/25 rounded-xl text-sm font-mono text-rose-400 animate-fadeIn">
          <span className="shrink-0">⚠</span>
          <div>
            <div className="font-bold">Query Error</div>
            <div className="text-[11px] text-rose-400/70 mt-0.5">{error}</div>
          </div>
          <button onClick={() => setError(null)} className="ml-auto text-rose-400/40 hover:text-rose-400 transition">✕</button>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="bg-panel border border-panelBorder rounded-2xl py-10 flex flex-col items-center gap-3">
          <div className="flex gap-1.5">
            {[0,1,2].map(i => (
              <div key={i} className="w-1.5 h-1.5 rounded-full bg-cyan-signal animate-ping"
                style={{ animationDelay: `${i * 150}ms`, animationDuration: "1.2s" }} />
            ))}
          </div>
          <div className="text-xs font-mono text-cyan-signal animate-blink">
            {activeTab === "email" ? "Searching 15B+ credential records across 770+ breach compilations…" : "Computing k-anonymous SHA-1 prefix hash…"}
          </div>
        </div>
      )}

      {/* Email result */}
      {emailResult && !loading && (
        <div className="space-y-4 animate-slideUp">
          {/* Status banner */}
          <div className={`flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl border ${
            emailResult.is_pwned
              ? "bg-crimson-risk/10 border-crimson-risk/35"
              : "bg-emerald-500/8 border-emerald-500/30"
          }`}>
            <div>
              <div className="text-[9px] font-mono text-mist uppercase tracking-widest mb-1">Target Identity</div>
              <div className="font-mono text-lg font-bold text-white">{emailResult.email}</div>
              <div className="text-xs font-mono text-mist mt-1">
                {emailResult.is_pwned
                  ? `Found in ${emailResult.breaches.length} breach database${emailResult.breaches.length !== 1 ? "s" : ""}`
                  : "Zero compromised records found in indexed datasets"}
              </div>
            </div>
            <div className="flex flex-col items-start sm:items-end gap-2 shrink-0">
              <div className={`font-display text-sm font-extrabold ${emailResult.is_pwned ? "text-crimson-risk" : "text-emerald-400"}`}>
                {emailResult.is_pwned ? `🚨 EXPOSED IN ${emailResult.breach_count} BREACH${emailResult.breach_count !== 1 ? "ES" : ""}` : "✅ CLEAN — NO LEAKS DETECTED"}
              </div>
              <RiskBadge level={emailResult.risk_level} pwned={emailResult.is_pwned} />
            </div>
          </div>

          {/* Analytics */}
          {emailResult.analytics?.risk_score && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 mb-4 inline-block">
                📊 THREAT ANALYTICS
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-3">
                <div className="bg-void/60 border border-panelBorder/50 rounded-xl p-4 font-mono">
                  <div className="text-[9px] text-mist uppercase tracking-widest mb-1">Threat Risk Score</div>
                  <div className="text-2xl font-bold text-amber-warn">{emailResult.analytics.risk_score}<span className="text-sm text-mist font-normal">/100</span></div>
                  <div className="text-xs text-mist mt-0.5">{emailResult.analytics.risk_label}</div>
                </div>
                {emailResult.analytics.password_strength && (
                  <div className="bg-void/60 border border-panelBorder/50 rounded-xl p-4 font-mono">
                    <div className="text-[9px] text-mist uppercase tracking-widest mb-2">Password Leak Strength</div>
                    <div className="space-y-1 text-xs">
                      <div className="flex justify-between">
                        <span className="text-mist">Plaintext exposed</span>
                        <span className="text-crimson-risk font-bold">{emailResult.analytics.password_strength.PlainText || 0}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-mist">Easy to crack</span>
                        <span className="text-amber-warn font-bold">{emailResult.analytics.password_strength.EasyToCrack || 0}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-mist">Strong hash</span>
                        <span className="text-cyan-signal font-bold">{emailResult.analytics.password_strength.StrongHash || 0}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Exposed data types */}
          {emailResult.is_pwned && emailResult.exposed_data_types.length > 0 && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-3">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 inline-block">
                🗂️ COMPROMISED DATA TYPES
              </span>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {emailResult.exposed_data_types.map((dt, i) => (
                  <span key={i} className="px-2.5 py-1 rounded-lg text-xs font-mono bg-crimson-risk/15 text-rose-300 border border-crimson-risk/25">
                    {dt}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Breach cards */}
          {emailResult.is_pwned && emailResult.breaches.length > 0 && (
            <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-crimson-risk/20 text-rose-300 border border-crimson-risk/30 inline-block">
                  📋 BREACH SOURCES ({emailResult.breaches.length})
                </span>
                <span className="text-[10px] font-mono text-mist/50">Sorted by severity</span>
              </div>
              <div className="space-y-2 max-h-[480px] overflow-y-auto pr-1">
                {emailResult.breaches.map((b, idx) => (
                  <div key={idx} className="bg-void/60 border border-panelBorder/50 p-4 rounded-xl hover:border-panelBorder transition">
                    <div className="flex items-center justify-between gap-2 flex-wrap mb-2">
                      <span className="font-display font-bold text-amber-warn text-sm">{b.title || b.name}</span>
                      <div className="flex items-center gap-2">
                        {b.industry && (
                          <span className="text-[10px] font-mono text-cyan-signal bg-cyan-signal/10 border border-cyan-signal/20 px-2 py-0.5 rounded-lg">
                            {b.industry}
                          </span>
                        )}
                        <span className="text-[10px] font-mono text-mist bg-panelBorder/80 px-2.5 py-1 rounded-full">
                          {b.breach_date}
                        </span>
                      </div>
                    </div>
                    <p className="text-mist text-xs leading-relaxed mb-2"
                      dangerouslySetInnerHTML={{ __html: b.description }} />
                    <div className="flex flex-wrap gap-1.5">
                      {b.data_classes.map((dc, i) => (
                        <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded-lg bg-panelBorder/60 text-mist border border-panelBorder/50">
                          {dc}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Password result */}
      {passwordResult && !loading && (
        <div className={`animate-slideUp p-6 rounded-2xl border space-y-4 ${
          passwordResult.pwned
            ? "bg-crimson-risk/10 border-crimson-risk/35"
            : "bg-emerald-500/8 border-emerald-500/30"
        }`}>
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className={`font-display text-base font-bold ${passwordResult.pwned ? "text-crimson-risk" : "text-emerald-400"}`}>
              {passwordResult.pwned ? "⚠️ PASSWORD FOUND IN BREACH DUMPS" : "✅ PASSWORD NOT FOUND IN BREACH DUMPS"}
            </div>
            <RiskBadge level={passwordResult.risk_level} pwned={passwordResult.pwned} />
          </div>

          {passwordResult.pwned ? (
            <div className="space-y-3">
              <p className="text-sm font-mono text-mist">
                This password has been exposed{" "}
                <strong className="text-crimson-risk text-base">{passwordResult.count.toLocaleString()}</strong>{" "}
                times in compromised credential leaks.
              </p>
              <div className="flex items-start gap-2.5 bg-amber-500/10 border border-amber-500/25 px-4 py-3 rounded-xl text-xs font-mono text-amber-300">
                <span>💡</span>
                <span><strong>Immediate action required:</strong> Change this password on every account where it is used. Switch to a unique, randomly generated passphrase.</span>
              </div>
            </div>
          ) : (
            <p className="text-sm font-mono text-mist">{passwordResult.recommendation}</p>
          )}
        </div>
      )}
    </div>
  );
}
