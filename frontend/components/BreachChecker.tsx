"use client";

import { useState } from "react";
import { checkEmailBreach, checkPasswordPwned, EmailBreachResult, PasswordPwnedResult } from "@/lib/api";

export default function BreachChecker() {
  const [activeTab, setActiveTab] = useState<"email" | "password">("email");
  const [emailInput, setEmailInput] = useState("");
  const [passwordInput, setPasswordInput] = useState("");
  const [emailResult, setEmailResult] = useState<EmailBreachResult | null>(null);
  const [passwordResult, setPasswordResult] = useState<PasswordPwnedResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPasswordText, setShowPasswordText] = useState(false);

  const handleEmailSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailInput.trim()) return;
    setLoading(true);
    setError(null);
    setEmailResult(null);
    try {
      const res = await checkEmailBreach(emailInput.trim());
      setEmailResult(res);
    } catch (err: any) {
      setError(err.message || "Failed to query breach database");
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passwordInput) return;
    setLoading(true);
    setError(null);
    setPasswordResult(null);
    try {
      const res = await checkPasswordPwned(passwordInput);
      setPasswordResult(res);
    } catch (err: any) {
      setError(err.message || "Failed to check password hash");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-4xl bg-panel border border-panelBorder rounded-xl p-6 shadow-2xl">
      <div className="flex items-center justify-between border-b border-panelBorder pb-4 mb-6">
        <div>
          <h2 className="font-display text-xl md:text-2xl font-bold flex items-center gap-2" style={{ color: "#E8EDF2" }}>
            <span className="text-cyan-signal">⚡</span> Advanced Breach Intelligence & Leak Engine
          </h2>
          <p className="text-mist text-xs md:text-sm mt-1">
            Search 15+ billion leaked credentials, compromised identity records, and pwned passwords across 770+ breach compilations.
          </p>
        </div>
        <div className="flex bg-panelBorder/40 p-1 rounded-lg">
          <button
            onClick={() => { setActiveTab("email"); setError(null); }}
            className={`px-4 py-1.5 text-xs font-mono rounded-md transition ${activeTab === "email" ? "bg-cyan-signal text-void font-bold" : "text-mist hover:text-white"}`}
          >
            Email & Identity Search
          </button>
          <button
            onClick={() => { setActiveTab("password"); setError(null); }}
            className={`px-4 py-1.5 text-xs font-mono rounded-md transition ${activeTab === "password" ? "bg-cyan-signal text-void font-bold" : "text-mist hover:text-white"}`}
          >
            Password Exposure (k-Anon)
          </button>
        </div>
      </div>

      {activeTab === "email" ? (
        <div>
          <form onSubmit={handleEmailSearch} className="flex gap-3 mb-6">
            <input
              type="email"
              value={emailInput}
              onChange={(e) => setEmailInput(e.target.value)}
              placeholder="Enter target email (e.g. user@domain.com)"
              className="flex-1 bg-void border border-panelBorder rounded-lg px-4 py-2.5 text-sm outline-none focus:border-cyan-signal transition text-white placeholder-mist/40 font-mono"
            />
            <button
              type="submit"
              disabled={loading || !emailInput.trim()}
              className="px-6 py-2.5 rounded-lg bg-cyan-signal text-void font-display text-xs md:text-sm font-semibold disabled:opacity-40 hover:brightness-110 transition"
            >
              {loading ? "Analyzing..." : "Deep Search"}
            </button>
          </form>

          {error && (
            <div className="p-4 rounded-lg bg-crimson-risk/10 border border-crimson-risk/30 text-crimson-risk text-sm mb-4 font-mono">
              {error}
            </div>
          )}

          {emailResult && (
            <div className="space-y-5">
              <div className={`p-5 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${emailResult.is_pwned ? "bg-crimson-risk/10 border-crimson-risk/40" : "bg-cyan-signal/10 border-cyan-signal/40"}`}>
                <div>
                  <div className="text-xs uppercase tracking-widest font-mono text-mist">Target Identity</div>
                  <div className="font-mono text-xl font-bold text-white mt-0.5">{emailResult.email}</div>
                  <div className="text-xs text-mist font-mono mt-1">
                    {emailResult.is_pwned ? `Identified in ${emailResult.breaches.length} security breach databases.` : "Zero compromised records found in indexed datasets."}
                  </div>
                </div>
                <div className="text-left md:text-right">
                  <div className={`font-display text-base md:text-lg font-extrabold ${emailResult.is_pwned ? "text-crimson-risk" : "text-cyan-signal"}`}>
                    {emailResult.is_pwned ? `🚨 EXPOSED IN ${emailResult.breach_count} DATA BREACHES` : "✅ CLEAN — NO LEAKS DETECTED"}
                  </div>
                  <span className={`inline-block mt-1 px-3 py-0.5 text-xs font-mono font-bold rounded-md ${emailResult.is_pwned ? "bg-crimson-risk text-white" : "bg-cyan-signal text-void"}`}>
                    {emailResult.risk_level}
                  </span>
                </div>
              </div>

              {/* Analytics summary if available */}
              {emailResult.analytics && emailResult.analytics.risk_score ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-void/60 border border-panelBorder p-4 rounded-lg text-xs">
                  <div>
                    <span className="text-mist font-mono">THREAT RISK SCORE:</span>
                    <div className="text-lg font-mono font-bold text-amber-warn mt-1">
                      {emailResult.analytics.risk_score} / 100 ({emailResult.analytics.risk_label})
                    </div>
                  </div>
                  {emailResult.analytics.password_strength && (
                    <div>
                      <span className="text-mist font-mono">PASSWORD LEAK STRENGTH METRICS:</span>
                      <div className="flex gap-3 mt-1 text-[11px] font-mono text-mist">
                        <span>Plaintext: <strong className="text-crimson-risk">{emailResult.analytics.password_strength.PlainText || 0}</strong></span>
                        <span>Easy Crack: <strong className="text-amber-warn">{emailResult.analytics.password_strength.EasyToCrack || 0}</strong></span>
                        <span>Strong Hash: <strong className="text-cyan-signal">{emailResult.analytics.password_strength.StrongHash || 0}</strong></span>
                      </div>
                    </div>
                  )}
                </div>
              ) : null}

              {emailResult.is_pwned && emailResult.breaches.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs font-mono uppercase tracking-wider text-mist">
                    <span>Compromised Data Sources ({emailResult.breaches.length}):</span>
                    <span>Sorted by Severity</span>
                  </div>

                  {emailResult.exposed_data_types.length > 0 && (
                    <div className="bg-void p-3 rounded-lg border border-panelBorder text-xs">
                      <div className="text-mist font-mono text-[11px] mb-1.5 uppercase">Compromised Attributes across all breaches:</div>
                      <div className="flex flex-wrap gap-1.5">
                        {emailResult.exposed_data_types.map((dt, i) => (
                          <span key={i} className="px-2 py-0.5 rounded bg-crimson-risk/20 text-crimson-risk border border-crimson-risk/30 font-mono text-[11px]">
                            {dt}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                    {emailResult.breaches.map((b, idx) => (
                      <div key={idx} className="bg-void border border-panelBorder p-4 rounded-lg text-sm space-y-2 hover:border-cyan-signal/40 transition">
                        <div className="flex items-center justify-between">
                          <span className="font-display font-bold text-amber-warn text-base">{b.title || b.name}</span>
                          <div className="flex items-center gap-2">
                            {b.industry && (
                              <span className="text-[10px] font-mono text-cyan-signal bg-cyan-signal/10 border border-cyan-signal/20 px-2 py-0.5 rounded">
                                {b.industry}
                              </span>
                            )}
                            <span className="text-xs font-mono text-mist bg-panelBorder px-2.5 py-1 rounded-full">{b.breach_date}</span>
                          </div>
                        </div>
                        <p className="text-mist text-xs leading-relaxed" dangerouslySetInnerHTML={{ __html: b.description }} />
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {b.data_classes.map((dc, i) => (
                            <span key={i} className="text-[11px] font-mono px-2 py-0.5 rounded bg-panelBorder text-mist border border-panelBorder">
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
        </div>
      ) : (
        <div>
          <form onSubmit={handlePasswordCheck} className="space-y-3 mb-6">
            <div className="flex gap-3">
              <div className="relative flex-1">
                <input
                  type={showPasswordText ? "text" : "password"}
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  placeholder="Enter password to check exposure safely"
                  className="w-full bg-void border border-panelBorder rounded-lg px-4 py-2.5 text-sm outline-none focus:border-cyan-signal transition text-white placeholder-mist/40 font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPasswordText(!showPasswordText)}
                  className="absolute right-3 top-2.5 text-xs text-mist hover:text-white"
                >
                  {showPasswordText ? "Hide" : "Show"}
                </button>
              </div>
              <button
                type="submit"
                disabled={loading || !passwordInput}
                className="px-6 py-2.5 rounded-lg bg-cyan-signal text-void font-display text-xs md:text-sm font-semibold disabled:opacity-40 hover:brightness-110 transition"
              >
                {loading ? "Hashing..." : "Check Password"}
              </button>
            </div>
            <div className="text-[11px] text-mist/70 font-mono">
              🔒 <strong>k-Anonymity Security:</strong> Your plain password NEVER leaves your browser. Only the first 5 characters of its SHA-1 hash are queried against the HIBP range API.
            </div>
          </form>

          {error && (
            <div className="p-4 rounded-lg bg-crimson-risk/10 border border-crimson-risk/30 text-crimson-risk text-sm mb-4 font-mono">
              {error}
            </div>
          )}

          {passwordResult && (
            <div className={`p-5 rounded-lg border space-y-3 ${passwordResult.pwned ? "bg-crimson-risk/10 border-crimson-risk/40" : "bg-cyan-signal/10 border-cyan-signal/40"}`}>
              <div className="flex items-center justify-between">
                <div className="font-display font-bold text-lg text-white">
                  {passwordResult.pwned ? "⚠️ PASSWORD EXPOSED IN BREACHES!" : "✅ PASSWORD NOT FOUND IN BREACH DUMPS"}
                </div>
                <span className={`px-3 py-1 text-xs font-mono font-bold rounded-full ${passwordResult.pwned ? "bg-crimson-risk text-white" : "bg-cyan-signal text-void"}`}>
                  {passwordResult.risk_level}
                </span>
              </div>

              {passwordResult.pwned ? (
                <div className="text-sm space-y-2">
                  <p className="text-mist">
                    This password has been observed <strong className="text-crimson-risk font-mono text-base">{passwordResult.count.toLocaleString()}</strong> times in compromised credential leaks across the web.
                  </p>
                  <div className="bg-void/80 p-3 rounded text-xs font-mono text-amber-warn border border-amber-warn/20">
                    💡 <strong>Recommendation:</strong> Immediately change any account using this password to a unique, randomly generated passphrase.
                  </div>
                </div>
              ) : (
                <p className="text-sm text-mist">
                  {passwordResult.recommendation}
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
