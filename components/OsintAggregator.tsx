"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface OsintResult {
  target: string;
  email_target: string | null;
  wayback: any;
  hackernews: any;
  github_exposure: any;
  dns_services: any;
  social_presence: any;
  gravatar?: any;
}

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className={`inline-block w-2 h-2 rounded-full ${ok ? "bg-emerald-400" : "bg-mist/30"}`} />
  );
}

export default function OsintAggregator() {
  const [domain, setDomain] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<OsintResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"social" | "wayback" | "github" | "hn" | "dns" | "gravatar">("social");

  const sessionToken = (() => {
    try {
      const u = localStorage.getItem("thunder_recon_auth_user");
      return u ? JSON.parse(u)?.session_token : null;
    } catch { return null; }
  })();

  const handleSearch = async () => {
    if (!domain.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/tools/osint`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          domain: domain.trim(),
          email: email.trim() || null,
          session_token: sessionToken,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      setResult(await res.json());
    } catch (e: any) {
      setError(e.message || "OSINT aggregation failed");
    } finally { setLoading(false); }
  };

  const social = result?.social_presence;
  const wayback = result?.wayback;
  const github = result?.github_exposure;
  const hn = result?.hackernews;
  const dns = result?.dns_services;
  const gravatar = result?.gravatar;

  const confirmedSocial = social?.platforms?.filter((p: any) => p.likely_exists).length || 0;
  const tabs = [
    { key: "social", label: `🌐 Social (${confirmedSocial})` },
    { key: "wayback", label: `📸 Wayback` },
    { key: "github", label: `🐙 GitHub` },
    { key: "hn", label: `🔴 HackerNews` },
    { key: "dns", label: `📡 Services` },
    ...(email ? [{ key: "gravatar", label: "👤 Gravatar" }] : []),
  ] as const;

  return (
    <div className="w-full max-w-4xl space-y-5 animate-fadeIn">
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
              OPEN-SOURCE INTELLIGENCE
            </span>
          </div>
          <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
            📡 OSINT Aggregator
          </h2>
          <p className="text-xs text-mist font-mono mt-1 max-w-xl">
            Social media presence, Wayback Machine history, GitHub exposure, HackerNews mentions,
            DNS service discovery, and Gravatar/email footprint.
          </p>
        </div>

        <div className="space-y-3">
          <div className="flex gap-3 flex-col sm:flex-row">
            <input
              type="text"
              placeholder="Target domain (e.g. example.com)"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
            />
            <input
              type="email"
              placeholder="Optional: email for Gravatar"
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="flex-1 sm:max-w-[240px] bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-purple-500/60 transition"
            />
          </div>
          <button
            onClick={handleSearch}
            disabled={loading || !domain.trim()}
            className="px-6 py-3 bg-purple-500 text-white rounded-xl font-display font-bold text-sm hover:opacity-90 transition disabled:opacity-40 w-full sm:w-auto"
          >
            {loading ? "Aggregating OSINT..." : "🔍 Run OSINT Scan"}
          </button>
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
                <div key={i} className="w-2 h-2 rounded-full bg-purple-400 animate-ping"
                  style={{ animationDelay: `${i*150}ms` }} />
              ))}
            </div>
            <p className="font-mono text-xs text-purple-300 animate-pulse">
              Querying multiple OSINT sources in parallel...
            </p>
          </div>
        )}
      </div>

      {result && (
        <div className="bg-panel border border-panelBorder rounded-2xl shadow-xl overflow-hidden animate-fadeIn">
          {/* Tabs */}
          <div className="flex border-b border-panelBorder overflow-x-auto">
            {tabs.map(tab => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as any)}
                className={`px-4 py-3 text-xs font-mono font-semibold transition border-b-2 -mb-px whitespace-nowrap ${
                  activeTab === tab.key
                    ? "text-purple-300 border-purple-400 bg-purple-500/5"
                    : "text-mist border-transparent hover:text-white"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="p-5">
            {/* Social Presence */}
            {activeTab === "social" && social && (
              <div className="space-y-3">
                <div className="text-xs font-mono text-mist">
                  Found <span className="text-white font-bold">{social.confirmed_count}</span> of {social.platforms?.length} platforms with likely presence for brand <span className="text-purple-300 font-bold">"{social.brand}"</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {social.platforms?.map((p: any) => (
                    <a
                      key={p.name}
                      href={p.url}
                      target="_blank"
                      rel="noreferrer"
                      className={`flex items-center justify-between p-3 rounded-xl border transition font-mono text-xs ${
                        p.likely_exists
                          ? "bg-emerald-500/5 border-emerald-500/30 hover:bg-emerald-500/10"
                          : "bg-void/30 border-panelBorder/50 opacity-60 cursor-default"
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <span>{p.icon}</span>
                        <span className={p.likely_exists ? "text-white" : "text-mist/60"}>{p.name}</span>
                      </span>
                      <span className="flex items-center gap-2">
                        {p.status && (
                          <span className={`text-[10px] ${p.likely_exists ? "text-emerald-400" : "text-mist/40"}`}>
                            {p.status}
                          </span>
                        )}
                        <StatusDot ok={p.likely_exists} />
                      </span>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Wayback Machine */}
            {activeTab === "wayback" && wayback && (
              <div className="space-y-4">
                {wayback.has_snapshots ? (
                  <>
                    <div className="flex items-center gap-2 p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl font-mono text-xs text-emerald-400">
                      ✅ Domain has archived snapshots on Wayback Machine
                    </div>
                    {wayback.closest_snapshot && (
                      <div className="bg-void/60 p-4 rounded-xl border border-panelBorder font-mono text-xs space-y-2">
                        <div className="text-[10px] text-mist uppercase tracking-wider font-bold">Closest Snapshot</div>
                        <div className="text-white">{wayback.closest_snapshot.timestamp}</div>
                        {wayback.closest_snapshot.url && (
                          <a href={wayback.closest_snapshot.url} target="_blank" rel="noreferrer"
                            className="text-cyan-signal hover:underline block truncate">{wayback.closest_snapshot.url}</a>
                        )}
                      </div>
                    )}
                    {wayback.recent_pages?.length > 0 && (
                      <div>
                        <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold mb-3">Recent Archived Pages</div>
                        <div className="space-y-2">
                          {wayback.recent_pages.map((page: any, i: number) => (
                            <div key={i} className="bg-void/50 p-3 rounded-xl border border-panelBorder font-mono text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                              <div>
                                <span className="text-mist/60">{page.timestamp}</span>
                                <span className="text-mist/40 ml-2">HTTP {page.status}</span>
                              </div>
                              <a href={page.archive_url} target="_blank" rel="noreferrer"
                                className="text-cyan-signal hover:underline truncate max-w-xs">{page.url}</a>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-mist/50 font-mono text-sm text-center py-8">
                    No archived snapshots found for this domain.
                  </div>
                )}
              </div>
            )}

            {/* GitHub */}
            {activeTab === "github" && github && (
              <div className="space-y-3">
                {github.rate_limited ? (
                  <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl font-mono text-xs text-amber-400">
                    ⚠️ {github.message}
                  </div>
                ) : (
                  <>
                    <div className="text-xs font-mono text-mist">
                      Found <span className="text-white font-bold">{github.total_results?.toLocaleString()}</span> public code matches for <span className="text-cyan-signal">"{result.target}"</span>
                    </div>
                    <div className="space-y-2">
                      {github.results?.map((r: any, i: number) => (
                        <div key={i} className="bg-void/60 p-3 rounded-xl border border-panelBorder font-mono text-xs space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-bold text-white">{r.repo}</span>
                            {r.is_public && <span className="text-[10px] text-emerald-400 bg-emerald-400/10 px-1.5 py-0.5 rounded">PUBLIC</span>}
                          </div>
                          <div className="text-mist/60">{r.path}</div>
                          <a href={r.file_url} target="_blank" rel="noreferrer"
                            className="text-cyan-signal hover:underline text-[11px]">View on GitHub →</a>
                        </div>
                      ))}
                      {(!github.results || github.results.length === 0) && (
                        <div className="text-mist/50 font-mono text-sm text-center py-6">No public code matches found.</div>
                      )}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* HackerNews */}
            {activeTab === "hn" && hn && (
              <div className="space-y-3">
                <div className="text-xs font-mono text-mist">
                  <span className="text-white font-bold">{hn.total_mentions?.toLocaleString()}</span> total HackerNews mentions
                </div>
                <div className="space-y-2">
                  {hn.recent_stories?.map((s: any, i: number) => (
                    <div key={i} className="bg-void/60 p-3 rounded-xl border border-panelBorder font-mono text-xs space-y-1">
                      <div className="font-semibold text-white">{s.title}</div>
                      <div className="flex gap-4 text-mist/60 text-[11px]">
                        <span>⬆ {s.points} pts</span>
                        <span>💬 {s.comments} comments</span>
                        <span>{s.created_at?.split("T")[0]}</span>
                      </div>
                      <a href={s.hn_url} target="_blank" rel="noreferrer"
                        className="text-orange-400 hover:underline text-[11px]">View on HN →</a>
                    </div>
                  ))}
                  {(!hn.recent_stories || hn.recent_stories.length === 0) && (
                    <div className="text-mist/50 font-mono text-sm text-center py-6">No HackerNews stories found.</div>
                  )}
                </div>
              </div>
            )}

            {/* DNS Services */}
            {activeTab === "dns" && dns && (
              <div className="space-y-4">
                {dns.discovered_services?.length > 0 ? (
                  <div>
                    <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold mb-3">
                      Discovered Hosted Services ({dns.discovered_services.length})
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {dns.discovered_services.map((svc: string) => (
                        <span key={svc} className="px-3 py-1.5 bg-cyan-signal/10 border border-cyan-signal/30 text-cyan-signal rounded-xl text-xs font-mono font-semibold">
                          {svc}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-mist/50 font-mono text-xs">No known services detected via DNS.</div>
                )}

                {dns.mx_records?.length > 0 && (
                  <div>
                    <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold mb-2">MX Records</div>
                    {dns.mx_records.map((mx: string) => (
                      <div key={mx} className="font-mono text-xs text-mist/80 py-1">{mx}</div>
                    ))}
                  </div>
                )}

                {dns.txt_records?.length > 0 && (
                  <div>
                    <div className="text-[10px] font-mono text-mist uppercase tracking-wider font-bold mb-2">TXT Records</div>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                      {dns.txt_records.map((t: string, i: number) => (
                        <div key={i} className="font-mono text-[11px] text-mist/70 bg-void/50 px-3 py-2 rounded-lg border border-panelBorder/40 break-all">{t}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Gravatar */}
            {activeTab === "gravatar" && gravatar && (
              <div className="space-y-4 font-mono">
                {gravatar.found ? (
                  <div className="flex items-start gap-4">
                    <img src={gravatar.avatar_url} alt="Gravatar" className="w-20 h-20 rounded-full border-2 border-cyan-signal/40 shrink-0" />
                    <div className="space-y-2 text-xs">
                      <div className="font-bold text-white text-base">{gravatar.display_name || "Unknown"}</div>
                      {gravatar.profile_url && (
                        <a href={gravatar.profile_url} target="_blank" rel="noreferrer"
                          className="text-cyan-signal hover:underline">{gravatar.profile_url}</a>
                      )}
                      {gravatar.about_me && <p className="text-mist/70 max-w-md">{gravatar.about_me}</p>}
                      {gravatar.accounts?.length > 0 && (
                        <div>
                          <div className="text-[10px] text-mist uppercase tracking-wider font-bold mb-1">Linked Accounts</div>
                          <div className="flex flex-wrap gap-2">
                            {gravatar.accounts.map((a: any) => (
                              <span key={a.domain} className="px-2 py-0.5 bg-cyan-signal/10 border border-cyan-signal/30 text-cyan-signal rounded text-[10px]">
                                {a.domain}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-4 text-mist/60 font-mono text-sm">
                    <div className="w-16 h-16 rounded-full bg-void border border-panelBorder flex items-center justify-center text-2xl">👤</div>
                    <div>No Gravatar profile found for this email address.</div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
