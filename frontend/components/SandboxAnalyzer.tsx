"use client";

import { useState, useRef, useCallback } from "react";
import {
  submitFileToSandbox,
  submitUrlToSandbox,
  SandboxFileResult,
  SandboxUrlResult,
} from "@/lib/api";

// ─────────────────────────────────────────────────────────────────
// Design tokens / shared sub-components
// ─────────────────────────────────────────────────────────────────

function SectionBadge({ label, color = "cyan" }: { label: string; color?: "cyan" | "violet" | "amber" | "rose" | "emerald" }) {
  const colors: Record<string, string> = {
    cyan:    "bg-cyan-500/20 text-cyan-signal border-cyan-500/30",
    violet:  "bg-violet-500/20 text-violet-300 border-violet-500/30",
    amber:   "bg-amber-500/20 text-amber-300 border-amber-500/30",
    rose:    "bg-rose-500/20 text-rose-300 border-rose-500/30",
    emerald: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  };
  return (
    <span className={`inline-flex items-center text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${colors[color]}`}>
      {label}
    </span>
  );
}

function VerdictBanner({ verdict, color }: { verdict: string; color: string }) {
  const cfg: Record<string, { bg: string; text: string; border: string; glow: string; icon: string }> = {
    critical:   { bg: "bg-rose-500/15", text: "text-rose-300",    border: "border-rose-500/50",    glow: "shadow-rose-500/20",    icon: "🔴" },
    suspicious: { bg: "bg-amber-500/15", text: "text-amber-300",   border: "border-amber-500/50",   glow: "shadow-amber-500/20",   icon: "🟡" },
    warn:       { bg: "bg-orange-500/15", text: "text-orange-300", border: "border-orange-500/40",  glow: "shadow-orange-500/15",  icon: "🟠" },
    clean:      { bg: "bg-emerald-500/10", text: "text-emerald-300", border: "border-emerald-500/40", glow: "shadow-emerald-500/10", icon: "🟢" },
  };
  const c = cfg[color] ?? cfg.clean;
  return (
    <div className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl border shadow-lg ${c.bg} ${c.border} ${c.glow} ${color === "critical" ? "animate-pulse" : ""}`}>
      <span className="text-lg leading-none">{c.icon}</span>
      <span className={`font-mono font-bold text-sm tracking-wide ${c.text}`}>{verdict}</span>
    </div>
  );
}

function SeverityChip({ severity }: { severity: string }) {
  const s = severity.toUpperCase();
  const styles: Record<string, string> = {
    CRITICAL: "bg-rose-500/25 text-rose-300 border-rose-500/50",
    HIGH:     "bg-rose-500/15 text-rose-400 border-rose-500/35",
    MEDIUM:   "bg-amber-500/15 text-amber-300 border-amber-500/35",
    LOW:      "bg-slate-600/30 text-slate-400 border-slate-500/30",
  };
  return (
    <span className={`shrink-0 text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${styles[s] ?? styles.LOW}`}>
      {s}
    </span>
  );
}

function EnginePill({ category, result }: { category: string; result: string }) {
  const label = result === "clean" ? "CLEAN" : result.toUpperCase().slice(0, 14);
  if (category === "malicious")
    return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 truncate max-w-[80px]">{label}</span>;
  if (category === "suspicious")
    return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 truncate max-w-[80px]">{label}</span>;
  return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/25">CLEAN</span>;
}

function HashRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="group flex items-center gap-2.5 bg-void/80 px-3 py-2 rounded-lg border border-panelBorder/50 hover:border-cyan-signal/30 transition">
      <span className="text-[9px] font-mono font-bold text-cyan-signal/80 w-9 shrink-0 uppercase">{label}</span>
      <span className="text-[11px] font-mono text-white/70 break-all flex-1 select-all leading-tight">{value}</span>
      <button
        onClick={copy}
        title="Copy to clipboard"
        className="shrink-0 w-5 h-5 flex items-center justify-center rounded text-mist hover:text-cyan-signal transition opacity-0 group-hover:opacity-100"
      >
        {copied ? <span className="text-emerald-400 text-[10px]">✓</span> : <span className="text-[10px]">⎘</span>}
      </button>
    </div>
  );
}

function StatBox({ label, value, color = "text-white" }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="bg-void/70 border border-panelBorder/70 rounded-xl p-3 text-center font-mono">
      <span className="text-[9px] text-mist uppercase tracking-widest block mb-1">{label}</span>
      <span className={`text-sm font-bold ${color}`}>{value}</span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Detection ring (SVG donut chart)
// ─────────────────────────────────────────────────────────────────
function DetectionRing({
  malicious, suspicious, harmless, total,
}: { malicious: number; suspicious: number; harmless: number; total: number }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const malPct = total > 0 ? malicious / total : 0;
  const susPct = total > 0 ? suspicious / total : 0;

  const ringColor = malicious > 5 ? "#f87171" : malicious > 0 ? "#fb923c" : suspicious > 0 ? "#fbbf24" : "#34d399";
  const countLabel = malicious > 0 ? `${malicious}/${total}` : suspicious > 0 ? `${suspicious}/${total}` : `0/${total}`;
  const statusLabel = malicious > 0 ? "DETECTED" : suspicious > 0 ? "SUSPICIOUS" : "CLEAN";

  const malArc = malPct * circ;
  const susArc = susPct * circ;

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="140" height="140" viewBox="0 0 140 140">
        {/* Track */}
        <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="12" />
        {/* Harmless */}
        <circle cx="70" cy="70" r={r} fill="none"
          stroke="rgba(52,211,153,0.25)" strokeWidth="12"
          strokeDasharray={circ} strokeDashoffset={0}
          strokeLinecap="butt" transform="rotate(-90 70 70)" />
        {/* Suspicious */}
        {suspicious > 0 && (
          <circle cx="70" cy="70" r={r} fill="none"
            stroke="#fbbf24" strokeWidth="12"
            strokeDasharray={`${susArc} ${circ - susArc}`}
            strokeDashoffset={-malArc}
            strokeLinecap="butt" transform="rotate(-90 70 70)" />
        )}
        {/* Malicious */}
        {malicious > 0 && (
          <circle cx="70" cy="70" r={r} fill="none"
            stroke={ringColor} strokeWidth="12"
            strokeDasharray={`${malArc} ${circ - malArc}`}
            strokeDashoffset={0}
            strokeLinecap="butt" transform="rotate(-90 70 70)" />
        )}
        {/* Glow ring for malicious */}
        {malicious > 0 && (
          <circle cx="70" cy="70" r={r} fill="none"
            stroke={ringColor} strokeWidth="2" strokeOpacity="0.3"
            strokeDasharray={`${malArc} ${circ - malArc}`}
            strokeDashoffset={0}
            transform="rotate(-90 70 70)" />
        )}
        {/* Center: count */}
        <text x="70" y="64" textAnchor="middle" fill={ringColor}
          fontSize="22" fontFamily="JetBrains Mono, monospace" fontWeight="700" letterSpacing="-1">
          {countLabel}
        </text>
        {/* Center: label */}
        <text x="70" y="80" textAnchor="middle" fill="rgba(255,255,255,0.35)"
          fontSize="8" fontFamily="JetBrains Mono, monospace" letterSpacing="2">
          {statusLabel}
        </text>
        {/* Center: engines */}
        <text x="70" y="93" textAnchor="middle" fill="rgba(255,255,255,0.2)"
          fontSize="7" fontFamily="JetBrains Mono, monospace">
          {total} ENGINES
        </text>
      </svg>
      {/* Legend */}
      <div className="flex items-center gap-4 text-[10px] font-mono">
        <span className="flex items-center gap-1 text-rose-400">
          <span className="w-2 h-2 rounded-full bg-rose-400 inline-block" /> {malicious} malicious
        </span>
        <span className="flex items-center gap-1 text-amber-300">
          <span className="w-2 h-2 rounded-full bg-amber-300 inline-block" /> {suspicious} suspicious
        </span>
        <span className="flex items-center gap-1 text-emerald-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" /> {harmless} clean
        </span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Engine matrix grid (shared)
// ─────────────────────────────────────────────────────────────────
function EngineMatrix({ engines, source }: { engines: { engine_name: string; category: string; result: string; method: string }[]; source: string }) {
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? engines : engines.slice(0, 21);
  const malCount = engines.filter(e => e.category === "malicious").length;
  const susCount = engines.filter(e => e.category === "suspicious").length;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <SectionBadge label="⚡ SECURITY VENDOR VERDICTS" color="cyan" />
          {malCount > 0 && <span className="text-[10px] font-mono text-rose-400 font-bold">{malCount} malicious</span>}
          {susCount > 0 && <span className="text-[10px] font-mono text-amber-300 font-bold">{susCount} suspicious</span>}
        </div>
        <span className="text-[10px] font-mono text-mist/60">{source}</span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1.5">
        {visible.map((eng, idx) => (
          <div
            key={idx}
            className={`flex justify-between items-center px-3 py-1.5 rounded-lg text-xs font-mono transition ${
              eng.category === "malicious"
                ? "bg-rose-500/10 border border-rose-500/25 hover:border-rose-500/50"
                : eng.category === "suspicious"
                ? "bg-amber-500/8 border border-amber-500/20 hover:border-amber-500/40"
                : "bg-void/50 border border-panelBorder/40 hover:border-panelBorder/70"
            }`}
          >
            <span className="text-white truncate max-w-[140px] font-medium">{eng.engine_name}</span>
            <EnginePill category={eng.category} result={eng.result} />
          </div>
        ))}
      </div>
      {engines.length > 21 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="text-xs font-mono text-cyan-signal hover:text-cyan-signal/80 transition"
        >
          {showAll ? "▲ Show fewer" : `▼ Show all ${engines.length} engines`}
        </button>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// File results panel
// ─────────────────────────────────────────────────────────────────
function FileResultsPanel({ result, onReset }: { result: SandboxFileResult; onReset: () => void }) {
  const [detailTab, setDetailTab] = useState<"identity" | "engines" | "iocs" | "bazaar">("identity");
  const { submission, file_identity, verdict, engine_results, behavioral_indicators, embedded_iocs, malwarebazaar, vt_link, community, source } = result;

  const fileIcon = file_identity.is_executable ? "⚙️"
    : file_identity.category === "Document" ? "📄"
    : file_identity.category === "Archive" ? "🗜️"
    : file_identity.category === "Image" ? "🖼️"
    : "📁";

  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Top bar: file name + reset */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2.5">
          <span className="text-2xl">{fileIcon}</span>
          <div>
            <div className="text-sm font-mono font-bold text-white truncate max-w-xs">{submission.filename}</div>
            <div className="text-[11px] font-mono text-mist">{submission.size_display} • {file_identity.category}</div>
          </div>
        </div>
        <button
          onClick={onReset}
          className="text-xs font-mono text-mist hover:text-white border border-panelBorder/70 px-3 py-1.5 rounded-lg hover:border-panelBorder transition"
        >
          ← Scan another file
        </button>
      </div>

      {/* Verdict row */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-5">
          {/* Detection ring */}
          <DetectionRing
            malicious={verdict.malicious_count}
            suspicious={verdict.suspicious_count}
            harmless={verdict.harmless_count}
            total={verdict.total_engines}
          />
          {/* Verdict + stats */}
          <div className="flex flex-col items-center sm:items-start gap-3 flex-1">
            <VerdictBanner verdict={verdict.overall} color={verdict.color} />
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 w-full">
              <StatBox label="Malicious" value={verdict.malicious_count}
                color={verdict.malicious_count > 0 ? "text-rose-400" : "text-mist"} />
              <StatBox label="Suspicious" value={verdict.suspicious_count}
                color={verdict.suspicious_count > 0 ? "text-amber-300" : "text-mist"} />
              <StatBox label="Harmless" value={verdict.harmless_count} color="text-emerald-400" />
              <StatBox label="Reputation" value={`${verdict.reputation}/100`} color="text-cyan-signal" />
            </div>
            {(community.votes_malicious > 0 || community.votes_harmless > 0) && (
              <div className="flex items-center gap-3 text-[11px] font-mono text-mist">
                <span>Community votes:</span>
                <span className="text-emerald-400">👍 {community.votes_harmless} harmless</span>
                <span className="text-rose-400">👎 {community.votes_malicious} malicious</span>
              </div>
            )}
            <a href={vt_link} target="_blank" rel="noreferrer"
              className="text-xs font-mono text-cyan-signal hover:text-cyan-signal/80 border border-cyan-signal/30 hover:border-cyan-signal/60 px-3 py-1.5 rounded-lg transition">
              View full report on VirusTotal ↗
            </a>
          </div>
        </div>
      </div>

      {/* Behavioral indicators — always shown if present */}
      {behavioral_indicators.length > 0 && (
        <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-3 animate-slideUp">
          <div className="flex items-center justify-between">
            <SectionBadge label="🔬 BEHAVIORAL INDICATORS" color="amber" />
            <span className="text-[10px] font-mono text-mist">Static heuristics · no execution required</span>
          </div>
          <div className="space-y-2">
            {behavioral_indicators.map((ind, idx) => (
              <div key={idx}
                className="flex items-start gap-3 bg-void/60 border border-panelBorder/50 px-3.5 py-2.5 rounded-xl hover:border-panelBorder transition">
                <SeverityChip severity={ind.severity} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-mono font-bold text-white">{ind.type}</div>
                  <div className="text-[11px] font-mono text-mist leading-relaxed mt-0.5">{ind.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabbed detail panel */}
      <div className="bg-panel border border-panelBorder rounded-2xl shadow-xl overflow-hidden animate-slideUp">
        {/* Tab bar */}
        <div className="flex border-b border-panelBorder/60 overflow-x-auto">
          {([
            { key: "identity", label: "🧬 File Identity" },
            { key: "engines",  label: `⚡ Engines (${engine_results.length})` },
            { key: "iocs",     label: `🔗 IOCs (${embedded_iocs.total_iocs})` },
            { key: "bazaar",   label: "🏴 MalwareBazaar" },
          ] as const).map(tab => (
            <button key={tab.key} onClick={() => setDetailTab(tab.key)}
              className={`flex-1 min-w-max px-4 py-3 text-xs font-mono font-semibold whitespace-nowrap transition ${
                detailTab === tab.key
                  ? "bg-cyan-signal/10 text-cyan-signal border-b-2 border-cyan-signal"
                  : "text-mist hover:text-white hover:bg-void/40"
              }`}>
              {tab.label}
            </button>
          ))}
        </div>

        <div className="p-5">
          {/* FILE IDENTITY TAB */}
          {detailTab === "identity" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div className="space-y-2">
                <div className="text-[9px] font-mono text-mist uppercase tracking-widest mb-2">File Metadata</div>
                {[
                  ["Extension", file_identity.extension],
                  ["Category", file_identity.category],
                  ["Magic Bytes", file_identity.magic_description],
                  ["Entropy", `${file_identity.entropy} / 8.0`],
                  ["Entropy Risk", file_identity.entropy_risk.split(" — ")[0]],
                  ["Suspicious Ext", file_identity.is_suspicious_extension ? "Yes ⚠" : "No ✓"],
                  ["Executable", file_identity.is_executable ? "Yes ⚠" : "No ✓"],
                  ["Size", submission.size_display],
                  ...(submission.first_seen ? [["First Seen", submission.first_seen.slice(0, 10)]] : []),
                  ...(submission.last_seen  ? [["Last Seen",  submission.last_seen.slice(0, 10)]]  : []),
                  ...(submission.times_submitted > 1 ? [["Times Submitted", String(submission.times_submitted)]] : []),
                ].map(([label, val]) => (
                  <div key={label} className="flex justify-between items-center bg-void/50 px-3 py-1.5 rounded-lg text-xs font-mono border border-panelBorder/30">
                    <span className="text-mist">{label}</span>
                    <span className={`font-semibold text-right max-w-[200px] ${
                      val.includes("⚠") ? "text-amber-300" : val.includes("✓") ? "text-emerald-400" : "text-white"
                    }`}>{val}</span>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                <div className="text-[9px] font-mono text-mist uppercase tracking-widest mb-2">Cryptographic Hashes</div>
                <HashRow label="MD5"    value={file_identity.md5} />
                <HashRow label="SHA1"   value={file_identity.sha1} />
                <HashRow label="SHA256" value={file_identity.sha256} />
                {/* Entropy bar */}
                <div className="mt-3 space-y-1.5">
                  <div className="flex justify-between text-[10px] font-mono text-mist">
                    <span>Shannon Entropy</span>
                    <span className={
                      file_identity.entropy_level === "critical" ? "text-rose-400" :
                      file_identity.entropy_level === "high"     ? "text-amber-300" :
                      file_identity.entropy_level === "medium"   ? "text-yellow-400" : "text-emerald-400"
                    }>{file_identity.entropy} / 8.0</span>
                  </div>
                  <div className="h-1.5 bg-void rounded-full overflow-hidden border border-panelBorder/50">
                    <div
                      className={`h-full rounded-full transition-all ${
                        file_identity.entropy_level === "critical" ? "bg-rose-500" :
                        file_identity.entropy_level === "high"     ? "bg-amber-400" :
                        file_identity.entropy_level === "medium"   ? "bg-yellow-400" : "bg-emerald-500"
                      }`}
                      style={{ width: `${(file_identity.entropy / 8) * 100}%` }}
                    />
                  </div>
                  <div className="text-[10px] font-mono text-mist/60 leading-tight">{file_identity.entropy_risk}</div>
                </div>
              </div>
            </div>
          )}

          {/* ENGINES TAB */}
          {detailTab === "engines" && (
            <EngineMatrix engines={engine_results} source={source} />
          )}

          {/* IOCs TAB */}
          {detailTab === "iocs" && (
            <div className="space-y-4">
              {embedded_iocs.total_iocs === 0 ? (
                <div className="flex items-center justify-center gap-3 py-8 text-emerald-400 font-mono text-xs">
                  <span>✓</span>
                  <span>No embedded URLs, IPs, or suspicious domains detected in file content.</span>
                </div>
              ) : (
                <>
                  {embedded_iocs.urls.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[9px] font-mono text-mist uppercase tracking-widest">Embedded URLs ({embedded_iocs.urls.length})</div>
                      <div className="space-y-1 max-h-40 overflow-y-auto pr-1">
                        {embedded_iocs.urls.map((u, i) => (
                          <div key={i} className="text-[11px] font-mono text-cyan-signal bg-cyan-signal/5 border border-cyan-signal/15 px-3 py-1.5 rounded-lg break-all hover:border-cyan-signal/30 transition">
                            {u}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {embedded_iocs.ips.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[9px] font-mono text-mist uppercase tracking-widest">Embedded IP Addresses ({embedded_iocs.ips.length})</div>
                      <div className="flex flex-wrap gap-1.5">
                        {embedded_iocs.ips.map((ip, i) => (
                          <span key={i} className="text-xs font-mono text-amber-300 bg-amber-500/10 border border-amber-500/25 px-2 py-0.5 rounded-lg">{ip}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {embedded_iocs.domains.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[9px] font-mono text-mist uppercase tracking-widest">Embedded Domains ({embedded_iocs.domains.length})</div>
                      <div className="flex flex-wrap gap-1.5">
                        {embedded_iocs.domains.map((d, i) => (
                          <span key={i} className="text-xs font-mono text-white/70 bg-void/70 border border-panelBorder/50 px-2 py-0.5 rounded-lg">{d}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* MALWAREBAZAAR TAB */}
          {detailTab === "bazaar" && (
            <div className="space-y-3 text-xs font-mono">
              {!malwarebazaar ? (
                <div className="text-center py-6 text-mist">MalwareBazaar API unavailable.</div>
              ) : !malwarebazaar.found ? (
                <div className="flex items-center gap-3 p-4 bg-emerald-500/8 border border-emerald-500/25 rounded-xl text-emerald-400">
                  <span className="text-lg">✓</span>
                  <div>
                    <div className="font-bold">Hash not found in MalwareBazaar</div>
                    <div className="text-[11px] text-emerald-400/70 mt-0.5">SHA256 has no known malware match in the abuse.ch corpus.</div>
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="flex items-center gap-2.5 p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-300">
                    <span className="text-lg">⚠️</span>
                    <div>
                      <div className="font-bold">SHA256 found in MalwareBazaar malware corpus</div>
                      <div className="text-[11px] text-rose-300/70 mt-0.5">This file is a known malware sample tracked by the abuse.ch community.</div>
                    </div>
                  </div>
                  {[
                    ["Malware Signature", malwarebazaar.signature],
                    ["File Type",         malwarebazaar.file_type],
                    ["Reporter",          malwarebazaar.reporter],
                    ["First Seen",        malwarebazaar.first_seen],
                    ["Last Seen",         malwarebazaar.last_seen],
                    ["Tags",              (malwarebazaar.tags || []).join(", ") || "none"],
                  ].filter(([_, v]) => !!v).map(([label, val]) => (
                    <div key={label as string} className="flex justify-between items-center bg-void/60 px-3 py-2 rounded-lg border border-panelBorder/40">
                      <span className="text-mist">{label as string}</span>
                      <span className="text-white font-semibold text-right">{val as string}</span>
                    </div>
                  ))}
                  <a href={malwarebazaar.malwarebazaar_link} target="_blank" rel="noreferrer"
                    className="flex items-center justify-center gap-2 text-xs font-mono py-2 mt-1 rounded-xl border border-rose-500/30 text-rose-300 hover:bg-rose-500/10 transition">
                    View full sample on MalwareBazaar ↗
                  </a>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// URL results panel
// ─────────────────────────────────────────────────────────────────
function UrlResultsPanel({ result, onReset }: { result: SandboxUrlResult; onReset: () => void }) {
  const [detailTab, setDetailTab] = useState<"info" | "engines" | "heuristics">("info");
  const { submission, verdict, heuristics, engine_results, vt_link, source } = result;

  const schemeIcon = submission.scheme === "https" ? "🔒" : "⚠️";

  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Top bar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="text-xl shrink-0">{schemeIcon}</span>
          <div className="min-w-0">
            <div className="text-sm font-mono font-bold text-white truncate">{submission.domain}</div>
            <div className="text-[11px] font-mono text-mist truncate">{submission.final_url}</div>
          </div>
        </div>
        <button onClick={onReset}
          className="text-xs font-mono text-mist hover:text-white border border-panelBorder/70 px-3 py-1.5 rounded-lg hover:border-panelBorder transition shrink-0">
          ← Scan another URL
        </button>
      </div>

      {/* Verdict row */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-5">
          <DetectionRing
            malicious={verdict.malicious_count}
            suspicious={verdict.suspicious_count}
            harmless={verdict.harmless_count}
            total={verdict.total_engines}
          />
          <div className="flex flex-col items-center sm:items-start gap-3 flex-1">
            <VerdictBanner verdict={verdict.overall} color={verdict.color} />
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 w-full">
              <StatBox label="Risk Score" value={`${verdict.risk_score ?? 0}/100`}
                color={(verdict.risk_score ?? 0) > 50 ? "text-rose-400" : "text-emerald-400"} />
              <StatBox label="Malicious"  value={verdict.malicious_count}
                color={verdict.malicious_count > 0 ? "text-rose-400" : "text-mist"} />
              <StatBox label="Harmless"   value={verdict.harmless_count} color="text-emerald-400" />
              <StatBox label="Reputation" value={`${verdict.reputation}/100`} color="text-cyan-signal" />
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <span className={`text-[11px] font-mono font-bold px-2.5 py-1 rounded-lg border ${
                verdict.risk_rating?.includes("High") || verdict.risk_rating?.includes("Malicious")
                  ? "bg-rose-500/15 text-rose-400 border-rose-500/30"
                  : verdict.risk_rating?.includes("Suspicious")
                  ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
                  : "bg-emerald-500/10 text-emerald-400 border-emerald-500/25"
              }`}>
                {verdict.risk_rating || "Unknown"}
              </span>
              <a href={vt_link} target="_blank" rel="noreferrer"
                className="text-xs font-mono text-cyan-signal hover:text-cyan-signal/80 border border-cyan-signal/30 hover:border-cyan-signal/60 px-3 py-1.5 rounded-lg transition">
                View on VirusTotal ↗
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Tabbed detail panel */}
      <div className="bg-panel border border-panelBorder rounded-2xl shadow-xl overflow-hidden animate-slideUp">
        <div className="flex border-b border-panelBorder/60">
          {([
            { key: "info",       label: "🔗 URL Details" },
            { key: "engines",    label: `⚡ Engines (${engine_results.length})` },
            { key: "heuristics", label: `🔬 Heuristics (${heuristics.length})` },
          ] as const).map(tab => (
            <button key={tab.key} onClick={() => setDetailTab(tab.key)}
              className={`flex-1 px-4 py-3 text-xs font-mono font-semibold transition ${
                detailTab === tab.key
                  ? "bg-cyan-signal/10 text-cyan-signal border-b-2 border-cyan-signal"
                  : "text-mist hover:text-white hover:bg-void/40"
              }`}>
              {tab.label}
            </button>
          ))}
        </div>

        <div className="p-5">
          {/* URL INFO TAB */}
          {detailTab === "info" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {[
                  ["Scheme",       submission.scheme.toUpperCase()],
                  ["Domain",       submission.domain],
                  ["Path",         submission.path || "/"],
                  ["IP Address",   submission.ip || "Unresolved"],
                  ["Status Code",  String(submission.status_code ?? "N/A")],
                  ["Server",       submission.server || "Hidden"],
                  ["Content-Type", (submission.content_type || "Unknown").split(";")[0]],
                  ["Accessible",   submission.is_accessible ? "✓ Yes" : "✗ No"],
                  ["Redirect Hops",String(submission.redirect_hops)],
                ].map(([label, val]) => (
                  <div key={label} className="flex justify-between items-center bg-void/50 px-3 py-1.5 rounded-lg text-xs font-mono border border-panelBorder/30">
                    <span className="text-mist">{label}</span>
                    <span className={`font-semibold ${val.startsWith("✓") ? "text-emerald-400" : val.startsWith("✗") ? "text-rose-400" : "text-white"}`}>
                      {val}
                    </span>
                  </div>
                ))}
              </div>

              {/* Redirect chain */}
              {submission.redirect_chain.length > 0 && (
                <div className="space-y-1.5">
                  <div className="text-[9px] font-mono text-mist uppercase tracking-widest">Redirect Chain</div>
                  {submission.redirect_chain.map((hop, i) => (
                    <div key={i} className="flex items-center gap-2.5 bg-void/60 border border-panelBorder/40 px-3 py-2 rounded-xl text-xs font-mono">
                      <span className="w-5 h-5 rounded-full bg-cyan-signal/15 text-cyan-signal text-[10px] flex items-center justify-center font-bold shrink-0">
                        {hop.hop}
                      </span>
                      <span className="text-white truncate flex-1">{hop.url}</span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ${
                        hop.status_code >= 200 && hop.status_code < 300 ? "bg-emerald-500/15 text-emerald-400" :
                        hop.status_code >= 300 && hop.status_code < 400 ? "bg-amber-500/15 text-amber-300" :
                        "bg-rose-500/15 text-rose-400"
                      }`}>
                        {hop.status_code}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ENGINES TAB */}
          {detailTab === "engines" && (
            <EngineMatrix engines={engine_results} source={source} />
          )}

          {/* HEURISTICS TAB */}
          {detailTab === "heuristics" && (
            <div className="space-y-2">
              {heuristics.length === 0 ? (
                <div className="flex items-center justify-center gap-3 py-8 text-emerald-400 font-mono text-xs">
                  <span>✓</span> No suspicious heuristics detected.
                </div>
              ) : (
                heuristics.map((h, idx) => (
                  <div key={idx} className="flex items-start gap-3 bg-void/60 border border-panelBorder/50 px-3.5 py-2.5 rounded-xl hover:border-panelBorder transition">
                    <SeverityChip severity={h.severity} />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-mono font-bold text-white">{h.type}</div>
                      <div className="text-[11px] font-mono text-mist leading-relaxed mt-0.5">{h.details}</div>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Loading animation
// ─────────────────────────────────────────────────────────────────
const FILE_STEPS = [
  "Computing SHA256 / MD5 / SHA1 hashes...",
  "Querying MalwareBazaar hash database...",
  "Checking VirusTotal file intelligence...",
  "Running entropy & IOC extraction...",
  "Building multi-engine verdict...",
];
const URL_STEPS = [
  "Resolving domain & IP address...",
  "Tracing redirect chain...",
  "Running phishing heuristics...",
  "Querying 30+ threat intel engines...",
  "Computing behavioral verdict...",
];

function SandboxLoader({ mode }: { mode: "file" | "url" }) {
  const [step, setStep] = useState(0);
  const steps = mode === "file" ? FILE_STEPS : URL_STEPS;

  // Cycle through steps every 1.8s for visual feedback
  useState(() => {
    const id = setInterval(() => setStep(s => (s + 1) % steps.length), 1800);
    return () => clearInterval(id);
  });

  return (
    <div className="flex flex-col items-center gap-5 py-12">
      {/* Animated radar rings */}
      <div className="relative w-20 h-20">
        {[0, 1, 2].map(i => (
          <div key={i} className="absolute inset-0 rounded-full border border-cyan-signal/30 animate-ping"
            style={{ animationDelay: `${i * 200}ms`, animationDuration: "1.6s" }} />
        ))}
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-3xl">{mode === "file" ? "🧬" : "🔗"}</span>
        </div>
      </div>
      {/* Step text */}
      <div className="text-center space-y-1">
        <div className="text-sm font-mono text-cyan-signal animate-blink">{steps[step]}</div>
        <div className="text-xs font-mono text-mist/60">MalwareBazaar · VirusTotal · Community Intel</div>
      </div>
      {/* Progress dots */}
      <div className="flex gap-2">
        {steps.map((_, i) => (
          <div key={i} className={`w-1.5 h-1.5 rounded-full transition-all duration-500 ${
            i <= step ? "bg-cyan-signal" : "bg-panelBorder"
          }`} />
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Sample URL quick-picks
// ─────────────────────────────────────────────────────────────────
const SAMPLE_URLS = [
  { label: "github.com", url: "https://github.com" },
  { label: "cloudflare.com", url: "https://cloudflare.com" },
  { label: "http redirect", url: "http://httpforever.com" },
];

// ─────────────────────────────────────────────────────────────────
// Main SandboxAnalyzer
// ─────────────────────────────────────────────────────────────────
const MAX_FILE_MB = 32;

export default function SandboxAnalyzer() {
  const [mode, setMode]               = useState<"file" | "url">("file");
  const [dragging, setDragging]       = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [urlInput, setUrlInput]       = useState("");
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState<string | null>(null);
  const [fileResult, setFileResult]   = useState<SandboxFileResult | null>(null);
  const [urlResult, setUrlResult]     = useState<SandboxUrlResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const reset = () => { setFileResult(null); setUrlResult(null); setError(null); setSelectedFile(null); setUrlInput(""); };
  const resetResults = () => { setFileResult(null); setUrlResult(null); setError(null); };

  const acceptFile = useCallback((file: File) => {
    if (file.size > MAX_FILE_MB * 1024 * 1024) {
      setError(`File too large — max ${MAX_FILE_MB} MB (got ${(file.size / 1024 / 1024).toFixed(1)} MB).`);
      return;
    }
    setSelectedFile(file);
    setError(null);
    resetResults();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) acceptFile(f);
  }, [acceptFile]);

  const handleDragOver  = (e: React.DragEvent) => { e.preventDefault(); setDragging(true); };
  const handleDragLeave = () => setDragging(false);

  const submitFile = async () => {
    if (!selectedFile) return;
    setLoading(true); setError(null); resetResults();
    try {
      setFileResult(await submitFileToSandbox(selectedFile));
    } catch (e: any) {
      setError(e.message || "Sandbox analysis failed.");
    } finally { setLoading(false); }
  };

  const submitUrl = async () => {
    if (!urlInput.trim()) return;
    setLoading(true); setError(null); resetResults();
    try {
      setUrlResult(await submitUrlToSandbox(urlInput.trim()));
    } catch (e: any) {
      setError(e.message || "URL sandbox analysis failed.");
    } finally { setLoading(false); }
  };

  const hasResult = !!(fileResult || urlResult);

  return (
    <div className="w-full max-w-6xl space-y-5">
      {/* ── Header ── */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-5 sm:p-6 shadow-xl animate-fadeIn">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <SectionBadge label="THUNDER SANDBOX" color="violet" />
              <span className="text-[10px] font-mono text-mist/50">v1.0 · Behavioral Detonation Engine</span>
            </div>
            <h2 className="font-display text-xl sm:text-2xl font-extrabold text-white tracking-tight">
              🧪 File &amp; URL Sandbox
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-lg">
              Submit files or URLs for cryptographic hash intelligence, multi-AV engine scanning,
              entropy analysis, IOC extraction, and behavioral heuristics.
            </p>
          </div>
          {/* Mode toggle pill */}
          <div className="flex bg-void border border-panelBorder rounded-xl p-1 gap-1">
            {(["file", "url"] as const).map(m => (
              <button key={m} onClick={() => { setMode(m); resetResults(); if (m === "file") setUrlInput(""); else setSelectedFile(null); }}
                className={`px-5 py-2 rounded-lg text-xs font-mono font-semibold transition ${
                  mode === m ? "bg-cyan-signal text-void shadow-sm" : "text-mist hover:text-white"
                }`}>
                {m === "file" ? "📁 File" : "🔗 URL"}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ── Input section ── */}
      {!hasResult && !loading && (
        <div className="animate-slideUp">
          {mode === "file" ? (
            <div className="bg-panel border border-panelBorder rounded-2xl p-5 sm:p-6 shadow-xl space-y-4">
              {/* Drop zone */}
              <div
                onDrop={handleDrop} onDragOver={handleDragOver} onDragLeave={handleDragLeave}
                onClick={() => fileInputRef.current?.click()}
                className={`relative flex flex-col items-center justify-center gap-3 rounded-2xl border-2 border-dashed p-12 cursor-pointer select-none transition-all duration-200 ${
                  dragging
                    ? "border-cyan-signal bg-cyan-signal/8 scale-[1.005]"
                    : selectedFile
                    ? "border-emerald-500/50 bg-emerald-500/5"
                    : "border-panelBorder hover:border-cyan-signal/40 hover:bg-cyan-signal/3"
                }`}
              >
                <input ref={fileInputRef} type="file" className="hidden"
                  onChange={e => e.target.files?.[0] && acceptFile(e.target.files[0])} />

                {dragging && (
                  <div className="absolute inset-0 rounded-2xl bg-cyan-signal/10 pointer-events-none border-2 border-cyan-signal animate-pulse" />
                )}

                {selectedFile ? (
                  <>
                    <div className="text-5xl">📄</div>
                    <div className="text-center">
                      <div className="text-sm font-mono font-bold text-white">{selectedFile.name}</div>
                      <div className="text-xs font-mono text-mist mt-0.5">
                        {selectedFile.size > 1048576
                          ? `${(selectedFile.size / 1048576).toFixed(2)} MB`
                          : `${(selectedFile.size / 1024).toFixed(1)} KB`}
                        {" "}• Click to change
                      </div>
                    </div>
                    {/* Type chip */}
                    <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      {selectedFile.type || "application/octet-stream"}
                    </span>
                  </>
                ) : (
                  <>
                    <div className="w-16 h-16 rounded-2xl border-2 border-dashed border-panelBorder/60 flex items-center justify-center text-3xl text-mist/40">
                      ⬆
                    </div>
                    <div className="text-center">
                      <div className="text-sm font-semibold text-white">Drop any file here</div>
                      <div className="text-xs text-mist font-mono mt-0.5">
                        or <span className="text-cyan-signal">click to browse</span> · Max {MAX_FILE_MB} MB · No login required
                      </div>
                    </div>
                    <div className="flex flex-wrap justify-center gap-1.5 text-[10px] font-mono text-mist/50">
                      {[".exe", ".dll", ".pdf", ".doc", ".zip", ".js", ".py", "…"].map(ext => (
                        <span key={ext} className="px-1.5 py-0.5 rounded bg-void border border-panelBorder/40">{ext}</span>
                      ))}
                    </div>
                  </>
                )}
              </div>

              <button onClick={submitFile} disabled={!selectedFile}
                className="w-full py-3 rounded-xl font-mono font-bold text-sm bg-cyan-signal text-void hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15">
                🔬 Analyze File
              </button>
            </div>
          ) : (
            <div className="bg-panel border border-panelBorder rounded-2xl p-5 sm:p-6 shadow-xl space-y-4">
              <div className="text-[9px] font-mono text-mist uppercase tracking-widest">Target URL</div>
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text" value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && submitUrl()}
                  placeholder="https://example.com/suspicious-path?redirect=login"
                  className="flex-1 bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
                />
                <button onClick={submitUrl} disabled={!urlInput.trim()}
                  className="px-6 py-3 rounded-xl font-mono font-bold text-sm bg-cyan-signal text-void hover:opacity-90 transition disabled:opacity-30 disabled:cursor-not-allowed shadow-lg shadow-cyan-signal/15 whitespace-nowrap">
                  🔗 Scan URL
                </button>
              </div>

              {/* Sample URLs */}
              <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-mist">
                <span>Try samples:</span>
                {SAMPLE_URLS.map(s => (
                  <button key={s.url} onClick={() => setUrlInput(s.url)}
                    className="px-2 py-0.5 rounded bg-void border border-panelBorder hover:text-white hover:border-panelBorder/80 transition">
                    {s.label}
                  </button>
                ))}
              </div>
              <div className="text-[10px] font-mono text-mist/50">
                No login required · Checks redirect chain, phishing heuristics, and 30+ threat intelligence engines
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Loading ── */}
      {loading && (
        <div className="bg-panel border border-panelBorder rounded-2xl shadow-xl animate-fadeIn">
          <SandboxLoader mode={mode} />
        </div>
      )}

      {/* ── Error ── */}
      {error && !loading && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-rose-500/10 border border-rose-500/25 rounded-xl text-sm font-mono text-rose-400 animate-fadeIn">
          <span className="text-base shrink-0">⚠</span>
          <div>
            <div className="font-bold">Analysis Error</div>
            <div className="text-[11px] text-rose-400/70 mt-0.5">{error}</div>
          </div>
          <button onClick={() => setError(null)} className="ml-auto shrink-0 text-rose-400/50 hover:text-rose-400 transition">✕</button>
        </div>
      )}

      {/* ── Results ── */}
      {fileResult && <FileResultsPanel result={fileResult} onReset={reset} />}
      {urlResult  && <UrlResultsPanel  result={urlResult}  onReset={reset} />}

      {/* ── Empty state feature cards ── */}
      {!loading && !error && !fileResult && !urlResult && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 animate-fadeIn">
          {[
            { icon: "🔢", title: "Hash Intelligence",       desc: "MD5, SHA1, SHA256 checked instantly against MalwareBazaar and the VirusTotal file corpus." },
            { icon: "🔬", title: "Behavioral Analysis",    desc: "Shannon entropy, magic bytes, PE header signals, embedded URL/IP/domain IOC extraction." },
            { icon: "⚡", title: "30+ AV Engine Matrix",   desc: "Unified multi-vendor verdict matrix: Kaspersky, Sophos, CrowdStrike, ESET, Microsoft Defender, and more." },
          ].map(card => (
            <div key={card.title} className="bg-panel border border-panelBorder rounded-2xl p-5 shadow space-y-2.5 hover:border-panelBorder/80 transition">
              <div className="text-3xl">{card.icon}</div>
              <div className="text-sm font-bold text-white font-display">{card.title}</div>
              <div className="text-[11px] text-mist font-mono leading-relaxed">{card.desc}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
