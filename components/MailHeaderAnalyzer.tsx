"use client";

import { useState } from "react";
import { analyzeMailHeaders, MailHeaderResult } from "@/lib/api";

const SAMPLE_EMAIL_HEADER = `Delivered-To: recipient@example.com
Received: by 2002:a17:902:d009:b0:1df:4f87:2311 with SMTP id a9csp3451234
        for <recipient@example.com>; Wed, 19 Aug 2026 10:15:32 -0700 (PDT)
Received: from mail-ed1-f52.google.com (mail-ed1-f52.google.com. [209.85.208.52])
        by mx.google.com with ESMTPS id f12si3849129edw.452.2026.08.19.10.15.31
        for <recipient@example.com>; Wed, 19 Aug 2026 10:15:31 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@github.com header.s=s20220108 header.b=XyZ12345;
       spf=pass (google.com: domain of noreply@github.com designates 209.85.208.52 as permitted sender) smtp.mailfrom=noreply@github.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com
From: GitHub Notifications <noreply@github.com>
To: recipient@example.com
Subject: [GitHub] Security Alert: New sign-in detected on your account
Date: Wed, 19 Aug 2026 17:15:28 +0000
Message-ID: <github/security/alert/12984912@github.com>
Return-Path: <noreply@github.com>
Reply-To: support@github.com
X-Spam-Status: No, score=-2.5 required=5.0 tests=BAYES_00,DKIM_SIGNED,DKIM_VALID`;

function AuthVerdict({ label, value }: { label: string; value: string }) {
  const pass = value.toUpperCase().includes("PASS");
  const fail = value.toUpperCase().includes("FAIL") || value.toUpperCase().includes("NONE");
  return (
    <div className="bg-void/70 border border-panelBorder/60 rounded-xl p-4 text-center space-y-2">
      <div className="text-[9px] font-mono uppercase tracking-widest text-mist">{label}</div>
      <span className={`inline-block text-xs font-mono font-bold px-3 py-1 rounded-lg border ${
        pass ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" :
        fail ? "bg-rose-500/15 text-rose-400 border-rose-500/30" :
               "bg-amber-500/15 text-amber-300 border-amber-500/30"
      }`}>
        {value || "NOT CHECKED"}
      </span>
    </div>
  );
}

export default function MailHeaderAnalyzer() {
  const [rawHeaders, setRawHeaders] = useState("");
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);
  const [result, setResult]         = useState<MailHeaderResult | null>(null);

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!rawHeaders.trim()) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const data = await analyzeMailHeaders(rawHeaders);
      if (data.error) throw new Error(data.error);
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to parse mail headers");
    } finally { setLoading(false); }
  };

  const trustColor = result
    ? result.trust_score >= 80 ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
    : result.trust_score >= 50 ? "text-amber-300 border-amber-500/30 bg-amber-500/10"
    : "text-rose-400 border-rose-500/30 bg-rose-500/10"
    : "";

  return (
    <div className="w-full max-w-4xl space-y-5 animate-fadeIn">

      {/* Input card */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-signal border border-cyan-500/30">
                FORENSIC ANALYZER
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white">📬 Mail Header Forensic Analyzer</h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Paste raw RFC 822 email headers to trace MTA delivery hops, verify SPF / DKIM / DMARC / ARC signatures, and detect sender spoofing.
            </p>
          </div>
          <button type="button" onClick={() => setRawHeaders(SAMPLE_EMAIL_HEADER)}
            className="shrink-0 px-3 py-1.5 rounded-lg text-xs font-mono border border-cyan-signal/40 text-cyan-signal hover:bg-cyan-signal/10 transition">
            Load Sample →
          </button>
        </div>

        <form onSubmit={handleAnalyze} className="space-y-3">
          <textarea
            rows={8}
            placeholder={"Paste raw email headers here\n(Received: from …, Authentication-Results: …, From: …)"}
            value={rawHeaders}
            onChange={e => setRawHeaders(e.target.value)}
            className="w-full px-4 py-3 bg-void border border-panelBorder rounded-xl text-white font-mono text-xs focus:outline-none focus:border-cyan-signal/60 leading-relaxed resize-none transition placeholder:text-mist/25"
          />
          <button type="submit" disabled={loading || !rawHeaders.trim()}
            className="w-full py-3 bg-cyan-signal text-void font-display font-bold text-sm rounded-xl hover:opacity-90 transition shadow-lg shadow-cyan-signal/15 disabled:opacity-30 disabled:cursor-not-allowed">
            {loading ? "Deconstructing MTA Hops & Signatures…" : "Analyze Email Headers"}
          </button>
        </form>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-rose-500/10 border border-rose-500/25 rounded-xl text-sm font-mono text-rose-400 animate-fadeIn">
          <span className="shrink-0">⚠</span>
          <div>
            <div className="font-bold">Parse Error</div>
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
            Deconstructing MTA delivery hops &amp; verifying cryptographic signatures…
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slideUp">

          {/* Summary card */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
              <div className="space-y-0.5">
                <div className="text-[9px] font-mono text-mist uppercase tracking-widest">Subject</div>
                <div className="font-mono text-base font-bold text-white leading-tight">
                  {result.envelope.subject || "(No Subject)"}
                </div>
                <div className="text-xs font-mono text-mist pt-1">
                  Origin IP: <span className="text-cyan-signal">{result.envelope.originating_ip || "N/A"}</span>
                  {" "}·{" "}
                  Date: <span className="text-white/70">{result.envelope.date || "N/A"}</span>
                </div>
              </div>
              <div className={`flex items-center gap-2 px-4 py-2 rounded-xl border font-mono font-bold text-sm shrink-0 ${trustColor}`}>
                <span className="text-lg">{result.trust_score >= 80 ? "✓" : result.trust_score >= 50 ? "⚠" : "✕"}</span>
                {result.trust_score}/100 · {result.trust_rating}
              </div>
            </div>

            {/* Envelope grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 font-mono text-xs">
              {[
                ["FROM (Display Sender)",     result.envelope.from],
                ["RETURN-PATH (Envelope)",    result.envelope.return_path],
                ["TO (Recipient)",            result.envelope.to],
                ["MESSAGE-ID",               result.envelope.message_id],
              ].map(([label, val]) => (
                <div key={label as string} className="bg-void/60 border border-panelBorder/60 p-3 rounded-xl">
                  <span className="text-[9px] text-mist block uppercase tracking-widest mb-1">{label as string}</span>
                  <span className="text-white font-medium break-all">{(val as string) || "N/A"}</span>
                </div>
              ))}
            </div>
          </div>

          {/* SPF / DKIM / DMARC */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-signal border border-cyan-500/30">
                🔐 CRYPTOGRAPHIC EMAIL AUTH
              </span>
              <span className="text-[10px] font-mono text-mist/60">SPF · DKIM · DMARC</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <AuthVerdict label="SPF Verdict"      value={result.authentication.spf}   />
              <AuthVerdict label="DKIM Signature"   value={result.authentication.dkim}  />
              <AuthVerdict label="DMARC Alignment"  value={result.authentication.dmarc} />
            </div>
          </div>

          {/* MTA Hop Trace */}
          <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/30">
                📡 MTA DELIVERY HOP TRACE
              </span>
              <span className="text-[10px] font-mono text-mist/60">{result.delivery_hops.length} hops</span>
            </div>

            {result.delivery_hops.length > 0 ? (
              <div className="space-y-2">
                {result.delivery_hops.map((hop, idx) => (
                  <div key={idx} className="bg-void/60 border border-panelBorder/50 p-3.5 rounded-xl space-y-1.5 hover:border-panelBorder transition">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <span className="w-5 h-5 rounded-full bg-cyan-signal/15 text-cyan-signal text-[10px] flex items-center justify-center font-bold shrink-0">
                          {hop.hop_number}
                        </span>
                        <span className="text-xs font-mono font-bold text-white">{hop.by_host}</span>
                      </div>
                      {hop.ip && (
                        <span className="text-[10px] font-mono text-cyan-signal bg-void px-2 py-0.5 rounded border border-panelBorder/60">
                          {hop.ip}
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] font-mono text-mist flex flex-col sm:flex-row sm:justify-between gap-0.5 pl-7">
                      <span>From: <span className="text-white/80">{hop.from_host}</span></span>
                      <span className="text-mist/60">{hop.protocol}</span>
                    </div>
                    {hop.timestamp_raw && (
                      <div className="text-[10px] font-mono text-mist/40 pl-7">{hop.timestamp_raw}</div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs font-mono text-mist text-center py-6 bg-void/40 rounded-xl">
                No standard 'Received:' MTA headers found in the provided snippet.
              </div>
            )}
          </div>

          {/* Security flags */}
          {result.security_flags.length > 0 && (
            <div className="bg-panel border border-rose-500/20 rounded-2xl p-6 shadow-xl space-y-3 animate-slideUp">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                ⚠️ SPOOFING &amp; PHISHING ANOMALIES
              </span>
              <div className="space-y-2">
                {result.security_flags.map((flag, idx) => (
                  <div key={idx} className="flex items-start justify-between gap-3 bg-rose-500/8 border border-rose-500/25 p-3.5 rounded-xl">
                    <div className="min-w-0">
                      <div className="text-xs font-mono font-bold text-rose-400">{flag.type}</div>
                      <div className="text-[11px] font-mono text-mist/80 mt-0.5 leading-relaxed">{flag.description}</div>
                    </div>
                    <span className="shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded border bg-rose-500/20 text-rose-400 border-rose-500/40">
                      {flag.severity}
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
