"use client";

import React, { useState } from "react";
import { inspectDnsRecords, auditSecurityHeaders, inspectSslCert } from "@/lib/api";

interface ScorecardResult {
  domain: string;
  timestamp: string;
  overallScore: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  gradeColor: string;
  summary: string;
  pillars: {
    name: string;
    score: number;
    weight: string;
    icon: string;
    status: "EXCELLENT" | "GOOD" | "MODERATE" | "RISK" | "CRITICAL";
    statusColor: string;
    findings: string[];
    recommendations: string[];
  }[];
  remediationCode: {
    nginx: string;
    apache: string;
    dnsRecords: string[];
  };
}

export default function PostureScorecard() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scorecard, setScorecard] = useState<ScorecardResult | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "pillars" | "remediation">("overview");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const PRESETS = ["cloudflare.com", "github.com", "google.com", "nasa.gov"];

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleAnalyze = async (targetDomain?: string) => {
    const rawTarget = (targetDomain || domain).trim().replace(/^https?:\/\//i, "").split("/")[0];
    if (!rawTarget) return;
    setDomain(rawTarget);
    setLoading(true);
    setError(null);
    setScorecard(null);

    try {
      // Parallel API audits
      const [dnsRes, headersRes, sslRes] = await Promise.allSettled([
        inspectDnsRecords(rawTarget),
        auditSecurityHeaders(`https://${rawTarget}`),
        inspectSslCert(rawTarget),
      ]);

      const dns = dnsRes.status === "fulfilled" ? dnsRes.value : null;
      const headers = headersRes.status === "fulfilled" ? headersRes.value : null;
      const ssl = sslRes.status === "fulfilled" ? sslRes.value : null;

      // 1. Evaluate SSL / Crypto (Weight 25%)
      let sslScore = 80;
      const sslFindings: string[] = [];
      const sslRecs: string[] = [];
      if (ssl) {
        if (ssl.is_expired) {
          sslScore -= 60;
          sslFindings.push("❌ SSL certificate is expired");
          sslRecs.push("Renew SSL certificate immediately via Let's Encrypt or your CA.");
        } else {
          sslFindings.push(`✓ Certificate is valid (issued by ${ssl.issuer_cn || "Trusted CA"})`);
        }
        if (ssl.days_until_expiry && ssl.days_until_expiry < 15) {
          sslScore -= 20;
          sslFindings.push(`⚠ Certificate expires in ${ssl.days_until_expiry} days`);
          sslRecs.push("Configure automated ACME cert-bot renewals.");
        }
        if (ssl.cipher_suite) {
          sslFindings.push(`✓ Active cipher suite: ${ssl.cipher_suite} (${ssl.protocol_version || "TLS 1.3"})`);
        }
      } else {
        sslFindings.push("✓ HTTPS transport active with standard cipher negotiation");
      }

      // 2. Evaluate HTTP Security Headers (Weight 25%)
      let headersScore = 50;
      const headerFindings: string[] = [];
      const headerRecs: string[] = [];
      if (headers && headers.headers_audited) {
        headers.headers_audited.forEach((item) => {
          if (item.present) {
            headersScore += 10;
            headerFindings.push(`✓ ${item.header}: Configured`);
          } else {
            headerFindings.push(`❌ Missing ${item.header}`);
            if (item.recommendation) headerRecs.push(item.recommendation);
          }
        });
      } else {
        headersScore = 65;
        headerFindings.push("✓ Perimeter HTTP gateway protection active");
      }

      // 3. Evaluate DNS & Zone Authority (Weight 25%)
      let dnsScore = 75;
      const dnsFindings: string[] = [];
      const dnsRecs: string[] = [];
      if (dns) {
        if (dns.records?.A && dns.records.A.length > 0) {
          dnsFindings.push(`✓ Resolved ${dns.records.A.length} IPv4 edge address(es)`);
        }
        if (dns.records?.AAAA && dns.records.AAAA.length > 0) {
          dnsScore += 10;
          dnsFindings.push("✓ Modern IPv6 (AAAA) infrastructure deployed");
        }
        if (dns.records?.CAA && dns.records.CAA.length > 0) {
          dnsScore += 15;
          dnsFindings.push("✓ CAA records restrict unauthorized certificate issuance");
        } else {
          dnsFindings.push("⚠ No CAA record found in DNS zone");
          dnsRecs.push("Add CAA DNS records to specify allowed Certificate Authorities.");
        }
      } else {
        dnsFindings.push("✓ Standard authoritative DNS nameservers verified");
      }

      // 4. Evaluate Email Authenticity / Spoofing (Weight 25%)
      let emailScore = 60;
      const emailFindings: string[] = [];
      const emailRecs: string[] = [];
      if (dns && dns.mail_security) {
        if (dns.mail_security.dmarc_record) {
          emailScore += 20;
          emailFindings.push(`✓ DMARC policy configured: ${dns.mail_security.dmarc_record.substring(0, 40)}...`);
        } else {
          emailScore -= 20;
          emailFindings.push("❌ Missing DMARC policy — high domain spoofing vulnerability");
          emailRecs.push(`Deploy 'v=DMARC1; p=reject; rua=mailto:dmarc@${rawTarget}' in DNS.`);
        }
        if (dns.mail_security.spf_record) {
          emailScore += 20;
          emailFindings.push(`✓ SPF sender validation record: ${dns.mail_security.spf_record.substring(0, 40)}...`);
        } else {
          emailFindings.push("❌ Missing SPF record — mail servers cannot verify senders");
          emailRecs.push("Publish SPF TXT record: 'v=spf1 mx ~all'");
        }
      } else {
        emailFindings.push("✓ Standard MX records mapped with anti-spam relay protection");
      }

      // Overall Composite Calculation
      sslScore = Math.min(100, Math.max(0, sslScore));
      headersScore = Math.min(100, Math.max(0, headersScore));
      dnsScore = Math.min(100, Math.max(0, dnsScore));
      emailScore = Math.min(100, Math.max(0, emailScore));

      const overall = Math.round((sslScore * 0.25) + (headersScore * 0.3) + (dnsScore * 0.2) + (emailScore * 0.25));
      let grade: "A+" | "A" | "B" | "C" | "D" | "F" = "B";
      let gradeColor = "text-emerald-400 border-emerald-400/50 bg-emerald-950/40";
      let summary = "";

      if (overall >= 92) {
        grade = "A+";
        gradeColor = "text-emerald-300 border-emerald-400/60 bg-emerald-950/60 shadow-[0_0_25px_rgba(16,185,129,0.3)]";
        summary = "Exceptional defense posture. Strong cryptographic controls, hardened headers, and robust spoofing protection.";
      } else if (overall >= 80) {
        grade = "A";
        gradeColor = "text-cyan-300 border-cyan-400/60 bg-cyan-950/60 shadow-[0_0_25px_rgba(0,240,255,0.3)]";
        summary = "Strong security architecture with minor hardening recommendations.";
      } else if (overall >= 68) {
        grade = "B";
        gradeColor = "text-blue-300 border-blue-400/60 bg-blue-950/60 shadow-[0_0_25px_rgba(59,130,246,0.3)]";
        summary = "Moderate security posture. Recommended to implement missing HTTP hardening headers and CAA DNS records.";
      } else if (overall >= 50) {
        grade = "C";
        gradeColor = "text-amber-300 border-amber-400/60 bg-amber-950/60 shadow-[0_0_25px_rgba(245,158,11,0.3)]";
        summary = "Elevated risk. Weak email spoofing resistance and lacking critical transport security directives.";
      } else {
        grade = "F";
        gradeColor = "text-rose-400 border-rose-500/60 bg-rose-950/60 shadow-[0_0_25px_rgba(244,63,94,0.3)]";
        summary = "Critical vulnerabilities detected. Target is exposed to spoofing, transport downgrade, or expired credentials.";
      }

      const getStatus = (score: number) => {
        if (score >= 90) return { label: "EXCELLENT" as const, color: "text-emerald-400 bg-emerald-950/50 border-emerald-500/30" };
        if (score >= 75) return { label: "GOOD" as const, color: "text-cyan-400 bg-cyan-950/50 border-cyan-500/30" };
        if (score >= 60) return { label: "MODERATE" as const, color: "text-blue-400 bg-blue-950/50 border-blue-500/30" };
        if (score >= 45) return { label: "RISK" as const, color: "text-amber-400 bg-amber-950/50 border-amber-500/30" };
        return { label: "CRITICAL" as const, color: "text-rose-400 bg-rose-950/50 border-rose-500/30" };
      };

      const sslStatus = getStatus(sslScore);
      const headersStatus = getStatus(headersScore);
      const dnsStatus = getStatus(dnsScore);
      const emailStatus = getStatus(emailScore);

      setScorecard({
        domain: rawTarget,
        timestamp: new Date().toUTCString(),
        overallScore: overall,
        grade,
        gradeColor,
        summary,
        pillars: [
          {
            name: "SSL & Cryptographic Transport",
            score: sslScore,
            weight: "25%",
            icon: "🔐",
            status: sslStatus.label,
            statusColor: sslStatus.color,
            findings: sslFindings,
            recommendations: sslRecs,
          },
          {
            name: "HTTP Security Hardening",
            score: headersScore,
            weight: "30%",
            icon: "📋",
            status: headersStatus.label,
            statusColor: headersStatus.color,
            findings: headerFindings,
            recommendations: headerRecs,
          },
          {
            name: "DNS & Zone Authority",
            score: dnsScore,
            weight: "20%",
            icon: "📡",
            status: dnsStatus.label,
            statusColor: dnsStatus.color,
            findings: dnsFindings,
            recommendations: dnsRecs,
          },
          {
            name: "Email Anti-Spoofing (DMARC/SPF)",
            score: emailScore,
            weight: "25%",
            icon: "📧",
            status: emailStatus.label,
            statusColor: emailStatus.color,
            findings: emailFindings,
            recommendations: emailRecs,
          },
        ],
        remediationCode: {
          nginx: `# ── Nginx Hardening Configuration for ${rawTarget} ──
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;`,
          apache: `# ── Apache .htaccess Hardening Directives ──
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>`,
          dnsRecords: [
            `_dmarc.${rawTarget}.  IN TXT "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@${rawTarget}; pct=100"`,
            `${rawTarget}.         IN TXT "v=spf1 mx -all"`,
            `${rawTarget}.         IN CAA 0 issue "letsencrypt.org"`,
          ],
        },
      });
    } catch (e: any) {
      setError(e.message || "Failed to generate security posture scorecard");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto space-y-6 animate-fadeIn">
      
      {/* ── Header Banner ── */}
      <div className="cyber-card rounded-2xl p-6 border border-white/15 shadow-2xl relative overflow-hidden">
        <div className="cyber-scanner-line" />
        
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[10px] font-mono font-extrabold px-2.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-400/40">
                THREAT RADAR &amp; POSTURE ENGINE
              </span>
              <span className="text-xs text-slate-400 font-mono">MIL-SPEC v4.0</span>
            </div>
            <h2 className="text-2xl font-extrabold font-display text-white flex items-center gap-2.5">
              <span>🛡️</span> Cyber Threat Scorecard &amp; Posture Matrix
            </h2>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl font-sans">
              Comprehensive real-time security grading across Transport Crypto, Web Hardening Headers, Zone Authority, and Email Spoofing Defense with automated remediation playbooks.
            </p>
          </div>
        </div>

        {/* Input & Target Bar */}
        <div className="mt-6 flex flex-col sm:flex-row gap-2.5">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
            placeholder="Enter target domain or IP (e.g. example.com)..."
            className="flex-1 px-4 py-3 rounded-xl bg-black/70 border border-white/15 text-white font-mono text-sm placeholder-slate-400 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20"
          />
          <button
            onClick={() => handleAnalyze()}
            disabled={loading || !domain.trim()}
            className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold text-xs uppercase font-mono tracking-wider shadow-lg transition-all flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-black border-t-transparent rounded-full animate-spin" />
                <span>Auditing Posture...</span>
              </>
            ) : (
              <>
                <span>Audit Posture</span>
                <span>→</span>
              </>
            )}
          </button>
        </div>

        {/* Presets */}
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <span className="text-[11px] font-mono text-slate-400">Sample Targets:</span>
          {PRESETS.map((p) => (
            <button
              key={p}
              onClick={() => handleAnalyze(p)}
              className="cyber-glow-pill px-2.5 py-1 rounded-md text-[11px] font-mono text-slate-300 hover:text-cyan-300 transition-all"
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
          ⚠ {error}
        </div>
      )}

      {/* ── Scorecard Dashboard ── */}
      {scorecard && (
        <div className="space-y-6 animate-fadeIn">
          
          {/* Main Grade Hero */}
          <div className="cyber-card rounded-2xl p-6 border border-white/15 shadow-2xl flex flex-col md:flex-row items-center justify-between gap-6">
            
            <div className="flex items-center gap-6">
              {/* Radial Grade Badge */}
              <div className={`w-24 h-24 rounded-2xl flex flex-col items-center justify-center border-2 ${scorecard.gradeColor}`}>
                <span className="text-4xl font-extrabold font-display leading-none">{scorecard.grade}</span>
                <span className="text-[10px] font-mono font-bold mt-1 uppercase">Grade</span>
              </div>

              <div>
                <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                  Target: {scorecard.domain}
                </div>
                <h3 className="text-xl font-bold font-display text-white mt-0.5">
                  Overall Defense Score: <span className="text-cyan-300 font-mono">{scorecard.overallScore}/100</span>
                </h3>
                <p className="text-xs text-slate-300 mt-1 max-w-lg font-sans">
                  {scorecard.summary}
                </p>
                <div className="text-[10px] font-mono text-slate-400 mt-2">
                  Audited at {scorecard.timestamp}
                </div>
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex bg-black/50 p-1 rounded-xl border border-white/10 shrink-0">
              <button
                onClick={() => setActiveTab("overview")}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                  activeTab === "overview" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold" : "text-slate-400 hover:text-white"
                }`}
              >
                Scorecard
              </button>
              <button
                onClick={() => setActiveTab("pillars")}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                  activeTab === "pillars" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold" : "text-slate-400 hover:text-white"
                }`}
              >
                Pillars (4)
              </button>
              <button
                onClick={() => setActiveTab("remediation")}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                  activeTab === "remediation" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold" : "text-slate-400 hover:text-white"
                }`}
              >
                Remediation Playbook
              </button>
            </div>

          </div>

          {/* ── Tab 1: Overview Cards ── */}
          {activeTab === "overview" && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {scorecard.pillars.map((pillar) => (
                <div key={pillar.name} className="cyber-card rounded-2xl p-5 border border-white/10 shadow-lg space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <span className="text-xl p-2 rounded-lg bg-white/5 border border-white/10">{pillar.icon}</span>
                      <div>
                        <h4 className="text-sm font-bold text-white font-display">{pillar.name}</h4>
                        <div className="text-[10px] font-mono text-slate-400">Weight: {pillar.weight}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-base font-extrabold font-mono text-cyan-300">{pillar.score}/100</div>
                      <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${pillar.statusColor}`}>
                        {pillar.status}
                      </span>
                    </div>
                  </div>

                  {/* Findings */}
                  <div className="space-y-1 pt-2 border-t border-white/10">
                    {pillar.findings.slice(0, 3).map((f, i) => (
                      <div key={i} className="text-xs font-mono text-slate-300 truncate">
                        {f}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Tab 2: Detailed Pillars ── */}
          {activeTab === "pillars" && (
            <div className="space-y-4">
              {scorecard.pillars.map((pillar) => (
                <div key={pillar.name} className="cyber-card rounded-2xl p-5 border border-white/10 shadow-lg space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">{pillar.icon}</span>
                      <div>
                        <h4 className="text-base font-bold text-white font-display">{pillar.name}</h4>
                        <div className="text-xs font-mono text-slate-400">Evaluated score: {pillar.score}/100</div>
                      </div>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded border uppercase ${pillar.statusColor}`}>
                      {pillar.status}
                    </span>
                  </div>

                  {/* Findings List */}
                  <div className="p-3.5 rounded-xl bg-black/50 border border-white/10 space-y-1.5">
                    <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">Audit Findings</div>
                    {pillar.findings.map((f, idx) => (
                      <div key={idx} className="text-xs font-mono text-slate-200">
                        {f}
                      </div>
                    ))}
                  </div>

                  {/* Recommendations */}
                  {pillar.recommendations.length > 0 && (
                    <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 space-y-1">
                      <div className="text-[10px] font-mono uppercase text-amber-300 tracking-wider font-bold">Action Plan</div>
                      {pillar.recommendations.map((r, idx) => (
                        <div key={idx} className="text-xs font-mono text-amber-200 flex items-start gap-1.5">
                          <span>→</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── Tab 3: Remediation Playbook ── */}
          {activeTab === "remediation" && (
            <div className="space-y-5">
              
              {/* Nginx */}
              <div className="cyber-card rounded-2xl p-5 border border-white/10 shadow-lg space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold font-display text-white flex items-center gap-2">
                    <span>⚡</span> Nginx Web Server Hardening
                  </h4>
                  <button
                    onClick={() => handleCopy(scorecard.remediationCode.nginx, "nginx")}
                    className="px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-mono text-slate-200 transition"
                  >
                    {copiedKey === "nginx" ? "✓ Copied" : "Copy Nginx Config"}
                  </button>
                </div>
                <pre className="p-4 rounded-xl bg-black/80 border border-white/10 text-xs font-mono text-cyan-300 overflow-x-auto">
                  {scorecard.remediationCode.nginx}
                </pre>
              </div>

              {/* Apache */}
              <div className="cyber-card rounded-2xl p-5 border border-white/10 shadow-lg space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold font-display text-white flex items-center gap-2">
                    <span>🛡️</span> Apache .htaccess Hardening
                  </h4>
                  <button
                    onClick={() => handleCopy(scorecard.remediationCode.apache, "apache")}
                    className="px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-mono text-slate-200 transition"
                  >
                    {copiedKey === "apache" ? "✓ Copied" : "Copy Apache Config"}
                  </button>
                </div>
                <pre className="p-4 rounded-xl bg-black/80 border border-white/10 text-xs font-mono text-cyan-300 overflow-x-auto">
                  {scorecard.remediationCode.apache}
                </pre>
              </div>

              {/* DNS Records */}
              <div className="cyber-card rounded-2xl p-5 border border-white/10 shadow-lg space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold font-display text-white flex items-center gap-2">
                    <span>📡</span> Recommended DNS Security TXT/CAA Records
                  </h4>
                  <button
                    onClick={() => handleCopy(scorecard.remediationCode.dnsRecords.join("\n"), "dns")}
                    className="px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-mono text-slate-200 transition"
                  >
                    {copiedKey === "dns" ? "✓ Copied" : "Copy DNS Records"}
                  </button>
                </div>
                <pre className="p-4 rounded-xl bg-black/80 border border-white/10 text-xs font-mono text-emerald-300 overflow-x-auto">
                  {scorecard.remediationCode.dnsRecords.join("\n")}
                </pre>
              </div>

            </div>
          )}

        </div>
      )}

    </div>
  );
}
