"use client";

import React, { useState } from "react";

interface CommandDashboardProps {
  onSelectMode: (mode: string) => void;
  onQuickScan: (domain: string) => void;
}

export default function CommandDashboard({ onSelectMode, onQuickScan }: CommandDashboardProps) {
  const [quickDomain, setQuickDomain] = useState("");

  const SAMPLE_TARGETS = [
    { name: "cloudflare.com", tag: "CDN & Edge" },
    { name: "github.com", tag: "Code & Dev" },
    { name: "nasa.gov", tag: "Gov / Edu" },
    { name: "1.1.1.1", tag: "Public DNS IP" },
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickDomain.trim()) return;
    onQuickScan(quickDomain.trim());
  };

  const FEATURED_ENGINES = [
    {
      id: "domain",
      title: "Domain Recon Hub",
      icon: "🛡️",
      tag: "CORE SCANNER",
      desc: "Full-spectrum perimeter intelligence: DNS mapping, WHOIS, IP geolocation, SSL/TLS, port discovery, and technology stack fingerprinting.",
      accent: "#00F0FF",
      glowClass: "hover:shadow-[0_0_30px_rgba(0,240,255,0.25)] hover:border-cyan-400/60",
      badgeColor: "text-cyan-300 bg-cyan-950/80 border-cyan-500/40",
    },
    {
      id: "scorecard",
      title: "Cyber Threat Scorecard",
      icon: "📊",
      tag: "POSTURE & AUDIT",
      desc: "A+ to F security posture grading with 4 defense pillars (Transport, Headers, DNS, Anti-Spoofing) and instant remediation configs.",
      accent: "#10B981",
      glowClass: "hover:shadow-[0_0_30px_rgba(16,185,129,0.25)] hover:border-emerald-400/60",
      badgeColor: "text-emerald-300 bg-emerald-950/80 border-emerald-500/40",
    },
    {
      id: "subdomains",
      title: "Subdomain Enumerator",
      icon: "🌳",
      tag: "CERT TRANSPARENCY",
      desc: "Instant passive & active asset discovery using Certificate Transparency (crt.sh) logs and DNS brute correlation.",
      accent: "#38BDF8",
      glowClass: "hover:shadow-[0_0_30px_rgba(56,189,248,0.25)] hover:border-sky-400/60",
      badgeColor: "text-sky-300 bg-sky-950/80 border-sky-500/40",
    },
    {
      id: "dns",
      title: "DNS Record Intelligence",
      icon: "📡",
      tag: "NAMESERVER & MX",
      desc: "Deep record lookup for A, AAAA, MX, NS, TXT, CAA, SOA, CNAME records with DNSSEC validation status.",
      accent: "#3B82F6",
      glowClass: "hover:shadow-[0_0_30px_rgba(59,130,246,0.25)] hover:border-blue-400/60",
      badgeColor: "text-blue-300 bg-blue-950/80 border-blue-500/40",
    },
    {
      id: "ssl",
      title: "SSL/TLS Security Auditor",
      icon: "🔐",
      tag: "CRYPTO AUDITOR",
      desc: "Deep cryptographic audit: validity timelines, certificate issuer chain, SANs, cipher protocols, and expiration alerts.",
      accent: "#10B981",
      glowClass: "hover:shadow-[0_0_30px_rgba(16,185,129,0.25)] hover:border-emerald-400/60",
      badgeColor: "text-emerald-300 bg-emerald-950/80 border-emerald-500/40",
    },
    {
      id: "headers",
      title: "Security Headers Analyzer",
      icon: "📋",
      tag: "HARDENING AUDIT",
      desc: "Evaluates CSP, HSTS, X-Frame-Options, CORS headers, Permissions-Policy, and cookie security flags.",
      accent: "#14B8A6",
      glowClass: "hover:shadow-[0_0_30px_rgba(20,184,166,0.25)] hover:border-teal-400/60",
      badgeColor: "text-teal-300 bg-teal-950/80 border-teal-500/40",
    },
    {
      id: "ip",
      title: "IP Threat & Geolocation",
      icon: "🌐",
      tag: "GEO & ASN INTEL",
      desc: "Extract IP coordinates, ISP carrier, Autonomous System (ASN), reverse PTR records, and malicious abuse scores.",
      accent: "#818CF8",
      glowClass: "hover:shadow-[0_0_30px_rgba(129,140,248,0.25)] hover:border-indigo-400/60",
      badgeColor: "text-indigo-300 bg-indigo-950/80 border-indigo-500/40",
    },
    {
      id: "whois",
      title: "WHOIS & Registrar Forensics",
      icon: "🕵️",
      tag: "REGISTRY INTEL",
      desc: "Domain registrant data, creation & expiry timestamps, raw registry telemetry, and privacy protection indicators.",
      accent: "#C084FC",
      glowClass: "hover:shadow-[0_0_30px_rgba(192,132,252,0.25)] hover:border-purple-400/60",
      badgeColor: "text-purple-300 bg-purple-950/80 border-purple-500/40",
    },
    {
      id: "sandbox",
      title: "URL & File Sandbox",
      icon: "🧪",
      tag: "DYNAMIC DETONATION",
      desc: "Live behavioral analysis for suspicious URLs and files with heuristic threat scoring and redirect tracking.",
      accent: "#A855F7",
      glowClass: "hover:shadow-[0_0_30px_rgba(168,85,247,0.25)] hover:border-violet-400/60",
      badgeColor: "text-violet-300 bg-violet-950/80 border-violet-500/40",
    },
    {
      id: "pwned",
      title: "Breach & Credential Hunter",
      icon: "☠️",
      tag: "15B+ LEAK RECORDS",
      desc: "Search global exposed database breaches for compromised organizational emails, passwords, and data leaks.",
      accent: "#F43F5E",
      glowClass: "hover:shadow-[0_0_30px_rgba(244,63,94,0.25)] hover:border-rose-400/60",
      badgeColor: "text-rose-300 bg-rose-950/80 border-rose-500/40",
    },
    {
      id: "cve",
      title: "CVE Exploit Database",
      icon: "🚨",
      tag: "NIST NVD VULNS",
      desc: "Query national vulnerability databases with real-time CVSS v3.1 severity scores, CWE vectors, and exploit links.",
      accent: "#F59E0B",
      glowClass: "hover:shadow-[0_0_30px_rgba(245,158,11,0.25)] hover:border-amber-400/60",
      badgeColor: "text-amber-300 bg-amber-950/80 border-amber-500/40",
    },
    {
      id: "email",
      title: "Email Security & DMARC/SPF",
      icon: "📧",
      tag: "ANTI-SPOOFING",
      desc: "Audit email authentication mechanisms (DMARC, SPF, DKIM, MX) to mitigate phishing and sender impersonation.",
      accent: "#FB923C",
      glowClass: "hover:shadow-[0_0_30px_rgba(251,146,60,0.25)] hover:border-orange-400/60",
      badgeColor: "text-orange-300 bg-orange-950/80 border-orange-500/40",
    },
    {
      id: "attack_map",
      title: "3D Live Attack Globe",
      icon: "🌍",
      tag: "REALTIME 3D WAR ROOM",
      desc: "Interactive 3D WebGL cyber attack simulator with real-time vector arcs, live threat telemetry, and DEFCON levels.",
      accent: "#22D3EE",
      glowClass: "hover:shadow-[0_0_35px_rgba(34,211,238,0.3)] hover:border-cyan-300/70",
      badgeColor: "text-cyan-200 bg-cyan-950/90 border-cyan-400/60",
    },
  ];

  const QUICK_ACTIONS = [
    { id: "toolkit", icon: "🔧", label: "Swiss Army Sec Toolkit", desc: "Hashes, subnet CIDR, decoders" },
    { id: "topology", icon: "🕸️", label: "Attack Topology Graph", desc: "Node & exploit vector mapping" },
    { id: "report", icon: "📑", label: "Executive Pentest Report", desc: "Audit summary & PDF export" },
  ];

  return (
    <div className="w-full max-w-6xl mx-auto space-y-8 animate-fadeIn py-2 relative z-10">
      
      {/* ── Hero Glassmorphic Command Section ── */}
      <div className="relative overflow-hidden rounded-3xl cyber-card p-6 sm:p-10 border border-white/15 shadow-[0_20px_50px_rgba(0,0,0,0.8)] backdrop-blur-2xl">
        
        {/* Glow Spheres */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/15 rounded-full blur-[100px] pointer-events-none -mr-24 -mt-24" />
        <div className="absolute bottom-0 left-0 w-80 h-80 bg-blue-600/15 rounded-full blur-[100px] pointer-events-none -ml-24 -mb-24" />
        
        {/* Animated Scanner Line */}
        <div className="cyber-scanner-line" />

        <div className="relative z-10 flex flex-col items-center text-center max-w-3xl mx-auto space-y-5">
          
          {/* Top Cyber Badge */}
          <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-400/40 text-cyan-300 text-xs font-mono shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#00F0FF]" />
            <span className="font-bold tracking-wider">THUNDER RECON v4.0</span>
            <span className="text-cyan-400/40">|</span>
            <span className="text-slate-300">MIL-SPEC CYBER SUITE</span>
          </div>

          {/* Heading */}
          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight font-display text-white leading-tight">
            Offensive Reconnaissance &amp; Attack Surface Intelligence
          </h1>

          <p className="text-sm sm:text-base text-slate-300 max-w-2xl font-sans leading-relaxed">
            High-precision intelligence platform providing instant domain reconnaissance, passive DNS &amp; SSL cryptography analysis, breach hunting, and real-time vulnerability scans.
          </p>

          {/* Main Quick Scanner Bar */}
          <form onSubmit={handleSubmit} className="w-full max-w-2xl mt-2">
            <div className="flex flex-col sm:flex-row gap-2 p-2 rounded-2xl bg-black/80 border border-white/20 backdrop-blur-xl shadow-2xl focus-within:border-cyan-400 focus-within:ring-4 focus-within:ring-cyan-500/20 transition-all duration-300">
              <div className="flex-1 flex items-center px-3.5 gap-2.5">
                <span className="text-cyan-400 font-mono text-lg drop-shadow-[0_0_8px_rgba(0,240,255,0.8)]">⚡</span>
                <input
                  type="text"
                  value={quickDomain}
                  onChange={(e) => setQuickDomain(e.target.value)}
                  placeholder="Enter domain or IP (e.g. cloudflare.com, 1.1.1.1)..."
                  className="w-full bg-transparent text-white placeholder-slate-400 text-sm font-mono focus:outline-none"
                />
              </div>
              <button
                type="submit"
                className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-400 via-cyan-500 to-blue-600 hover:from-cyan-300 hover:to-blue-500 text-black font-extrabold text-xs tracking-wider uppercase font-mono shadow-[0_0_20px_rgba(6,182,212,0.4)] hover:shadow-[0_0_30px_rgba(6,182,212,0.7)] transition-all duration-200 flex items-center justify-center gap-2"
              >
                <span>Launch Recon</span>
                <span className="text-sm font-bold">→</span>
              </button>
            </div>
          </form>

          {/* 1-Click Sample Target Quick-Launch Pills */}
          <div className="flex flex-wrap items-center justify-center gap-2 pt-1">
            <span className="text-[11px] font-mono text-slate-400">Quick Test:</span>
            {SAMPLE_TARGETS.map((sample) => (
              <button
                key={sample.name}
                type="button"
                onClick={() => {
                  setQuickDomain(sample.name);
                  onQuickScan(sample.name);
                }}
                className="cyber-glow-pill px-2.5 py-1 rounded-lg text-[11px] font-mono text-slate-300 hover:text-cyan-300 hover:border-cyan-400/60 transition-all flex items-center gap-1.5"
              >
                <span className="text-cyan-400">⚡</span>
                <span className="font-semibold">{sample.name}</span>
                <span className="text-[9px] text-slate-400">({sample.tag})</span>
              </button>
            ))}
          </div>

          {/* Real-time Status Badges */}
          <div className="pt-3 border-t border-white/10 w-full flex flex-wrap items-center justify-center gap-5 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#10B981]" />
              <span className="text-slate-200 font-semibold">14 Verified Engines Online</span>
            </div>
            <span className="text-white/20 hidden sm:inline">•</span>
            <div className="flex items-center gap-1.5">
              <span className="text-cyan-400 font-bold">⚡</span>
              <span>Sub-Second CT Logs</span>
            </div>
            <span className="text-white/20 hidden sm:inline">•</span>
            <div className="flex items-center gap-1.5">
              <span className="text-purple-400">🛡️</span>
              <span>NIST NVD Live Sync</span>
            </div>
            <span className="text-white/20 hidden sm:inline">•</span>
            <div className="flex items-center gap-1.5">
              <span className="text-amber-400">🌐</span>
              <span>Global Threat Nodes</span>
            </div>
          </div>

        </div>
      </div>

      {/* ── Featured Core Tools Grid ── */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold font-display text-white flex items-center gap-2">
            <span className="text-cyan-400 drop-shadow-[0_0_8px_rgba(0,240,255,0.8)]">⚡</span>
            Core Intelligence Tools
          </h2>
          <span className="text-xs font-mono text-slate-400">Select any engine to open</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {FEATURED_ENGINES.map((tool) => (
            <button
              key={tool.id}
              onClick={() => onSelectMode(tool.id)}
              className={`text-left rounded-2xl cyber-card p-5 border border-white/10 ${tool.glowClass} transition-all duration-300 flex flex-col justify-between group shadow-lg cursor-pointer bg-[#0c121e]/75 backdrop-blur-xl relative overflow-hidden`}
            >
              <div className="relative z-10">
                <div className="flex items-center justify-between mb-3.5">
                  <span className="text-2xl p-2.5 rounded-xl bg-white/5 border border-white/10 group-hover:scale-110 group-hover:border-white/20 transition-all duration-300 shadow-inner">
                    {tool.icon}
                  </span>
                  <span className={`text-[9px] font-mono font-bold px-2.5 py-1 rounded-md border uppercase tracking-wider ${tool.badgeColor}`}>
                    {tool.tag}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white group-hover:text-cyan-300 transition-colors font-display">
                  {tool.title}
                </h3>
                <p className="text-xs text-slate-400 mt-2 line-clamp-2 font-sans leading-relaxed">
                  {tool.desc}
                </p>
              </div>

              <div className="relative z-10 mt-4 pt-3 border-t border-white/10 flex items-center justify-between text-xs font-mono text-cyan-400/80 group-hover:text-cyan-300">
                <span className="font-semibold">Launch Tool</span>
                <span className="group-hover:translate-x-1.5 transition-transform duration-200 font-bold">→</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* ── Operations & Swiss Utilities ── */}
      <div className="rounded-3xl cyber-card p-6 border border-white/15 shadow-2xl backdrop-blur-2xl">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-4">
          <div>
            <h3 className="text-base font-bold font-display text-white flex items-center gap-2">
              <span className="text-cyan-400">⚙️</span>
              Tactical Operations &amp; Swiss Sec Utilities
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Advanced calculators, cryptographic hash generators, attack path topology, and exportable pentest audits.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {QUICK_ACTIONS.map((qa) => (
            <button
              key={qa.id}
              onClick={() => onSelectMode(qa.id)}
              className="flex items-center gap-3 p-3.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 hover:border-cyan-400/50 transition-all text-left group cursor-pointer shadow-md hover:shadow-[0_0_20px_rgba(6,182,212,0.2)]"
            >
              <span className="text-2xl p-2 rounded-lg bg-black/40 border border-white/10 group-hover:scale-110 transition-transform">
                {qa.icon}
              </span>
              <div>
                <div className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">
                  {qa.label}
                </div>
                <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                  {qa.desc}
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>

    </div>
  );
}
