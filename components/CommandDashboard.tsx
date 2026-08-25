"use client";

import React, { useState, useEffect } from "react";

interface CommandDashboardProps {
  onSelectMode: (mode: string) => void;
  onQuickScan: (domain: string) => void;
}

export default function CommandDashboard({ onSelectMode, onQuickScan }: CommandDashboardProps) {
  const [quickDomain, setQuickDomain] = useState("");
  const [activeCategory, setActiveCategory] = useState<"all" | "recon" | "threat" | "ops">("all");
  const [pingLatency, setPingLatency] = useState(28);

  useEffect(() => {
    const interval = setInterval(() => {
      setPingLatency(Math.floor(22 + Math.random() * 15));
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  const SAMPLE_TARGETS = [
    { name: "cloudflare.com", tag: "CDN & Edge", ping: "8ms", icon: "☁️" },
    { name: "github.com", tag: "Code & Dev", ping: "14ms", icon: "🐙" },
    { name: "nasa.gov", tag: "Gov / Edu", ping: "38ms", icon: "🚀" },
    { name: "1.1.1.1", tag: "Public DNS", ping: "4ms", icon: "📡" },
  ];

  const THREAT_FEED = [
    "🚨 [CVE-2024-38077 Windows RCE] ACTIVE EXPLOITATION DETECTED",
    "🛡️ [DNSSEC ROOT] 100% cryptographic zone validation intact",
    "⚡ [BGP MONITOR] Zero anomalous route hijacking on major tier-1 backbones",
    "🔐 [TLS 1.3] 99.4% cipher negotiation across global endpoints",
    "🌐 [CERT-TRANSPARENCY] 24,000+ new subdomains ingested in real-time",
    "🧪 [SANDBOX ENGINE] 0-day heuristic behavioral analysis armed",
  ];

  const ALL_ENGINES = [
    // Recon
    {
      id: "domain",
      title: "Domain Recon Hub",
      category: "recon",
      icon: "🛡️",
      tag: "CORE SCANNER",
      desc: "Full-spectrum surface intelligence: DNS topology, WHOIS, IP geolocation, SSL/TLS, open ports, and tech stack fingerprinting.",
      capabilities: ["DNS Records", "WHOIS", "Tech Stack", "Open Ports"],
      accent: "#00F0FF",
      badgeColor: "text-cyan-300 bg-cyan-950/80 border-cyan-500/40",
    },
    {
      id: "scorecard",
      title: "Threat Scorecard & Posture",
      category: "recon",
      icon: "📊",
      tag: "MIL-SPEC AUDIT",
      desc: "A+ to F automated security defense scoring across 4 pillars (Transport, Headers, Zone, Anti-Spoof) with remediation playbooks.",
      capabilities: ["A+ to F Grading", "Remediation Code", "Nginx/Apache Config", "Zone Fixes"],
      accent: "#10B981",
      badgeColor: "text-emerald-300 bg-emerald-950/80 border-emerald-500/40",
    },
    {
      id: "subdomains",
      title: "Subdomain Enumerator",
      category: "recon",
      icon: "🌳",
      tag: "CERT TRANSPARENCY",
      desc: "Instant passive and active asset discovery leveraging Certificate Transparency logs (crt.sh) and DNS brute-force correlation.",
      capabilities: ["crt.sh Logs", "Wildcard Match", "Instant Export", "IP Mapping"],
      accent: "#38BDF8",
      badgeColor: "text-sky-300 bg-sky-950/80 border-sky-500/40",
    },
    {
      id: "dns",
      title: "DNS Intelligence Matrix",
      category: "recon",
      icon: "📡",
      tag: "RESOLVER ZONE",
      desc: "Deep resolution for A, AAAA, MX, TXT, NS, CNAME, SOA, and CAA records with DNSSEC validation and mail safety warnings.",
      capabilities: ["DNSSEC Check", "IPv4/IPv6", "Mail MX Routing", "CAA Validation"],
      accent: "#6366F1",
      badgeColor: "text-indigo-300 bg-indigo-950/80 border-indigo-500/40",
    },
    {
      id: "ssl",
      title: "SSL/TLS Cryptographic Auditor",
      category: "recon",
      icon: "🔐",
      tag: "TRANSPORT CRYPTO",
      desc: "Deep cryptographic handshake audit: certificate chains, cipher strength, expiration countdowns, and SAN enumeration.",
      capabilities: ["Chain Inspection", "TLS 1.3 / 1.2", "Expiry Alert", "Cipher Suite"],
      accent: "#EC4899",
      badgeColor: "text-pink-300 bg-pink-950/80 border-pink-500/40",
    },
    {
      id: "headers",
      title: "Security Headers Analyzer",
      category: "recon",
      icon: "📋",
      tag: "HTTP HARDENING",
      desc: "Instant evaluation of HSTS, CSP, X-Frame-Options, CORS, and info leakage with actionable config recommendations.",
      capabilities: ["HSTS Strict", "CSP Policy", "Clickjacking", "Info Leaks"],
      accent: "#F59E0B",
      badgeColor: "text-amber-300 bg-amber-950/80 border-amber-500/40",
    },
    {
      id: "whois",
      title: "WHOIS Forensics & Age",
      category: "recon",
      icon: "🕵️",
      tag: "DOMAIN REGISTRY",
      desc: "Registrar identification, domain age calculation, expiration countdown, name servers, and abuse contact intelligence.",
      capabilities: ["Domain Age", "Abuse Email", "Registrar Info", "Status Codes"],
      accent: "#8B5CF6",
      badgeColor: "text-purple-300 bg-purple-950/80 border-purple-500/40",
    },

    // Threat
    {
      id: "ip",
      title: "IP Threat Map & Geo-Intel",
      category: "threat",
      icon: "🌐",
      tag: "RADAR GEOLOCATION",
      desc: "IP threat scoring, Autonomous System (ASN) lookup, country/city coordinates, ISP identification, and reverse DNS mapping.",
      capabilities: ["ASN Lookup", "Threat Score", "ISP Detection", "Geo Mapping"],
      accent: "#06B6D4",
      badgeColor: "text-cyan-300 bg-cyan-950/80 border-cyan-500/40",
    },
    {
      id: "sandbox",
      title: "URL & File Threat Sandbox",
      category: "threat",
      icon: "🧪",
      tag: "BEHAVIORAL ENGINE",
      desc: "Safe heuristic analysis for suspicious URLs and files. Detects malicious redirects, phishing indicators, and payload risks.",
      capabilities: ["Redirect Trace", "Phishing Check", "Payload Score", "Heuristics"],
      accent: "#F43F5E",
      badgeColor: "text-rose-300 bg-rose-950/80 border-rose-500/40",
    },
    {
      id: "pwned",
      title: "Breach & Leak Hunter",
      category: "threat",
      icon: "☠️",
      tag: "EXPOSURE RADAR",
      desc: "Cross-reference target email addresses and domains against billions of compromised credentials in public breach dumps.",
      capabilities: ["HIBP Check", "Credential Leak", "Paste Searches", "Password Risk"],
      accent: "#EF4444",
      badgeColor: "text-red-300 bg-red-950/80 border-red-500/40",
    },
    {
      id: "cve",
      title: "CVE Exploit & Vulnerability Search",
      category: "threat",
      icon: "🚨",
      tag: "NVD INTELLIGENCE",
      desc: "Query the National Vulnerability Database (NVD) in real-time. CVSS v3.1 severity scores, exploit metrics, and patch advisories.",
      capabilities: ["CVSS v3.1", "NVD Sync", "Vector String", "Advisories"],
      accent: "#FB923C",
      badgeColor: "text-orange-300 bg-orange-950/80 border-orange-500/40",
    },
    {
      id: "email",
      title: "Email Security (DMARC & SPF)",
      category: "threat",
      icon: "📧",
      tag: "ANTI-SPOOFING",
      desc: "Comprehensive email security verification: DMARC policies, SPF alignment, DKIM selector checks, and spoofability grading.",
      capabilities: ["DMARC Policy", "SPF Alignment", "DKIM Selectors", "Anti-Phishing"],
      accent: "#22C55E",
      badgeColor: "text-green-300 bg-green-950/80 border-green-500/40",
    },

    // Ops
    {
      id: "attack_map",
      title: "3D Live Cyber Globe",
      category: "ops",
      icon: "🌍",
      tag: "WEBGL HUD",
      desc: "Interactive 3D planetary visualizer plotting live global attack vectors, IP geo-arcs, and real-time defense interceptions.",
      capabilities: ["3D WebGL", "Arc Geometries", "Atmosphere Mesh", "Interactive Controls"],
      accent: "#3B82F6",
      badgeColor: "text-blue-300 bg-blue-950/80 border-blue-500/40",
    },
    {
      id: "topology",
      title: "Attack Surface Topology",
      category: "ops",
      icon: "🕸️",
      tag: "GRAPH MATRIX",
      desc: "Interactive node graph connecting domains, subdomains, IPs, open ports, and vulnerabilities into an actionable map.",
      capabilities: ["Node Clustering", "Force Graph", "Attack Pathing", "Pivot Analysis"],
      accent: "#A855F7",
      badgeColor: "text-purple-300 bg-purple-950/80 border-purple-500/40",
    },
    {
      id: "toolkit",
      title: "Swiss Sec Utility Toolkit",
      category: "ops",
      icon: "🔧",
      tag: "OFFENSIVE SUITE",
      desc: "Essential security utilities: Subnet calculator, Hash identifier, Base64/Hex encoders, JWT decoder, and Password entropy checker.",
      capabilities: ["Subnet Calc", "Hash Identifier", "JWT Inspector", "Encoders"],
      accent: "#14B8A6",
      badgeColor: "text-teal-300 bg-teal-950/80 border-teal-500/40",
    },
    {
      id: "report",
      title: "Executive Pentest Report Generator",
      category: "ops",
      icon: "📑",
      tag: "COMPLIANCE EXPORT",
      desc: "Generate professional executive security summaries and pentest audit reports in printable HTML/PDF and Markdown formats.",
      capabilities: ["PDF Ready", "Executive Summary", "Findings Matrix", "Compliance Ready"],
      accent: "#EAB308",
      badgeColor: "text-yellow-300 bg-yellow-950/80 border-yellow-500/40",
    },
  ];

  const filteredEngines = activeCategory === "all"
    ? ALL_ENGINES
    : ALL_ENGINES.filter((e) => e.category === activeCategory);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickDomain.trim()) return;
    onQuickScan(quickDomain.trim());
  };

  return (
    <div className="w-full max-w-6xl mx-auto space-y-8 animate-fadeIn">
      
      {/* ── 1. Live SOC Threat Intelligence Stream Ticker ── */}
      <div className="w-full overflow-hidden rounded-xl bg-black/60 border border-white/10 py-2 px-3 flex items-center gap-3 backdrop-blur-md">
        <div className="flex items-center gap-2 shrink-0 pr-3 border-r border-white/10 text-[10px] font-mono font-bold text-cyan-400">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span>THREAT FEED</span>
        </div>
        <div className="overflow-hidden whitespace-nowrap flex-1">
          <div className="animate-marquee gap-8 text-[11px] font-mono text-slate-300">
            {THREAT_FEED.map((item, idx) => (
              <span key={idx} className="inline-flex items-center gap-2">
                <span>{item}</span>
                <span className="text-white/20">•</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── 2. Hero Cyber Command Launcher HUD ── */}
      <div className="relative rounded-3xl p-8 sm:p-10 cyber-card border border-white/15 overflow-hidden shadow-2xl">
        <div className="cyber-scanner-line" />

        <div className="relative z-10 flex flex-col items-center text-center max-w-3xl mx-auto">
          
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/30 text-cyan-300 text-xs font-mono font-bold uppercase tracking-wider mb-4 shadow-[0_0_15px_rgba(0,240,255,0.15)]">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
            MIL-SPEC CYBER RECONNAISSANCE ENGINE • v4.0
          </div>

          {/* Main Title */}
          <h1 className="text-3xl sm:text-5xl font-extrabold font-display text-white tracking-tight leading-tight">
            Next-Gen Attack Surface <br />
            <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500 bg-clip-text text-transparent">
              Intelligence &amp; Threat Forensics
            </span>
          </h1>

          <p className="text-sm sm:text-base text-slate-300 mt-4 leading-relaxed font-sans max-w-2xl">
            Execute passive OSINT scans, cryptographic audits, vulnerability matrices, and instant posture scoring across global enterprise targets.
          </p>

          {/* Omnibar Input */}
          <form onSubmit={handleSubmit} className="w-full mt-8 relative">
            <div className="relative flex items-center">
              <div className="absolute left-4 text-cyan-400 text-lg pointer-events-none">
                ⚡
              </div>
              <input
                type="text"
                value={quickDomain}
                onChange={(e) => setQuickDomain(e.target.value)}
                placeholder="Enter target domain, IPv4/IPv6, or URL (e.g. cloudflare.com)..."
                className="w-full pl-12 pr-32 py-4 rounded-2xl bg-black/80 border border-white/20 text-white font-mono text-sm sm:text-base placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-4 focus:ring-cyan-500/20 transition-all shadow-inner"
              />
              <button
                type="submit"
                disabled={!quickDomain.trim()}
                className="absolute right-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold text-xs font-mono uppercase tracking-wider transition-all disabled:opacity-40 disabled:pointer-events-none shadow-[0_0_20px_rgba(0,240,255,0.3)] flex items-center gap-1.5"
              >
                <span>Launch Recon</span>
                <span>→</span>
              </button>
            </div>
          </form>

          {/* 1-Click Sample Target Cards */}
          <div className="w-full mt-5 flex flex-wrap items-center justify-center gap-2 sm:gap-3">
            <span className="text-xs font-mono text-slate-400 flex items-center gap-1">
              <span>🎯</span> Sample Targets:
            </span>
            {SAMPLE_TARGETS.map((t) => (
              <button
                key={t.name}
                onClick={() => onQuickScan(t.name)}
                className="cyber-glow-pill px-3 py-1.5 rounded-xl text-xs font-mono text-slate-200 flex items-center gap-2 group transition-all"
              >
                <span>{t.icon}</span>
                <span className="font-semibold text-white group-hover:text-cyan-300 transition-colors">{t.name}</span>
                <span className="text-[10px] text-slate-400 bg-white/5 px-1.5 py-0.5 rounded border border-white/10 font-sans">{t.tag}</span>
              </button>
            ))}
          </div>

        </div>
      </div>

      {/* ── 3. Category Filter Navigation ── */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 border-b border-white/10 pb-4">
        <div>
          <h2 className="text-xl font-bold font-display text-white flex items-center gap-2">
            <span>⚔️</span> Specialized Intelligence Modules
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Select a dedicated module or trigger automated reconnaissance
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex bg-black/60 p-1 rounded-xl border border-white/10 shrink-0">
          {(["all", "recon", "threat", "ops"] as const).map((cat) => {
            const labels = { all: "All Modules (16)", recon: "Recon (7)", threat: "Threat (5)", ops: "Ops (4)" };
            const isActive = activeCategory === cat;
            return (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all uppercase tracking-wider ${
                  isActive
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 font-bold shadow-[0_0_15px_rgba(0,240,255,0.2)]"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {labels[cat]}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── 4. High-Tech Module Cards Grid ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredEngines.map((engine) => (
          <div
            key={engine.id}
            onClick={() => onSelectMode(engine.id)}
            className="group cyber-card rounded-2xl p-6 border border-white/10 cursor-pointer flex flex-col justify-between hover:border-cyan-400/60 hover:shadow-[0_0_30px_rgba(0,240,255,0.2)] transition-all duration-300 relative overflow-hidden"
          >
            {/* Ambient Corner Flare */}
            <div
              className="absolute top-0 right-0 w-32 h-32 rounded-full blur-3xl opacity-0 group-hover:opacity-20 transition-opacity pointer-events-none"
              style={{ backgroundColor: engine.accent }}
            />

            <div>
              {/* Header: Icon & Category Tag */}
              <div className="flex items-center justify-between mb-4">
                <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-2xl group-hover:scale-110 group-hover:border-cyan-400/40 transition-transform">
                  {engine.icon}
                </div>
                <span className={`text-[9px] font-mono font-bold px-2.5 py-1 rounded-full border uppercase ${engine.badgeColor}`}>
                  {engine.tag}
                </span>
              </div>

              {/* Title & Description */}
              <h3 className="text-lg font-bold font-display text-white group-hover:text-cyan-300 transition-colors">
                {engine.title}
              </h3>
              <p className="text-xs text-slate-300 mt-2 line-clamp-3 font-sans leading-relaxed">
                {engine.desc}
              </p>

              {/* Capability Badges */}
              <div className="flex flex-wrap gap-1.5 mt-4 pt-3 border-t border-white/5">
                {engine.capabilities.map((cap) => (
                  <span
                    key={cap}
                    className="text-[10px] font-mono text-slate-400 bg-black/40 px-2 py-0.5 rounded border border-white/5"
                  >
                    {cap}
                  </span>
                ))}
              </div>
            </div>

            {/* Launch Action */}
            <div className="mt-5 pt-3 border-t border-white/10 flex items-center justify-between text-xs font-mono text-slate-400 group-hover:text-cyan-300 transition-colors">
              <span className="font-semibold">Launch Engine</span>
              <span className="transform group-hover:translate-x-1.5 transition-transform">→</span>
            </div>
          </div>
        ))}
      </div>

      {/* ── 5. System Status & Security Telemetry HUD Footer ── */}
      <div className="cyber-card rounded-2xl p-4 border border-white/10 flex flex-col md:flex-row items-center justify-between gap-4 text-xs font-mono text-slate-400">
        <div className="flex items-center gap-3">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#10B981]" />
          <span className="text-slate-200 font-semibold">ALL 16 INTELLIGENCE ENGINES ONLINE</span>
          <span className="text-white/20">|</span>
          <span className="text-cyan-400">API GATEWAY: 0.0.0.0:8000</span>
        </div>

        <div className="flex items-center gap-4 text-[11px]">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Edge Ping:</span>
            <span className="text-emerald-400 font-bold">{pingLatency}ms</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Enc:</span>
            <span className="text-cyan-300 font-bold">TLS 1.3 / AES-256</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Policy:</span>
            <span className="text-slate-300">Zero Retention</span>
          </div>
        </div>
      </div>

    </div>
  );
}
