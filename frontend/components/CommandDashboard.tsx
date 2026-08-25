"use client";

import React, { useState, useEffect } from "react";
import dynamic from "next/dynamic";

const RealWorldThreatMap = dynamic(() => import("./RealWorldThreatMap"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-[460px] bg-[#030712] rounded-2xl border border-white/10 flex items-center justify-center text-xs font-mono text-cyan-400">
      <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping mr-2.5"></span>
      Initializing High-Resolution Geographic CartoDB Stream...
    </div>
  ),
});

interface CommandDashboardProps {
  onSelectMode: (mode: string) => void;
  onQuickScan: (domain: string) => void;
}

export default function CommandDashboard({ onSelectMode, onQuickScan }: CommandDashboardProps) {
  const [quickDomain, setQuickDomain] = useState("");
  const [activeCategory, setActiveCategory] = useState<"all" | "recon" | "threat" | "ops">("all");
  const [ddosBandwidth, setDdosBandwidth] = useState(524);
  const [packetRate, setPacketRate] = useState(342);
  const [activeBotCount, setActiveBotCount] = useState(412800);

  // Periodic Telemetry Pulse
  useEffect(() => {
    const timer = setInterval(() => {
      setDdosBandwidth(Math.floor(480 + Math.random() * 110));
      setPacketRate(Math.floor(310 + Math.random() * 70));
      setActiveBotCount((prev) => prev + Math.floor((Math.random() - 0.47) * 150));
    }, 2500);

    return () => clearInterval(timer);
  }, []);

  const SECTORS = [
    { name: "Financial & Banking", percent: 34, attacks: "1.4M / hr", color: "bg-rose-500" },
    { name: "Healthcare & Biotech", percent: 24, attacks: "890K / hr", color: "bg-amber-500" },
    { name: "Gov & Defense", percent: 20, attacks: "720K / hr", color: "bg-purple-500" },
    { name: "Cloud & Telecom", percent: 14, attacks: "510K / hr", color: "bg-cyan-500" },
    { name: "Energy & Infrastructure", percent: 8, attacks: "320K / hr", color: "bg-emerald-500" },
  ];

  const TOP_COUNTRIES_SRC = [
    { name: "United States", flag: "🇺🇸", vol: "28.4%", active: "High" },
    { name: "China", flag: "🇨🇳", vol: "22.1%", active: "Critical" },
    { name: "Russia", flag: "🇷🇺", vol: "18.6%", active: "Critical" },
    { name: "Brazil", flag: "🇧🇷", vol: "11.2%", active: "Elevated" },
    { name: "Germany", flag: "🇩🇪", vol: "8.5%", active: "Moderate" },
  ];

  const TOP_COUNTRIES_TGT = [
    { name: "United States", flag: "🇺🇸", vol: "38.2%", status: "Shielded" },
    { name: "United Kingdom", flag: "🇬🇧", vol: "16.4%", status: "Guarded" },
    { name: "Ukraine", flag: "🇺🇦", vol: "14.8%", status: "Targeted" },
    { name: "Germany", flag: "🇩🇪", vol: "12.1%", status: "Guarded" },
    { name: "Japan", flag: "🇯🇵", vol: "9.3%", status: "Defended" },
  ];

  const BOTNET_FAMILIES = [
    { name: "Mirai Variant", bots: "148,200 nodes", type: "IoT & Routers", status: "Active Attack" },
    { name: "Mozi Botnet", bots: "94,100 nodes", type: "DHT P2P Swarm", status: "Propagating" },
    { name: "DarkGate C2", bots: "46,800 nodes", type: "Infostealer", status: "Monitored" },
    { name: "Emotet Reborn", bots: "32,400 nodes", type: "Banking Trojan", status: "Contained" },
  ];

  const ALL_ENGINES = [
    {
      id: "domain",
      title: "Domain Recon Hub",
      category: "recon",
      icon: "🛡️",
      tag: "Core Scanner",
      desc: "Full-spectrum surface intelligence: DNS topology, WHOIS, IP geolocation, SSL/TLS, open ports, and tech stack fingerprinting.",
      capabilities: ["DNS Records", "WHOIS", "Tech Stack", "Open Ports"],
    },
    {
      id: "scorecard",
      title: "Threat Scorecard & Posture",
      category: "recon",
      icon: "📊",
      tag: "Security Audit",
      desc: "Automated defense posture scoring across 4 pillars (Transport, Headers, Zone, Anti-Spoof) with remediation playbooks.",
      capabilities: ["A+ to F Grading", "Remediation Code", "Config Fixes"],
    },
    {
      id: "subdomains",
      title: "Subdomain Enumerator",
      category: "recon",
      icon: "🌳",
      tag: "Cert Transparency",
      desc: "Passive asset discovery leveraging Certificate Transparency logs (crt.sh) and DNS correlation.",
      capabilities: ["crt.sh Logs", "Wildcard Match", "Instant Export"],
    },
    {
      id: "dns",
      title: "DNS Intelligence Matrix",
      category: "recon",
      icon: "📡",
      tag: "Resolver Zone",
      desc: "Deep resolution for A, AAAA, MX, TXT, NS, CNAME, SOA, and CAA records with DNSSEC validation.",
      capabilities: ["DNSSEC Check", "IPv4/IPv6", "Mail MX Routing"],
    },
    {
      id: "ssl",
      title: "SSL/TLS Cryptographic Auditor",
      category: "recon",
      icon: "🔐",
      tag: "Transport Crypto",
      desc: "Handshake audit: certificate chains, cipher strength, expiration countdowns, and SAN enumeration.",
      capabilities: ["Chain Inspection", "TLS 1.3 / 1.2", "Expiry Alert"],
    },
    {
      id: "headers",
      title: "Security Headers Analyzer",
      category: "recon",
      icon: "📋",
      tag: "HTTP Hardening",
      desc: "Evaluation of HSTS, CSP, X-Frame-Options, CORS, and info leakage with actionable recommendations.",
      capabilities: ["HSTS Strict", "CSP Policy", "Clickjacking"],
    },
    {
      id: "whois",
      title: "WHOIS Forensics & Age",
      category: "recon",
      icon: "🕵️",
      tag: "Domain Registry",
      desc: "Registrar identification, domain age calculation, expiration countdown, and abuse contact intelligence.",
      capabilities: ["Domain Age", "Abuse Contact", "Registrar Info"],
    },
    {
      id: "ip",
      title: "IP Threat Map & Geo-Intel",
      category: "threat",
      icon: "🌐",
      tag: "Geolocation",
      desc: "IP threat scoring, Autonomous System (ASN) lookup, country/city coordinates, and ISP identification.",
      capabilities: ["ASN Lookup", "Threat Score", "ISP Detection"],
    },
    {
      id: "sandbox",
      title: "URL & File Threat Sandbox",
      category: "threat",
      icon: "🧪",
      tag: "Behavioral",
      desc: "Safe heuristic analysis for suspicious URLs and files. Detects malicious redirects and phishing risks.",
      capabilities: ["Redirect Trace", "Phishing Check", "Payload Score"],
    },
    {
      id: "pwned",
      title: "Breach & Leak Hunter",
      category: "threat",
      icon: "☠️",
      tag: "Exposure Radar",
      desc: "Cross-reference target email addresses and domains against billions of compromised credentials in breach dumps.",
      capabilities: ["HIBP Check", "Credential Leak", "Paste Searches"],
    },
    {
      id: "cve",
      title: "CVE Threat Intelligence Feed",
      category: "threat",
      icon: "⚠️",
      tag: "Vuln Database",
      desc: "Real-time NIST NVD and CISA KEV feeds tracking zero-days, actively exploited CVEs, and CVSS scores.",
      capabilities: ["CISA KEV List", "CVSS 3.1 Scores", "Zero-Day Tracker"],
    },
    {
      id: "email",
      title: "Email Security & DMARC/SPF",
      category: "threat",
      icon: "📧",
      tag: "Anti-Spoofing",
      desc: "Audit email deliverability and spoof protection: SPF record syntax, DMARC policy, and DKIM discovery.",
      capabilities: ["DMARC Policy", "SPF Alignment", "DKIM Selectors"],
    },
    {
      id: "attack_map",
      title: "Tactical Attack Vector Radar",
      category: "ops",
      icon: "🌐",
      tag: "Live Vectors",
      desc: "Interactive tactical matrix visualizer plotting global attack vectors, IP geo-arcs, and defense telemetry.",
      capabilities: ["Tactical Matrix", "Arc Geometries", "Live Controls"],
    },
    {
      id: "topology",
      title: "Attack Surface Topology",
      category: "ops",
      icon: "🕸️",
      tag: "Graph Matrix",
      desc: "Interactive node graph connecting domains, subdomains, IPs, open ports, and vulnerabilities into an actionable map.",
      capabilities: ["Node Clustering", "Force Graph", "Attack Pathing"],
    },
    {
      id: "toolkit",
      title: "Swiss Sec Utility Toolkit",
      category: "ops",
      icon: "🔧",
      tag: "Security Tools",
      desc: "Essential security utilities: Subnet calculator, Hash identifier, Base64/Hex encoders, and JWT decoder.",
      capabilities: ["Subnet Calc", "Hash Identifier", "JWT Inspector"],
    },
    {
      id: "report",
      title: "Executive Pentest Report Generator",
      category: "ops",
      icon: "📑",
      tag: "Audit Export",
      desc: "Generate professional executive security summaries and pentest audit reports in printable HTML/PDF formats.",
      capabilities: ["PDF Ready", "Executive Summary", "Findings Matrix"],
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
    <div className="w-full max-w-7xl mx-auto space-y-12 animate-fadeIn px-2 sm:px-4 py-4">
      
      {/* ── 1. Hero Reconnaissance Launcher ── */}
      <div className="flex flex-col items-center text-center max-w-3xl mx-auto space-y-6 pt-2">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-white/[0.04] border border-white/10 text-slate-300 text-xs font-medium backdrop-blur-md">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span>Thunder Recon • Cyber Intelligence Platform</span>
        </div>

        <h1 className="text-4xl sm:text-6xl font-bold tracking-tight text-white leading-tight font-display">
          Surface Intelligence &amp; <br />
          <span className="bg-gradient-to-r from-teal-200 via-cyan-300 to-sky-400 bg-clip-text text-transparent">
            Threat Forensics
          </span>
        </h1>

        <p className="text-base text-slate-400 leading-relaxed font-sans max-w-2xl">
          Fast, passive OSINT reconnaissance, DNSSEC cryptographic auditing, vulnerability tracking, and security posture scoring.
        </p>

        {/* Omnibar Search Input */}
        <form onSubmit={handleSubmit} className="w-full max-w-2xl relative pt-2">
          <div className="relative flex items-center bg-[#0C1220]/90 border border-white/15 rounded-2xl p-2 shadow-2xl focus-within:border-cyan-400/60 focus-within:ring-4 focus-within:ring-cyan-500/10 transition-all">
            <span className="pl-4 text-slate-400 text-base">🔍</span>
            <input
              type="text"
              value={quickDomain}
              onChange={(e) => setQuickDomain(e.target.value)}
              placeholder="Enter domain, IPv4/IPv6 address, or URL..."
              className="w-full bg-transparent px-4 py-3 text-white placeholder-slate-500 font-sans text-sm sm:text-base outline-none"
            />
            <button
              type="submit"
              disabled={!quickDomain.trim()}
              className="btn-cyber-primary text-sm px-6 py-3 whitespace-nowrap disabled:opacity-40 disabled:pointer-events-none"
            >
              <span>Scan Target</span>
              <span>→</span>
            </button>
          </div>
        </form>
      </div>

      {/* ── 2. Real-World Geographic Global Cyber Threat & Attack Map ── */}
      <div className="cyber-card rounded-3xl p-6 sm:p-8 border border-white/10 relative overflow-hidden shadow-2xl space-y-6">
        
        {/* Header Strip */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-3.5 h-3.5 rounded-full bg-rose-500 animate-pulse shadow-[0_0_12px_#F43F5E]" />
            <div>
              <h2 className="text-lg font-bold text-white font-display flex items-center gap-2">
                Live Cyber Threat &amp; Attack Telemetry
              </h2>
              <p className="text-xs text-slate-400">
                Real-world interactive geographic map with named sovereign nodes, live satellite layers, and ballistic trajectory tracking
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono text-slate-300">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">DDoS Stream:</span>
              <strong className="text-rose-400">{ddosBandwidth} Gbps</strong>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400">Packet Rate:</span>
              <strong className="text-cyan-300">{packetRate} Mpps</strong>
            </div>
          </div>
        </div>

        {/* Real-World Leaflet Map Component */}
        <RealWorldThreatMap />

        {/* ── 3. Detail Grids: Botnets, Sectors & Countries ── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4 border-t border-white/10">
          
          {/* 3a. Active Botnet Swarms */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white font-display flex items-center gap-2">
                <span>🤖</span> Active Botnet C2 Swarms
              </h3>
              <span className="text-[11px] font-mono text-cyan-400">{activeBotCount.toLocaleString()} bots</span>
            </div>
            
            <div className="space-y-2">
              {BOTNET_FAMILIES.map((b) => (
                <div key={b.name} className="p-3 rounded-xl bg-white/[0.03] border border-white/5 flex items-center justify-between text-xs">
                  <div>
                    <div className="font-medium text-white">{b.name}</div>
                    <div className="text-[11px] text-slate-400">{b.type}</div>
                  </div>
                  <div className="text-right">
                    <div className="font-mono text-slate-300 font-semibold">{b.bots}</div>
                    <span className="text-[10px] text-amber-400 font-medium">{b.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* 3b. Targeted Industry Sectors */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-white font-display flex items-center gap-2">
              <span>🎯</span> Targeted Industry Sectors
            </h3>
            
            <div className="space-y-2.5">
              {SECTORS.map((s) => (
                <div key={s.name} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-300">{s.name}</span>
                    <span className="font-mono text-slate-400 text-[11px]">{s.percent}% • {s.attacks}</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-white/5 overflow-hidden">
                    <div className={`h-full rounded-full ${s.color}`} style={{ width: `${s.percent}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* 3c. Top Countries: Sources & Targets */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-white font-display flex items-center gap-2">
              <span>🌐</span> Cross-Border Telemetry
            </h3>

            <div className="space-y-2">
              <div className="text-[11px] text-slate-400 font-medium">Top Incident Sources:</div>
              <div className="grid grid-cols-2 gap-1.5">
                {TOP_COUNTRIES_SRC.map((c) => (
                  <div key={c.name} className="p-2 rounded-lg bg-white/[0.03] border border-white/5 flex items-center justify-between text-[11px]">
                    <span className="flex items-center gap-1.5 text-slate-200">
                      <span>{c.flag}</span>
                      <span className="truncate">{c.name}</span>
                    </span>
                    <span className="font-mono text-rose-400 font-semibold">{c.vol}</span>
                  </div>
                ))}
              </div>

              <div className="text-[11px] text-slate-400 font-medium pt-1">Top Targeted Destinations:</div>
              <div className="grid grid-cols-2 gap-1.5">
                {TOP_COUNTRIES_TGT.slice(0, 4).map((c) => (
                  <div key={c.name} className="p-2 rounded-lg bg-white/[0.03] border border-white/5 flex items-center justify-between text-[11px]">
                    <span className="flex items-center gap-1.5 text-slate-200">
                      <span>{c.flag}</span>
                      <span className="truncate">{c.name}</span>
                    </span>
                    <span className="font-mono text-cyan-300 font-semibold">{c.vol}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

        </div>

      </div>

      {/* ── 4. Intelligence Engine Category Switcher ── */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-white/5">
        <div>
          <h2 className="text-lg font-semibold text-white font-display">
            Specialized Intelligence Engines
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Launch dedicated tools for surface discovery, threat scoring, and forensic operations
          </p>
        </div>

        {/* Category Filter Pills */}
        <div className="flex bg-white/[0.03] p-1 rounded-xl border border-white/10 shrink-0 gap-1">
          {(["all", "recon", "threat", "ops"] as const).map((cat) => {
            const labels = { all: "All (16)", recon: "Recon (7)", threat: "Threat (5)", ops: "Ops (4)" };
            const isActive = activeCategory === cat;
            return (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? "bg-white/15 text-white font-semibold shadow-sm"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {labels[cat]}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── 5. Clean Module Cards Grid ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredEngines.map((engine) => (
          <div
            key={engine.id}
            onClick={() => onSelectMode(engine.id)}
            className="group cyber-card rounded-2xl p-6 border border-white/10 cursor-pointer flex flex-col justify-between hover:border-cyan-400/40 hover:bg-white/[0.04] transition-all duration-200"
          >
            <div>
              {/* Header: Icon & Tag */}
              <div className="flex items-center justify-between mb-4">
                <div className="w-10 h-10 rounded-xl bg-white/[0.05] border border-white/10 flex items-center justify-center text-xl group-hover:scale-105 transition-transform">
                  {engine.icon}
                </div>
                <span className="text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-white/[0.05] border border-white/10 text-slate-400">
                  {engine.tag}
                </span>
              </div>

              {/* Title & Description */}
              <h3 className="text-base font-semibold text-white group-hover:text-cyan-300 transition-colors font-display">
                {engine.title}
              </h3>
              <p className="text-xs text-slate-400 mt-2 line-clamp-2 leading-relaxed">
                {engine.desc}
              </p>

              {/* Capability Chips */}
              <div className="flex flex-wrap gap-1.5 mt-4 pt-3 border-t border-white/5">
                {engine.capabilities.map((cap) => (
                  <span
                    key={cap}
                    className="text-[11px] text-slate-400 bg-white/[0.03] px-2 py-0.5 rounded-md border border-white/5"
                  >
                    {cap}
                  </span>
                ))}
              </div>
            </div>

            {/* Bottom Action */}
            <div className="mt-5 pt-3 border-t border-white/5 flex items-center justify-between text-xs text-slate-400 group-hover:text-cyan-300 transition-colors">
              <span className="font-medium">Open Engine</span>
              <span className="transform group-hover:translate-x-1 transition-transform">→</span>
            </div>
          </div>
        ))}
      </div>

    </div>
  );
}
