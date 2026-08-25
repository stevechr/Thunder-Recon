"use client";

import React, { useState, useEffect, useRef } from "react";

interface CommandDashboardProps {
  onSelectMode: (mode: string) => void;
  onQuickScan: (domain: string) => void;
}

interface CountryNode {
  id: string;
  name: string;
  code: string;
  flag: string;
  x: number; // Percentage 0-100 on 1000x500 viewBox
  y: number;
  color: string;
  region: "americas" | "europe" | "apac" | "mea";
  traffic: string;
  status: string;
}

interface LiveArc {
  id: string;
  src: CountryNode;
  tgt: CountryNode;
  progress: number;
  speed: number;
  color: string;
  type: string;
  bw: string;
}

// 22 Accurately Positioned Real-World Countries on 1000x500 Equirectangular Map
const REAL_COUNTRIES: CountryNode[] = [
  // Americas
  { id: "usa", name: "United States", code: "USA", flag: "🇺🇸", x: 230, y: 175, color: "#38BDF8", region: "americas", traffic: "184 Gbps", status: "Shield Active" },
  { id: "can", name: "Canada", code: "CAN", flag: "🇨🇦", x: 215, y: 110, color: "#38BDF8", region: "americas", traffic: "42 Gbps", status: "Guarded" },
  { id: "bra", name: "Brazil", code: "BRA", flag: "🇧🇷", x: 360, y: 345, color: "#F43F5E", region: "americas", traffic: "96 Gbps", status: "Attack Origin" },
  { id: "mex", name: "Mexico", code: "MEX", flag: "🇲🇽", x: 210, y: 225, color: "#FBBF24", region: "americas", traffic: "31 Gbps", status: "Monitored" },
  { id: "arg", name: "Argentina", code: "ARG", flag: "🇦🇷", x: 335, y: 420, color: "#38BDF8", region: "americas", traffic: "18 Gbps", status: "Stable" },

  // Europe
  { id: "gbr", name: "United Kingdom", code: "GBR", flag: "🇬🇧", x: 485, y: 135, color: "#00F5D4", region: "europe", traffic: "128 Gbps", status: "SOC Defense" },
  { id: "deu", name: "Germany", code: "DEU", flag: "🇩🇪", x: 525, y: 140, color: "#00F5D4", region: "europe", traffic: "115 Gbps", status: "Scrubbing Center" },
  { id: "fra", name: "France", code: "FRA", flag: "🇫🇷", x: 500, y: 155, color: "#00F5D4", region: "europe", traffic: "89 Gbps", status: "Guarded" },
  { id: "nld", name: "Netherlands", code: "NLD", flag: "🇳🇱", x: 512, y: 132, color: "#00F5D4", region: "europe", traffic: "140 Gbps", status: "IXP Hub Shielded" },
  { id: "ukr", name: "Ukraine", code: "UKR", flag: "🇺🇦", x: 585, y: 145, color: "#FFB703", region: "europe", traffic: "94 Gbps", status: "Critical Target" },
  { id: "rus", name: "Russia", code: "RUS", flag: "🇷🇺", x: 690, y: 110, color: "#F43F5E", region: "europe", traffic: "210 Gbps", status: "High Threat Swarm" },

  // Asia-Pacific
  { id: "chn", name: "China", code: "CHN", flag: "🇨🇳", x: 775, y: 195, color: "#F43F5E", region: "apac", traffic: "260 Gbps", status: "C2 Swarm Detected" },
  { id: "ind", name: "India", code: "IND", flag: "🇮🇳", x: 705, y: 245, color: "#FFB703", region: "apac", traffic: "145 Gbps", status: "DDoS Mitigation" },
  { id: "jpn", name: "Japan", code: "JPN", flag: "🇯🇵", x: 875, y: 180, color: "#38BDF8", region: "apac", traffic: "88 Gbps", status: "Hardened" },
  { id: "kor", name: "South Korea", code: "KOR", flag: "🇰🇷", x: 840, y: 185, color: "#38BDF8", region: "apac", traffic: "74 Gbps", status: "Target Defended" },
  { id: "sgp", name: "Singapore", code: "SGP", flag: "🇸🇬", x: 780, y: 310, color: "#00F5D4", region: "apac", traffic: "112 Gbps", status: "Secure Gateway" },
  { id: "aus", name: "Australia", code: "AUS", flag: "🇦🇺", x: 870, y: 395, color: "#38BDF8", region: "apac", traffic: "65 Gbps", status: "Protected" },

  // Middle East & Africa
  { id: "are", name: "UAE", code: "ARE", flag: "🇦🇪", x: 645, y: 235, color: "#00F5D4", region: "mea", traffic: "58 Gbps", status: "Cloud Flare Active" },
  { id: "zaf", name: "South Africa", code: "ZAF", flag: "🇿🇦", x: 555, y: 410, color: "#F43F5E", region: "mea", traffic: "44 Gbps", status: "Botnet Surge" },
  { id: "sau", name: "Saudi Arabia", code: "SAU", flag: "🇸🇦", x: 620, y: 230, color: "#FBBF24", region: "mea", traffic: "39 Gbps", status: "Monitored" },
  { id: "egy", name: "Egypt", code: "EGY", flag: "🇪🇬", x: 575, y: 215, color: "#00F5D4", region: "mea", traffic: "28 Gbps", status: "Stable" },
  { id: "nga", name: "Nigeria", code: "NGA", flag: "🇳🇬", x: 505, y: 285, color: "#F43F5E", region: "mea", traffic: "33 Gbps", status: "Phishing Hub" },
];

const ATTACK_VECTORS = [
  { name: "Volumetric UDP/DNS Amp", color: "#F43F5E", minBw: 80, maxBw: 185 },
  { name: "Mirai C2 IoT Swarm", color: "#FFB703", minBw: 30, maxBw: 75 },
  { name: "HTTP/2 Rapid Reset Exploit", color: "#00F5D4", minBw: 45, maxBw: 110 },
  { name: "SYN Flood Exfiltration", color: "#A855F7", minBw: 20, maxBw: 55 },
  { name: "BGP Route Hijack Attempt", color: "#38BDF8", minBw: 60, maxBw: 130 },
];

export default function CommandDashboard({ onSelectMode, onQuickScan }: CommandDashboardProps) {
  const [quickDomain, setQuickDomain] = useState("");
  const [activeCategory, setActiveCategory] = useState<"all" | "recon" | "threat" | "ops">("all");
  const [selectedRegion, setSelectedRegion] = useState<"all" | "americas" | "europe" | "apac" | "mea">("all");
  const [selectedCountry, setSelectedCountry] = useState<CountryNode | null>(null);
  const [activeArcs, setActiveArcs] = useState<LiveArc[]>([]);
  const [ddosBandwidth, setDdosBandwidth] = useState(524);
  const [packetRate, setPacketRate] = useState(342);
  const [activeBotCount, setActiveBotCount] = useState(412800);
  const [recentVectors, setRecentVectors] = useState<Array<{ id: number; text: string; color: string }>>([
    { id: 1, text: "🇨🇳 China ➔ 🇺🇸 United States • UDP Amp (142 Gbps)", color: "#F43F5E" },
    { id: 2, text: "🇷🇺 Russia ➔ 🇺🇦 Ukraine • Mirai C2 Swarm (68 Gbps)", color: "#FFB703" },
    { id: 3, text: "🇧🇷 Brazil ➔ 🇬🇧 United Kingdom • HTTP/2 Reset", color: "#00F5D4" },
  ]);

  // Periodic Telemetry Pulse & Live Arcs Generator
  useEffect(() => {
    const timer = setInterval(() => {
      setDdosBandwidth(Math.floor(480 + Math.random() * 110));
      setPacketRate(Math.floor(310 + Math.random() * 70));
      setActiveBotCount((prev) => prev + Math.floor((Math.random() - 0.47) * 150));

      const sIdx = Math.floor(Math.random() * REAL_COUNTRIES.length);
      let tIdx = Math.floor(Math.random() * REAL_COUNTRIES.length);
      while (tIdx === sIdx) tIdx = Math.floor(Math.random() * REAL_COUNTRIES.length);

      const src = REAL_COUNTRIES[sIdx];
      const tgt = REAL_COUNTRIES[tIdx];
      const type = ATTACK_VECTORS[Math.floor(Math.random() * ATTACK_VECTORS.length)];
      const bw = `${Math.floor(type.minBw + Math.random() * (type.maxBw - type.minBw))} Gbps`;

      const newArc: LiveArc = {
        id: Math.random().toString(36).substring(7),
        src,
        tgt,
        progress: 0,
        speed: 0.016 + Math.random() * 0.012,
        color: type.color,
        type: type.name,
        bw,
      };

      setActiveArcs((prev) => [...prev.slice(-7), newArc]);

      setRecentVectors((prev) => [
        {
          id: Date.now() + Math.random(),
          text: `${src.flag} ${src.name} ➔ ${tgt.flag} ${tgt.name} • ${type.name} (${bw})`,
          color: type.color,
        },
        ...prev.slice(0, 2),
      ]);
    }, 2200);

    return () => clearInterval(timer);
  }, []);

  // Animation Loop for Trajectory Progress
  useEffect(() => {
    let animId: number;
    const updateArcs = () => {
      setActiveArcs((prev) =>
        prev
          .map((arc) => ({ ...arc, progress: arc.progress + arc.speed }))
          .filter((arc) => arc.progress < 1.05)
      );
      animId = requestAnimationFrame(updateArcs);
    };
    animId = requestAnimationFrame(updateArcs);
    return () => cancelAnimationFrame(animId);
  }, []);

  const filteredCountries = selectedRegion === "all"
    ? REAL_COUNTRIES
    : REAL_COUNTRIES.filter((c) => c.region === selectedRegion);

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

      {/* ── 2. Real-World Global Cyber Threat & Attack Map ── */}
      <div className="cyber-card rounded-3xl p-6 sm:p-8 border border-white/10 relative overflow-hidden shadow-2xl space-y-6">
        
        {/* Header Strip & Region Selectors */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-white/10 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-3.5 h-3.5 rounded-full bg-rose-500 animate-pulse shadow-[0_0_12px_#F43F5E]" />
            <div>
              <h2 className="text-lg font-bold text-white font-display flex items-center gap-2">
                Live Cyber Threat &amp; Attack Telemetry
              </h2>
              <p className="text-xs text-slate-400">
                Real-world high-definition global vector map with named sovereign nodes and ballistic trajectory tracking
              </p>
            </div>
          </div>

          {/* Region Filter Buttons */}
          <div className="flex items-center gap-1.5 bg-white/[0.04] p-1 rounded-xl border border-white/10 self-stretch md:self-auto overflow-x-auto">
            {(["all", "americas", "europe", "apac", "mea"] as const).map((reg) => {
              const labels = { all: "Global", americas: "Americas", europe: "Europe", apac: "Asia-Pacific", mea: "Middle East & Africa" };
              return (
                <button
                  key={reg}
                  onClick={() => setSelectedRegion(reg)}
                  className={`px-3 py-1 text-xs rounded-lg font-medium whitespace-nowrap transition-all ${
                    selectedRegion === reg
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 shadow-sm"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {labels[reg]}
                </button>
              );
            })}
          </div>
        </div>

        {/* Real World Geographic Vector SVG Map Container */}
        <div className="w-full relative rounded-2xl bg-[#030712] border border-white/10 overflow-hidden shadow-inner aspect-[2/1] min-h-[380px] max-h-[520px]">
          
          {/* SVG Real World Map */}
          <svg
            viewBox="0 0 1000 500"
            className="w-full h-full block select-none"
            style={{ filter: "drop-shadow(0 0 20px rgba(0,245,212,0.05))" }}
          >
            <defs>
              {/* Gradients */}
              <radialGradient id="oceanGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#0B1528" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#030712" stopOpacity="1" />
              </radialGradient>
              <linearGradient id="landGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#0F1F38" />
                <stop offset="100%" stopColor="#081426" />
              </linearGradient>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Ocean Background */}
            <rect width="1000" height="500" fill="url(#oceanGlow)" />

            {/* Tactical Coordinate Grid (Latitude & Longitude) */}
            <g stroke="rgba(255,255,255,0.04)" strokeWidth="1">
              {[100, 200, 300, 400, 500, 600, 700, 800, 900].map((x) => (
                <line key={`x-${x}`} x1={x} y1="0" x2={x} y2="500" />
              ))}
              {[75, 150, 225, 300, 375, 450].map((y) => (
                <line key={`y-${y}`} x1="0" y1={y} x2="1000" y2={y} />
              ))}
              {/* Equator & Prime Meridian */}
              <line x1="0" y1="250" x2="1000" y2="250" stroke="rgba(0,245,212,0.15)" strokeDasharray="4 4" />
              <line x1="500" y1="0" x2="500" y2="500" stroke="rgba(0,245,212,0.15)" strokeDasharray="4 4" />
            </g>

            {/* High-Fidelity Vector World Continents & Landmasses */}
            <g fill="url(#landGradient)" stroke="rgba(0, 245, 212, 0.28)" strokeWidth="1.2" strokeLinejoin="round">
              {/* North America (Canada, USA, Alaska, Mexico, Central America) */}
              <path d="M 120 70 Q 140 50 170 55 Q 210 40 260 55 Q 310 65 315 90 Q 295 100 270 120 Q 285 135 295 160 Q 275 190 260 210 Q 235 210 220 230 Q 200 260 175 240 Q 160 215 145 170 Q 115 140 100 100 Z" />
              {/* Greenland */}
              <path d="M 330 35 Q 370 25 390 45 Q 380 85 345 80 Q 320 65 330 35 Z" />
              {/* Caribbean Islands */}
              <path d="M 270 230 Q 290 225 300 240 Q 280 250 270 230 Z" />
              
              {/* South America (Colombia, Brazil, Peru, Chile, Argentina) */}
              <path d="M 275 255 Q 315 250 355 270 Q 400 310 390 360 Q 360 410 330 460 Q 310 465 310 430 Q 300 370 280 320 Q 265 285 275 255 Z" />

              {/* Europe (UK & Ireland) */}
              <path d="M 470 115 Q 490 110 495 130 Q 485 150 465 145 Z" />
              {/* Europe Main (Scandinavia, Western & Central Europe, Mediterranean) */}
              <path d="M 500 80 Q 535 60 555 80 Q 545 110 520 125 Q 550 135 565 155 Q 540 185 500 185 Q 480 170 490 145 Q 485 120 500 80 Z" />
              
              {/* Eurasia / Russia & North Asia */}
              <path d="M 565 75 Q 630 50 720 50 Q 820 60 880 90 Q 860 120 800 130 Q 750 120 680 125 Q 610 110 565 75 Z" />

              {/* East Asia & China */}
              <path d="M 700 135 Q 780 135 830 160 Q 835 210 785 235 Q 730 225 710 180 Z" />

              {/* Japan */}
              <path d="M 865 150 Q 885 160 880 195 Q 860 190 865 150 Z" />

              {/* South Asia & India */}
              <path d="M 680 200 Q 735 205 735 240 Q 715 280 690 280 Q 670 240 680 200 Z" />

              {/* Southeast Asia */}
              <path d="M 750 240 Q 795 245 800 280 Q 770 300 750 270 Z" />
              {/* Indonesia / Philippines archipelago */}
              <path d="M 770 320 Q 820 315 840 335 Q 800 350 770 320 Z" />

              {/* Middle East & Arabian Peninsula */}
              <path d="M 600 190 Q 650 195 655 240 Q 625 260 595 230 Z" />

              {/* Africa */}
              <path d="M 480 200 Q 575 190 595 240 Q 610 300 575 365 Q 545 425 515 420 Q 465 350 460 280 Q 460 230 480 200 Z" />
              {/* Madagascar */}
              <path d="M 610 360 Q 625 365 620 405 Q 605 400 610 360 Z" />

              {/* Australia & New Zealand */}
              <path d="M 810 360 Q 880 340 920 375 Q 910 435 840 435 Q 800 405 810 360 Z" />
              <path d="M 940 420 Q 960 415 955 450 Q 935 445 940 420 Z" />
            </g>

            {/* Dotted Geo Matrix Overlay for Modern Threat-Map Texture */}
            <g fill="rgba(0, 245, 212, 0.22)">
              {/* North America dots */}
              {[
                [180,110],[210,95],[240,110],[190,140],[225,145],[260,150],[190,180],[225,185],[255,190],[210,220]
              ].map(([dx, dy], i) => (
                <circle key={`na-${i}`} cx={dx} cy={dy} r="1.4" />
              ))}
              {/* South America dots */}
              {[
                [310,280],[340,295],[320,330],[355,340],[330,380],[320,420]
              ].map(([dx, dy], i) => (
                <circle key={`sa-${i}`} cx={dx} cy={dy} r="1.4" />
              ))}
              {/* Europe dots */}
              {[
                [480,125],[510,115],[535,110],[500,145],[525,145],[550,140],[520,165],[555,165]
              ].map(([dx, dy], i) => (
                <circle key={`eu-${i}`} cx={dx} cy={dy} r="1.4" />
              ))}
              {/* Asia & Russia dots */}
              {[
                [610,95],[660,90],[715,90],[770,95],[825,100],[680,150],[730,155],[780,160],[830,165],[700,220],[750,210],[795,215]
              ].map(([dx, dy], i) => (
                <circle key={`as-${i}`} cx={dx} cy={dy} r="1.4" />
              ))}
              {/* Africa dots */}
              {[
                [510,230],[550,230],[500,270],[540,280],[575,280],[520,330],[555,340],[535,390]
              ].map(([dx, dy], i) => (
                <circle key={`af-${i}`} cx={dx} cy={dy} r="1.4" />
              ))}
              {/* Australia dots */}
              {[
                [840,380],[875,375],[850,405],[885,405]
              ].map(([dx, dy], i) => (
                <circle key={`oc-${i}`} cx={dx} cy={dy} r="1.4" />
              ))}
            </g>

            {/* Dynamic Ballistic Attack Trajectory Arcs */}
            <g>
              {activeArcs.map((arc) => {
                const sx = arc.src.x;
                const sy = arc.src.y;
                const tx = arc.tgt.x;
                const ty = arc.tgt.y;
                const mx = (sx + tx) / 2;
                const my = Math.min(sy, ty) - 55;

                // Current head position along quadratic Bezier curve
                const t = Math.min(1, arc.progress);
                const cx = (1 - t) * (1 - t) * sx + 2 * (1 - t) * t * mx + t * t * tx;
                const cy = (1 - t) * (1 - t) * sy + 2 * (1 - t) * t * my + t * t * ty;

                const pathD = `M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`;

                return (
                  <g key={arc.id}>
                    {/* Glowing Trajectory Arc */}
                    <path
                      d={pathD}
                      fill="none"
                      stroke={arc.color}
                      strokeWidth="1.5"
                      strokeOpacity="0.45"
                      strokeDasharray="4 3"
                    />
                    {/* Animated Leading Laser Missile Head */}
                    <circle
                      cx={cx}
                      cy={cy}
                      r="3.5"
                      fill={arc.color}
                      filter="url(#glow)"
                      className="animate-pulse"
                    />
                    {/* Particle Glow Core */}
                    <circle cx={cx} cy={cy} r="1.8" fill="#FFFFFF" />
                  </g>
                );
              })}
            </g>

            {/* Real Named Sovereign Country Beacons & Labels */}
            <g>
              {filteredCountries.map((c) => {
                const isSelected = selectedCountry?.id === c.id;
                return (
                  <g
                    key={c.id}
                    className="cursor-pointer group"
                    onClick={() => setSelectedCountry(c)}
                  >
                    {/* Radar wave pulse ring */}
                    <circle
                      cx={c.x}
                      cy={c.y}
                      r="8"
                      fill="none"
                      stroke={c.color}
                      strokeWidth="1"
                      strokeOpacity="0.4"
                      className="animate-ping"
                      style={{ transformOrigin: `${c.x}px ${c.y}px`, animationDuration: "3s" }}
                    />

                    {/* Outer hover halo */}
                    <circle
                      cx={c.x}
                      cy={c.y}
                      r={isSelected ? 6.5 : 4.5}
                      fill={c.color}
                      fillOpacity={isSelected ? "0.4" : "0.2"}
                      stroke={c.color}
                      strokeWidth="1.2"
                    />

                    {/* Inner core dot */}
                    <circle cx={c.x} cy={c.y} r="2.5" fill="#FFFFFF" />

                    {/* Country Name Tag with Flag */}
                    <g transform={`translate(${c.x + 8}, ${c.y + 3})`}>
                      {/* Dark badge backdrop */}
                      <rect
                        x="-2"
                        y="-10"
                        width={c.name.length * 5.8 + 22}
                        height="14"
                        rx="4"
                        fill="#060C18"
                        fillOpacity="0.85"
                        stroke={isSelected ? c.color : "rgba(255,255,255,0.15)"}
                        strokeWidth="0.8"
                      />
                      <text
                        x="2"
                        y="0"
                        fill={isSelected ? "#00F5D4" : "#F1F5F9"}
                        fontSize="8.5"
                        fontWeight="600"
                        fontFamily="'Plus Jakarta Sans', system-ui, sans-serif"
                      >
                        {c.flag} {c.name}
                      </text>
                    </g>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Active Intercept Feed Overlay (Top Right) */}
          <div className="absolute top-3 right-3 max-w-xs hidden sm:block bg-[#050B17]/90 backdrop-blur-md p-3 rounded-xl border border-white/10 text-[10px] font-mono space-y-1.5 shadow-xl">
            <div className="text-slate-400 font-bold tracking-wider text-[9px] uppercase border-b border-white/10 pb-1.5 flex items-center justify-between">
              <span>LIVE BALLISTIC STREAM</span>
              <span className="text-rose-400 animate-pulse font-semibold">● ACTIVE</span>
            </div>
            {recentVectors.slice(0, 3).map((vec) => (
              <div key={vec.id} className="text-slate-300 truncate" style={{ borderLeft: `2px solid ${vec.color}`, paddingLeft: "6px" }}>
                {vec.text}
              </div>
            ))}
          </div>

          {/* Selected Country Tactical Inspector Modal (Bottom Left) */}
          {selectedCountry && (
            <div className="absolute bottom-3 left-3 bg-[#060D1D]/95 backdrop-blur-md px-4 py-2.5 rounded-xl border border-cyan-400/30 text-xs font-mono flex items-center gap-4 shadow-2xl animate-fadeIn">
              <div>
                <span className="text-white font-bold flex items-center gap-1.5">
                  <span className="text-base">{selectedCountry.flag}</span>
                  <span>{selectedCountry.name} ({selectedCountry.code})</span>
                </span>
                <div className="text-[10px] text-slate-400 mt-0.5">
                  Status: <strong className="text-cyan-300">{selectedCountry.status}</strong> • Flow: <strong className="text-rose-400">{selectedCountry.traffic}</strong>
                </div>
              </div>
              <button
                onClick={() => setSelectedCountry(null)}
                className="text-slate-400 hover:text-white text-xs px-1.5 py-0.5 rounded bg-white/10"
              >
                ✕
              </button>
            </div>
          )}

          {/* Bottom Map Legend */}
          <div className="absolute bottom-3 right-3 hidden md:flex items-center gap-3 bg-[#050B17]/85 backdrop-blur-md px-3 py-1.5 rounded-xl border border-white/10 text-[10px] font-mono text-slate-300">
            <span className="flex items-center gap-1 text-rose-400">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500" /> UDP/DDoS
            </span>
            <span className="flex items-center gap-1 text-amber-400">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500" /> Mirai Botnet
            </span>
            <span className="flex items-center gap-1 text-cyan-300">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" /> HTTP/2 Reset
            </span>
            <span className="flex items-center gap-1 text-purple-400">
              <span className="w-1.5 h-1.5 rounded-full bg-purple-500" /> SYN Flood
            </span>
          </div>

        </div>

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
