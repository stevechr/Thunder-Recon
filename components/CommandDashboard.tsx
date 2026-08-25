"use client";

import React, { useState, useEffect, useRef } from "react";

interface CommandDashboardProps {
  onSelectMode: (mode: string) => void;
  onQuickScan: (domain: string) => void;
}

interface CountryNode {
  name: string;
  code: string;
  flag: string;
  lat: number;
  lng: number;
  color: string;
}

interface AttackParticle {
  srcCountry: CountryNode;
  tgtCountry: CountryNode;
  sx: number;
  sy: number;
  tx: number;
  ty: number;
  progress: number;
  speed: number;
  color: string;
  type: string;
  bandwidth: string;
}

export default function CommandDashboard({ onSelectMode, onQuickScan }: CommandDashboardProps) {
  const [quickDomain, setQuickDomain] = useState("");
  const [activeCategory, setActiveCategory] = useState<"all" | "recon" | "threat" | "ops">("all");
  const [ddosBandwidth, setDdosBandwidth] = useState(482);
  const [packetRate, setPacketRate] = useState(318);
  const [activeBotCount, setActiveBotCount] = useState(384200);
  const [recentVectors, setRecentVectors] = useState<Array<{ id: number; text: string; time: string; color: string }>>([
    { id: 1, text: "🇨🇳 China ➔ 🇺🇸 United States • DDoS Amplification (112 Gbps)", time: "Live", color: "#F43F5E" },
    { id: 2, text: "🇷🇺 Russia ➔ 🇩🇪 Germany • Mirai Botnet C2 Syn (48 Gbps)", time: "Live", color: "#FFB703" },
    { id: 3, text: "🇧🇷 Brazil ➔ 🇬🇧 United Kingdom • HTTP/2 Rapid Reset", time: "Live", color: "#00F5D4" },
  ]);
  const mapCanvasRef = useRef<HTMLCanvasElement | null>(null);

  // Real-world countries with geo-coordinates
  const COUNTRIES: CountryNode[] = [
    { name: "United States", code: "USA", flag: "🇺🇸", lat: 38.0, lng: -97.0, color: "#38BDF8" },
    { name: "Canada", code: "CAN", flag: "🇨🇦", lat: 56.0, lng: -106.0, color: "#38BDF8" },
    { name: "Brazil", code: "BRA", flag: "🇧🇷", lat: -14.2, lng: -51.9, color: "#F43F5E" },
    { name: "United Kingdom", code: "GBR", flag: "🇬🇧", lat: 55.3, lng: -3.4, color: "#00F5D4" },
    { name: "Germany", code: "DEU", flag: "🇩🇪", lat: 51.1, lng: 10.4, color: "#00F5D4" },
    { name: "France", code: "FRA", flag: "🇫🇷", lat: 46.2, lng: 2.2, color: "#00F5D4" },
    { name: "Ukraine", code: "UKR", flag: "🇺🇦", lat: 48.3, lng: 31.1, color: "#FFB703" },
    { name: "Russia", code: "RUS", flag: "🇷🇺", lat: 61.5, lng: 95.3, color: "#F43F5E" },
    { name: "China", code: "CHN", flag: "🇨🇳", lat: 35.8, lng: 104.1, color: "#F43F5E" },
    { name: "India", code: "IND", flag: "🇮🇳", lat: 20.5, lng: 78.9, color: "#FFB703" },
    { name: "Japan", code: "JPN", flag: "🇯🇵", lat: 36.2, lng: 138.2, color: "#38BDF8" },
    { name: "South Korea", code: "KOR", flag: "🇰🇷", lat: 35.9, lng: 127.7, color: "#38BDF8" },
    { name: "Singapore", code: "SGP", flag: "🇸🇬", lat: 1.35, lng: 103.8, color: "#00F5D4" },
    { name: "Australia", code: "AUS", flag: "🇦🇺", lat: -25.2, lng: 133.7, color: "#38BDF8" },
    { name: "South Africa", code: "ZAF", flag: "🇿🇦", lat: -30.5, lng: 22.9, color: "#F43F5E" },
    { name: "UAE", code: "ARE", flag: "🇦🇪", lat: 23.4, lng: 53.8, color: "#00F5D4" },
    { name: "Netherlands", code: "NLD", flag: "🇳🇱", lat: 52.1, lng: 5.2, color: "#00F5D4" },
  ];

  // Simplified continent polygons for background geo-landmass rendering [lng, lat][]
  const CONTINENTS: Array<Array<[number, number]>> = [
    // North America
    [
      [-168, 65], [-140, 70], [-120, 75], [-80, 72], [-60, 50],
      [-70, 42], [-75, 30], [-80, 25], [-97, 20], [-105, 20],
      [-118, 32], [-124, 48], [-140, 60], [-168, 65]
    ],
    // South America
    [
      [-78, 10], [-60, 5], [-35, -5], [-38, -15], [-50, -30],
      [-65, -54], [-75, -45], [-72, -18], [-80, -2], [-78, 10]
    ],
    // Eurasia / Europe & Asia
    [
      [-10, 36], [0, 44], [15, 55], [30, 70], [60, 72],
      [100, 75], [140, 72], [170, 65], [140, 50], [130, 35],
      [120, 22], [105, 10], [90, 22], [75, 10], [60, 25],
      [50, 30], [35, 32], [25, 36], [10, 38], [-10, 36]
    ],
    // Africa
    [
      [-18, 30], [10, 37], [32, 32], [50, 12], [42, -5],
      [35, -25], [20, -35], [12, -20], [8, 4], [-15, 12], [-18, 30]
    ],
    // Australia
    [
      [114, -22], [125, -15], [142, -11], [153, -28],
      [150, -38], [135, -36], [115, -34], [114, -22]
    ]
  ];

  // Live telemetry pulse
  useEffect(() => {
    const timer = setInterval(() => {
      setDdosBandwidth(Math.floor(450 + Math.random() * 95));
      setPacketRate(Math.floor(290 + Math.random() * 60));
      setActiveBotCount((prev) => prev + Math.floor((Math.random() - 0.48) * 120));
    }, 2500);
    return () => clearInterval(timer);
  }, []);

  // Home Page Real World Map Tactical Canvas
  useEffect(() => {
    const canvas = mapCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || 800);
    let height = (canvas.height = 420);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = 420;
    };
    window.addEventListener("resize", handleResize);

    // Geo projection: Equirectangular [lng, lat] -> [x, y]
    const project = (lng: number, lat: number) => {
      const x = ((lng + 180) / 360) * width;
      const y = ((90 - lat) / 180) * height;
      return { x, y };
    };

    const ATTACK_TYPES = [
      { name: "DDoS Volumetric Stream", color: "#F43F5E", minBw: 80, maxBw: 160 },
      { name: "Mirai C2 Botnet Swarm", color: "#FFB703", minBw: 24, maxBw: 68 },
      { name: "HTTP/2 Rapid Reset", color: "#00F5D4", minBw: 45, maxBw: 92 },
      { name: "SYN Flood Exfiltration", color: "#A855F7", minBw: 15, maxBw: 42 },
    ];

    let attacks: AttackParticle[] = [];

    const spawnAttack = () => {
      if (attacks.length > 16) return;
      const sIdx = Math.floor(Math.random() * COUNTRIES.length);
      let tIdx = Math.floor(Math.random() * COUNTRIES.length);
      while (tIdx === sIdx) tIdx = Math.floor(Math.random() * COUNTRIES.length);

      const src = COUNTRIES[sIdx];
      const tgt = COUNTRIES[tIdx];
      const srcPt = project(src.lng, src.lat);
      const tgtPt = project(tgt.lng, tgt.lat);
      const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
      const bw = `${Math.floor(type.minBw + Math.random() * (type.maxBw - type.minBw))} Gbps`;

      attacks.push({
        srcCountry: src,
        tgtCountry: tgt,
        sx: srcPt.x,
        sy: srcPt.y,
        tx: tgtPt.x,
        ty: tgtPt.y,
        progress: 0,
        speed: 0.007 + Math.random() * 0.010,
        color: type.color,
        type: type.name,
        bandwidth: bw,
      });

      // Update ticker
      setRecentVectors((prev) => [
        {
          id: Date.now() + Math.random(),
          text: `${src.flag} ${src.name} ➔ ${tgt.flag} ${tgt.name} • ${type.name} (${bw})`,
          time: new Date().toISOString().substring(11, 19),
          color: type.color,
        },
        ...prev.slice(0, 3),
      ]);
    };

    let pulse = 0;

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // 1. Tactical Longitude & Latitude Matrix Grid
      ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
      ctx.lineWidth = 1;

      // Longitude lines (every 30 deg)
      for (let lng = -180; lng <= 180; lng += 30) {
        const x = ((lng + 180) / 360) * width;
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }

      // Latitude lines (every 30 deg)
      for (let lat = -90; lat <= 90; lat += 30) {
        const y = ((90 - lat) / 180) * height;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Equator Highlight
      const eqY = height / 2;
      ctx.strokeStyle = "rgba(0, 245, 212, 0.08)";
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(0, eqY);
      ctx.lineTo(width, eqY);
      ctx.stroke();
      ctx.setLineDash([]);

      // 2. Real World Continent Landmass Geometry
      ctx.fillStyle = "rgba(14, 28, 48, 0.45)";
      ctx.strokeStyle = "rgba(0, 245, 212, 0.15)";
      ctx.lineWidth = 1.2;

      CONTINENTS.forEach((poly) => {
        if (poly.length < 2) return;
        ctx.beginPath();
        const start = project(poly[0][0], poly[0][1]);
        ctx.moveTo(start.x, start.y);
        for (let i = 1; i < poly.length; i++) {
          const pt = project(poly[i][0], poly[i][1]);
          ctx.lineTo(pt.x, pt.y);
        }
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      });

      // 3. Render Named Countries & Pulsing Nodes
      COUNTRIES.forEach((c) => {
        const pt = project(c.lng, c.lat);

        // Pulse beacon ring
        ctx.strokeStyle = `${c.color}40`;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 4 + ((pulse + c.lng * 0.1) % 16), 0, Math.PI * 2);
        ctx.stroke();

        // Country core beacon
        ctx.fillStyle = c.color;
        ctx.shadowColor = c.color;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 3.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Country Flag & Name Label
        ctx.fillStyle = "#FFFFFF";
        ctx.font = "bold 10px 'Plus Jakarta Sans', sans-serif";
        ctx.shadowColor = "rgba(0,0,0,0.9)";
        ctx.shadowBlur = 4;
        ctx.fillText(`${c.flag} ${c.name}`, pt.x + 7, pt.y - 2);
        ctx.shadowBlur = 0;
      });

      // 4. Dynamic Ballistic Attack Trajectory Arcs
      if (Math.random() < 0.10) spawnAttack();

      attacks.forEach((atk, i) => {
        atk.progress += atk.speed;

        // Quadratic Bezier arc midpoint
        const mx = (atk.sx + atk.tx) / 2;
        const my = Math.min(atk.sy, atk.ty) - 50;

        // Draw trajectory arc line
        ctx.strokeStyle = `${atk.color}35`;
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        ctx.moveTo(atk.sx, atk.sy);
        ctx.quadraticCurveTo(mx, my, atk.tx, atk.ty);
        ctx.stroke();

        // Interpolated current missile position
        const t = atk.progress;
        const cx = (1 - t) * (1 - t) * atk.sx + 2 * (1 - t) * t * mx + t * t * atk.tx;
        const cy = (1 - t) * (1 - t) * atk.sy + 2 * (1 - t) * t * my + t * t * atk.ty;

        // Glowing particle head
        ctx.fillStyle = atk.color;
        ctx.shadowColor = atk.color;
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.arc(cx, cy, 3.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Remove completed attacks
        if (atk.progress >= 1) {
          attacks.splice(i, 1);
        }
      });

      pulse += 0.35;
      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener("resize", handleResize);
      cancelAnimationFrame(animId);
    };
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
    // Recon
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

    // Threat
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

    // Ops
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

      {/* ── 2. Live Global Attack Map & Cyber Telemetry Hub ── */}
      <div className="cyber-card rounded-3xl p-6 sm:p-8 border border-white/10 relative overflow-hidden shadow-2xl space-y-6">
        
        {/* Header Strip */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full bg-rose-500 animate-pulse shadow-[0_0_10px_#F43F5E]" />
            <div>
              <h2 className="text-lg font-bold text-white font-display flex items-center gap-2">
                Live Cyber Threat &amp; Attack Telemetry
              </h2>
              <p className="text-xs text-slate-400">
                Real-world global map with live country attack streams, botnet swarms, and targeted sectors
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

        {/* Real World Map Canvas with Named Countries */}
        <div className="w-full relative rounded-2xl bg-[#040711] border border-white/5 overflow-hidden h-[420px]">
          <canvas ref={mapCanvasRef} className="w-full h-full block" />
          
          {/* Live Stream Vector Ticker (Top Right) */}
          <div className="absolute top-3 right-3 max-w-sm hidden sm:block bg-[#060912]/85 backdrop-blur-md p-2.5 rounded-xl border border-white/10 text-[10px] font-mono space-y-1">
            <div className="text-slate-400 font-bold tracking-wider text-[9px] uppercase border-b border-white/10 pb-1 flex items-center justify-between">
              <span>ACTIVE INTERCEPT STREAM</span>
              <span className="text-rose-400 animate-pulse">● LIVE</span>
            </div>
            {recentVectors.slice(0, 3).map((vec) => (
              <div key={vec.id} className="text-slate-300 truncate" style={{ borderLeft: `2px solid ${vec.color}`, paddingLeft: "6px" }}>
                {vec.text}
              </div>
            ))}
          </div>

          {/* Map Legend Overlay (Bottom Left) */}
          <div className="absolute bottom-3 left-3 bg-[#060912]/85 backdrop-blur-md px-3 py-2 rounded-xl border border-white/10 flex flex-wrap items-center gap-4 text-[11px] font-mono">
            <span className="flex items-center gap-1.5 text-rose-400">
              <span className="w-2 h-2 rounded-full bg-rose-500" /> Volumetric DDoS
            </span>
            <span className="flex items-center gap-1.5 text-amber-400">
              <span className="w-2 h-2 rounded-full bg-amber-500" /> Botnet C2
            </span>
            <span className="flex items-center gap-1.5 text-cyan-300">
              <span className="w-2 h-2 rounded-full bg-cyan-400" /> HTTP/2 Exploits
            </span>
            <span className="flex items-center gap-1.5 text-purple-400">
              <span className="w-2 h-2 rounded-full bg-purple-500" /> SYN Flood
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
