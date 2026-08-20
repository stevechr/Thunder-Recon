"use client";

import { useState, useEffect } from "react";
import ScanForm from "@/components/ScanForm";
import ResultsDashboard from "@/components/ResultsDashboard";
import BreachChecker from "@/components/BreachChecker";
import MailHeaderAnalyzer from "@/components/MailHeaderAnalyzer";
import SandboxAnalyzer from "@/components/SandboxAnalyzer";
import IpIntelligence from "@/components/IpIntelligence";
import SslInspector from "@/components/SslInspector";
import DnsIntelligence from "@/components/DnsIntelligence";
import CveSearch from "@/components/CveSearch";
import SecurityToolkit from "@/components/SecurityToolkit";
import SecurityHeaders from "@/components/SecurityHeaders";
import WhoisLookup from "@/components/WhoisLookup";
import TechDetector from "@/components/TechDetector";
import AuthModal from "@/components/AuthModal";
import SubdomainEnumerator from "@/components/SubdomainEnumerator";
import ScanHistory from "@/components/ScanHistory";
import AsnIntelligence from "@/components/AsnIntelligence";
import OsintAggregator from "@/components/OsintAggregator";
import WafTester from "@/components/WafTester";
import EmailSecurity from "@/components/EmailSecurity";
import BucketFinder from "@/components/BucketFinder";
import PhishingDetector from "@/components/PhishingDetector";
import PortScanner from "@/components/PortScanner";
import RobotsIntel from "@/components/RobotsIntel";
import DorkGenerator from "@/components/DorkGenerator";
import ExecutiveReport from "@/components/ExecutiveReport";
import AttackSurfaceDiff from "@/components/AttackSurfaceDiff";
import MitreNavigator from "@/components/MitreNavigator";
import MonitoringAlerts from "@/components/MonitoringAlerts";
import LiveThreatFeed from "@/components/LiveThreatFeed";
import DnsPropagation from "@/components/DnsPropagation";
import CommandPalette from "@/components/CommandPalette";
import AttackGraph from "@/components/AttackGraph";
import LiveAttackMap from "@/components/LiveAttackMap";
import { UserHeaderBadge, AuthUser, ProviderType } from "@/components/AuthProviders";
import { runScan, ScanResult } from "@/lib/api";

type Mode =
  | "domain"
  | "topology"
  | "sandbox"
  | "report"
  | "diff"
  | "mitre"
  | "threat_feed"
  | "alerts"
  | "dns_prop"
  | "ip"
  | "ssl"
  | "dns"
  | "headers"
  | "whois"
  | "tech"
  | "cve"
  | "mail_header"
  | "pwned"
  | "email"
  | "buckets"
  | "phishing"
  | "ports"
  | "crawl"
  | "dorks"
  | "subdomains"
  | "waf"
  | "asn"
  | "osint"
  | "live_map"
  | "toolkit"
  | "history";

type TabCategory = "all" | "command" | "perimeter" | "threat" | "infra" | "toolkit";

interface TabItem {
  key: Mode;
  icon: string;
  label: string;
  category: "command" | "perimeter" | "threat" | "infra" | "toolkit";
  accent?: string;
}

const TABS: TabItem[] = [
  { key: "domain",      icon: "🛡️",  label: "Domain Recon",       category: "perimeter" },
  { key: "live_map",    icon: "🌍",  label: "Live Attack Map",    category: "command", accent: "red" },
  { key: "topology",    icon: "🕸️",  label: "Attack Topology",    category: "command", accent: "cyan" },
  { key: "report",      icon: "📑",  label: "Executive Audit",    category: "command", accent: "violet" },
  { key: "diff",        icon: "⚖️",  label: "Surface Diff",       category: "command", accent: "cyan" },
  { key: "mitre",       icon: "🗺️",  label: "MITRE ATT&CK",       category: "command", accent: "red" },
  { key: "threat_feed", icon: "📡",  label: "CISA KEV Feed",      category: "command", accent: "red" },
  { key: "alerts",      icon: "🔔",  label: "Alert Webhooks",     category: "command", accent: "purple" },
  { key: "dns_prop",    icon: "🌐",  label: "DNS Propagation",    category: "perimeter", accent: "cyan" },
  { key: "sandbox",     icon: "🧪",  label: "Sandbox",             category: "threat", accent: "violet" },
  { key: "ip",          icon: "🌐",  label: "IP Threat Map",        category: "perimeter" },
  { key: "ssl",         icon: "🔐",  label: "SSL Auditor",          category: "perimeter" },
  { key: "dns",         icon: "📡",  label: "DNS Intelligence",     category: "perimeter" },
  { key: "headers",     icon: "📋",  label: "Security Headers",     category: "perimeter" },
  { key: "whois",       icon: "🕵️",  label: "WHOIS Intel",          category: "perimeter" },
  { key: "tech",        icon: "🎯",  label: "Stack Fingerprint",    category: "infra" },
  { key: "cve",         icon: "🔍",  label: "CVE Lookup",           category: "threat" },
  { key: "mail_header", icon: "📬",  label: "Mail Header",          category: "threat" },
  { key: "pwned",       icon: "⚡",  label: "Breach Leaks",         category: "threat" },
  { key: "email",       icon: "📧",  label: "Email Security",      category: "threat", accent: "violet" },
  { key: "buckets",     icon: "🪣",  label: "Cloud Buckets",       category: "infra", accent: "cyan" },
  { key: "phishing",    icon: "🎣",  label: "Phishing Threat",     category: "threat", accent: "red" },
  { key: "ports",       icon: "🔌",  label: "Port Scanner",        category: "infra", accent: "orange" },
  { key: "crawl",       icon: "🤖",  label: "Robots & Sitemap",    category: "infra", accent: "emerald" },
  { key: "dorks",       icon: "🎯",  label: "Dork Generator",      category: "infra", accent: "amber" },
  { key: "subdomains",  icon: "🕸️",  label: "Subdomains",           category: "perimeter" },
  { key: "waf",         icon: "🛡️",  label: "WAF Tester",          category: "perimeter", accent: "red" },
  { key: "asn",         icon: "🌍",  label: "ASN / BGP",            category: "perimeter" },
  { key: "osint",       icon: "📡",  label: "OSINT",               category: "threat", accent: "purple" },
  { key: "toolkit",     icon: "🛠️",  label: "Cyber Toolkit",        category: "toolkit" },
  { key: "history",     icon: "📊",  label: "Scan History",         category: "toolkit" },
];

export default function Home() {
  const [activeMode, setActiveMode] = useState<Mode>("domain");
  const [tabCategory, setTabCategory] = useState<TabCategory>("all");
  const [tabSearch, setTabSearch] = useState("");
  const [loading, setLoading]       = useState(false);
  const [result, setResult]         = useState<ScanResult | null>(null);
  const [error, setError]           = useState<string | null>(null);
  const [user, setUser]             = useState<AuthUser | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [pendingTargetDomain, setPendingTargetDomain] = useState("");
  const [authModalProvider, setAuthModalProvider]     = useState<ProviderType>("google");
  const [utcTime, setUtcTime]                         = useState("");

  useEffect(() => {
    const updateTime = () => {
      const d = new Date();
      setUtcTime(d.toISOString().slice(11, 19) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    try {
      const saved = localStorage.getItem("thunder_recon_auth_user");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed?.email) setUser(parsed);
      }
    } catch {}
  }, []);

  const handleScan = async (
    domain: string, authorized: boolean, includePorts: boolean,
    includeBreaches: boolean, email: string, sessionToken?: string,
  ) => {
    setLoading(true); setError(null); setResult(null);
    try {
      const token = sessionToken || user?.session_token;
      setResult(await runScan(domain, authorized, includePorts, includeBreaches, email, token));
    } catch (e: any) {
      setError(e.message || "Scan failed");
    } finally { setLoading(false); }
  };

  const handleRequestAuth = (domain: string, provider?: ProviderType) => {
    setPendingTargetDomain(domain);
    setAuthModalProvider(provider || "google");
    setIsAuthModalOpen(true);
  };

  const handleAuthSuccess = (authUser: AuthUser) => {
    setUser(authUser);
    setIsAuthModalOpen(false);
    if (pendingTargetDomain) {
      handleScan(pendingTargetDomain, true, true, true, authUser.email, authUser.session_token);
      setPendingTargetDomain("");
    }
  };

  const handleSignOut = () => {
    try {
      localStorage.removeItem("thunder_recon_auth_user");
      localStorage.removeItem("thunder_recon_google_user");
    } catch {}
    setUser(null);
  };

  return (
    <main className="min-h-screen scan-grid flex flex-col items-center px-4 sm:px-6 py-6 sm:py-8">

      {/* ── Top Navbar ── */}
      <header className="w-full max-w-6xl flex items-center justify-between py-3 px-5 bg-panel/90 border border-panelBorder rounded-2xl mb-8 backdrop-blur-md shadow-lg">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full border border-cyan-signal/50 bg-cyan-signal/10 flex items-center justify-center shadow-sm shadow-cyan-signal/20">
            <span className="text-cyan-signal font-mono text-sm font-bold">⚡</span>
          </div>
          <div>
            <span className="font-display font-extrabold text-sm tracking-tight text-white">Thunder Recon</span>
            <span className="hidden sm:inline ml-2 text-[10px] font-mono text-cyan-signal/80 bg-cyan-signal/10 px-1.5 py-0.5 rounded border border-cyan-signal/20">v4.0 Enterprise</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {utcTime && (
            <div className="hidden lg:flex items-center gap-1.5 px-3 py-1 rounded-xl bg-void/80 border border-panelBorder text-[11px] font-mono text-cyan-400/90 shadow-sm">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span>{utcTime}</span>
            </div>
          )}

          <button
            onClick={() => setIsCommandPaletteOpen(true)}
            className="px-3 py-1.5 rounded-xl bg-void/80 border border-panelBorder hover:border-cyan-signal/50 text-xs font-mono text-mist hover:text-white flex items-center gap-2 transition cursor-pointer shadow-sm"
          >
            <span>🔍 Search Tools</span>
            <kbd className="px-1.5 py-0.5 rounded bg-panel text-[10px] text-cyan-signal border border-panelBorder font-bold">Ctrl+K</kbd>
          </button>

          {user ? (
            <UserHeaderBadge user={user} onSignOut={handleSignOut} />
          ) : (
            <div className="text-[11px] font-mono text-mist/50 hidden md:block">
              Unified Cyber Command Center
            </div>
          )}
        </div>
      </header>

      {/* ── Hero ── */}
      <div className="relative flex flex-col items-center text-center mb-8 max-w-4xl w-full">
        {/* ── Live Telemetry Ribbon ── */}
        <div className="flex flex-wrap items-center justify-center gap-2 mb-4 animate-fadeIn">
          <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-[10px] font-bold flex items-center gap-1.5 shadow-sm">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            30 CYBER ENGINES ONLINE
          </span>
          <span className="px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 font-mono text-[10px] font-bold flex items-center gap-1.5">
            <span>🛡️</span> CISA KEV SYNCED
          </span>
          <span className="px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-[10px] font-bold flex items-center gap-1.5">
            <span>⚡</span> 15.2B BREACH SIGNATURES
          </span>
          <span className="px-2.5 py-1 rounded-full bg-violet-500/10 border border-violet-500/30 text-violet-400 font-mono text-[10px] font-bold flex items-center gap-1.5">
            <span>🔒</span> SOC2 / ISO 27001 COMPLIANCE
          </span>
        </div>

        {/* Radar icon */}
        <div className="relative w-16 h-16 mb-4">
          <div className="absolute inset-0 rounded-full border border-panelBorder/60" />
          <div className="absolute inset-[6px] rounded-full border border-panelBorder/40" />
          <div className="absolute inset-0 animate-sweep origin-center">
            <div className="absolute top-1/2 left-1/2 w-1/2 h-px"
              style={{ background: "linear-gradient(90deg, #4FD1C5, transparent)", transformOrigin: "0% 50%" }} />
          </div>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-2 h-2 rounded-full bg-cyan-signal animate-blink shadow-lg shadow-cyan-signal/60" />
          </div>
          {/* Outer glow pulse */}
          <div className="absolute inset-0 rounded-full bg-cyan-signal/5 animate-ping" style={{ animationDuration: "3s" }} />
        </div>

        <h1 className="font-display text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-white">
          Thunder Recon
        </h1>
        <p className="text-mist mt-2 text-xs sm:text-sm leading-relaxed max-w-lg">
          Enterprise Security Reconnaissance, Attack Surface Management &amp; Threat Intelligence Platform
        </p>

        {/* ── Category Filter Bar with Embedded Search ── */}
        <div className="flex flex-wrap items-center justify-center gap-2 mt-6 max-w-5xl">
          <div className="flex flex-wrap items-center justify-center gap-1.5">
            {[
              { id: "all", label: "🌟 All", count: TABS.length },
              { id: "command", label: "📑 Command & Compliance", count: TABS.filter(t => t.category === "command").length },
              { id: "perimeter", label: "🛡️ Perimeter & DNS", count: TABS.filter(t => t.category === "perimeter").length },
              { id: "threat", label: "🔬 Threat & Forensics", count: TABS.filter(t => t.category === "threat").length },
              { id: "infra", label: "🔌 Infra & Cloud", count: TABS.filter(t => t.category === "infra").length },
              { id: "toolkit", label: "🛠️ Toolkits", count: TABS.filter(t => t.category === "toolkit").length },
            ].map((cat) => (
              <button
                key={cat.id}
                onClick={() => setTabCategory(cat.id as any)}
                className={`text-xs px-3 py-1.5 rounded-xl border transition-all font-semibold cursor-pointer ${
                  tabCategory === cat.id
                    ? "bg-void text-cyan-400 border-cyan-500/60 shadow-sm shadow-cyan-500/10"
                    : "bg-panel/60 text-mist/80 border-panelBorder/70 hover:text-white"
                }`}
              >
                <span>{cat.label}</span>
                <span className="text-[10px] opacity-60 ml-1 font-mono">({cat.count})</span>
              </button>
            ))}
          </div>

          <input
            type="text"
            placeholder="Quick find module..."
            value={tabSearch}
            onChange={(e) => setTabSearch(e.target.value)}
            className="bg-void/80 border border-panelBorder rounded-xl px-3 py-1.5 text-xs text-white placeholder-mist/40 outline-none w-44 font-mono focus:border-cyan-signal/60 transition"
          />
        </div>

        {/* ── Mode Tabs ── */}
        <div className="flex flex-wrap justify-center bg-panel/90 border border-panelBorder p-1.5 rounded-2xl mt-3 gap-1 shadow-lg backdrop-blur-sm max-w-5xl">
          {TABS.filter((tab) => {
            if (tabCategory !== "all" && tab.category !== tabCategory) return false;
            if (tabSearch.trim() && !tab.label.toLowerCase().includes(tabSearch.toLowerCase()) && !tab.key.toLowerCase().includes(tabSearch.toLowerCase())) {
              return false;
            }
            return true;
          }).map((tab) => {
            const isActive = activeMode === tab.key;
            const isViolet = tab.accent === "violet";
            return (
              <button
                key={tab.key}
                onClick={() => { setActiveMode(tab.key); setResult(null); setError(null); }}
                className={`relative px-3 py-1.5 rounded-xl font-display text-xs md:text-sm font-semibold transition-all duration-200 cursor-pointer ${
                  isActive
                    ? isViolet
                      ? "bg-violet-500 text-white shadow-md shadow-violet-500/25"
                      : tab.accent === "purple"
                      ? "bg-purple-500 text-white shadow-md shadow-purple-500/25"
                      : tab.accent === "red"
                      ? "bg-red-500 text-white shadow-md shadow-red-500/25"
                      : "bg-cyan-signal text-void shadow-md shadow-cyan-signal/25"
                    : "text-mist hover:text-white hover:bg-void/60"
                }`}
              >
                <span className="mr-1">{tab.icon}</span>
                {tab.label}
                {isActive && (
                  <span className={`absolute bottom-0 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full ${
                    isViolet ? "bg-violet-300" : tab.accent === "purple" ? "bg-purple-300" : tab.accent === "red" ? "bg-red-300" : "bg-void"
                  } -mb-0.5`} />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Tab Content ── */}

      {/* 1. Domain Recon */}
      {activeMode === "domain" && (
        <div className="w-full flex flex-col items-center animate-fadeIn space-y-6">
          <ScanForm
            onScan={handleScan}
            loading={loading}
            user={user}
            onUserChange={setUser}
            onRequestAuth={handleRequestAuth}
          />

          {/* Quick Target Preset Chips */}
          <div className="flex flex-wrap items-center justify-center gap-2 pt-1 max-w-2xl text-xs font-mono">
            <span className="text-mist/60 text-[11px]">⚡ Quick Targets:</span>
            {["github.com", "cloudflare.com", "tesla.com", "proton.me", "paypal.com"].map((t) => (
              <button
                key={t}
                onClick={() => handleScan(t, true, true, true, user?.email || "")}
                className="px-2.5 py-1 rounded-lg bg-void/80 border border-panelBorder hover:border-cyan-signal/60 text-mist hover:text-cyan-300 transition text-[11px] cursor-pointer shadow-sm"
              >
                {t}
              </button>
            ))}
          </div>

          {error && (
            <div className="flex items-center gap-2 text-crimson-risk text-sm border border-crimson-risk/30 bg-crimson-risk/10 rounded-xl px-4 py-3 font-mono max-w-2xl w-full">
              <span>⚠</span> {error}
            </div>
          )}
          {loading && (
            <div className="my-10 flex flex-col items-center gap-3">
              <div className="flex gap-1.5">
                {[0, 1, 2].map((i) => (
                  <div key={i} className="w-1.5 h-1.5 rounded-full bg-cyan-signal animate-ping"
                    style={{ animationDelay: `${i * 150}ms`, animationDuration: "1.2s" }} />
                ))}
              </div>
              <div className="font-mono text-sm text-cyan-signal animate-blink">
                resolving target &amp; querying breach intelligence datasets...
              </div>
            </div>
          )}
          {result && (
            <div className="w-full flex justify-center">
              <ResultsDashboard result={result} />
            </div>
          )}

          {/* Featured Intelligence Engines Showcase (when idle) */}
          {!result && !loading && (
            <div className="w-full max-w-5xl mt-6 space-y-4">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm">⚡</span>
                  <span className="text-xs font-bold uppercase tracking-wider font-mono text-white">
                    Featured Next-Gen Cyber Engines
                  </span>
                </div>
                <span className="text-[10px] font-mono text-mist">Click any module to launch</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {[
                  { mode: "topology", icon: "🕸️", title: "Attack Topology Graph", desc: "Interactive SVG node-graph of perimeter assets and connections.", accent: "border-cyan-500/30 bg-cyan-500/5 hover:border-cyan-500/60" },
                  { mode: "report", icon: "📑", title: "Executive Audit & CISO Report", desc: "SOC2 / ISO 27001 / NIST CSF compliance matrix + PDF export.", accent: "border-violet-500/30 bg-violet-500/5 hover:border-violet-500/60" },
                  { mode: "diff", icon: "⚖️", title: "Attack Surface Diff", desc: "Compare Staging vs Production perimeter drift & port regressions.", accent: "border-cyan-500/30 bg-cyan-500/5 hover:border-cyan-500/60" },
                  { mode: "mitre", icon: "🗺️", title: "MITRE ATT&CK Matrix", desc: "Map perimeter vulnerabilities to adversary TTPs & D3FEND controls.", accent: "border-red-500/30 bg-red-500/5 hover:border-red-500/60" },
                  { mode: "threat_feed", icon: "📡", title: "CISA KEV Live Stream", desc: "Real-time catalog of weaponized zero-days and ransomware threats.", accent: "border-red-500/30 bg-red-500/5 hover:border-red-500/60" },
                  { mode: "email", icon: "📧", title: "Email Security & DMARC", desc: "Audit SPF lookup count, DKIM selectors & spoofing grade.", accent: "border-violet-500/30 bg-violet-500/5 hover:border-violet-500/60" },
                  { mode: "buckets", icon: "🪣", title: "Cloud Bucket Hunter", desc: "Search exposed AWS S3, Google Cloud, Azure Blob & DO Spaces.", accent: "border-cyan-500/30 bg-cyan-500/5 hover:border-cyan-500/60" },
                  { mode: "live_map", icon: "🌍", title: "Live Attack Map", desc: "Interactive 3D WebGL globe rendering real-time global cyber threats.", accent: "border-red-500/30 bg-red-500/5 hover:border-red-500/60" },
                ].map((item) => (
                  <div
                    key={item.mode}
                    onClick={() => { setActiveMode(item.mode as any); setResult(null); setError(null); }}
                    className={`p-4 rounded-2xl border transition-all cursor-pointer space-y-1.5 backdrop-blur-sm ${item.accent}`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-lg">{item.icon}</span>
                      <span className="text-xs font-bold text-white leading-tight">{item.title}</span>
                    </div>
                    <p className="text-[11px] text-mist/80 leading-relaxed">{item.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Visual Attack Topology Graph */}
      {activeMode === "topology" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <AttackGraph result={result} />
        </div>
      )}

      {/* Live WebGL Cyber Attack Map */}
      {activeMode === "live_map" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <LiveAttackMap />
        </div>
      )}

      {/* 2. Sandbox */}
      {activeMode === "sandbox" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <SandboxAnalyzer />
        </div>
      )}

      {/* Executive Audit & Compliance Report */}
      {activeMode === "report" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <ExecutiveReport />
        </div>
      )}

      {/* Attack Surface Diff & Drift Engine */}
      {activeMode === "diff" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <AttackSurfaceDiff />
        </div>
      )}

      {/* MITRE ATT&CK Matrix Navigator */}
      {activeMode === "mitre" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <MitreNavigator />
        </div>
      )}

      {/* CISA KEV Live Threat Feed */}
      {activeMode === "threat_feed" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <LiveThreatFeed />
        </div>
      )}

      {/* Continuous Monitoring & Alerting */}
      {activeMode === "alerts" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <MonitoringAlerts />
        </div>
      )}

      {/* Global DNS Propagation & Multi-Resolver */}
      {activeMode === "dns_prop" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <DnsPropagation />
        </div>
      )}

      {/* 3. IP Threat Map */}
      {activeMode === "ip" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <IpIntelligence />
        </div>
      )}

      {/* 4. SSL Auditor */}
      {activeMode === "ssl" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <SslInspector />
        </div>
      )}

      {/* 5. DNS Intelligence */}
      {activeMode === "dns" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <DnsIntelligence />
        </div>
      )}

      {/* 6. Security Headers */}
      {activeMode === "headers" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <SecurityHeaders />
        </div>
      )}

      {/* 7. WHOIS Intel */}
      {activeMode === "whois" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <WhoisLookup />
        </div>
      )}

      {/* 8. Stack Fingerprint */}
      {activeMode === "tech" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <TechDetector />
        </div>
      )}

      {/* 9. CVE Search */}
      {activeMode === "cve" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <CveSearch />
        </div>
      )}

      {/* 10. Mail Header Forensics */}
      {activeMode === "mail_header" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <MailHeaderAnalyzer />
        </div>
      )}

      {/* 11. Breach Intelligence */}
      {activeMode === "pwned" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <BreachChecker />
        </div>
      )}

      {/* 12. Email Security Analyzer */}
      {activeMode === "email" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <EmailSecurity />
        </div>
      )}

      {/* 13. Cloud Bucket Finder */}
      {activeMode === "buckets" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <BucketFinder />
        </div>
      )}

      {/* 14. Phishing & Threat URL Checker */}
      {activeMode === "phishing" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <PhishingDetector />
        </div>
      )}

      {/* 15. Port Scanner */}
      {activeMode === "ports" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <PortScanner />
        </div>
      )}

      {/* 16. Robots & Sitemap Intelligence */}
      {activeMode === "crawl" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <RobotsIntel />
        </div>
      )}

      {/* 17. OSINT Dork Generator */}
      {activeMode === "dorks" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <DorkGenerator />
        </div>
      )}

      {/* 18. Subdomain Enumerator */}
      {activeMode === "subdomains" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <SubdomainEnumerator />
        </div>
      )}

      {/* 19. WAF / Firewall Tester */}
      {activeMode === "waf" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <WafTester />
        </div>
      )}

      {/* 20. ASN / BGP Intelligence */}
      {activeMode === "asn" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <AsnIntelligence />
        </div>
      )}

      {/* 21. OSINT Aggregator */}
      {activeMode === "osint" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <OsintAggregator />
        </div>
      )}

      {/* 22. Cyber Security Toolkit */}
      {activeMode === "toolkit" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <SecurityToolkit />
        </div>
      )}

      {/* 23. Scan History */}
      {activeMode === "history" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <ScanHistory />
        </div>
      )}

      {/* Auth Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onAuthenticated={handleAuthSuccess}
        initialProvider={authModalProvider}
        targetDomain={pendingTargetDomain}
      />

      {/* Global Quick Launcher Command Palette */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onSelectMode={(modeKey) => {
          setActiveMode(modeKey as any);
          setResult(null);
          setError(null);
        }}
        onTriggerScan={(domainToScan) => {
          handleScan(domainToScan, true, true, true, user?.email || "");
        }}
      />

      {/* ── Platform Summary Footer ── */}
      <footer className="w-full max-w-6xl mt-16 pt-8 border-t border-panelBorder/60 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-mist/60">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Thunder Recon v4.0 Cyber Command Center • All Systems Operational</span>
        </div>
        <div className="flex items-center gap-4">
          <span>31 Enterprise Security Engines</span>
          <span>•</span>
          <span>15B+ Breach Records</span>
          <span>•</span>
          <span>CISA KEV Live Feeds</span>
        </div>
      </footer>
    </main>
  );
}
