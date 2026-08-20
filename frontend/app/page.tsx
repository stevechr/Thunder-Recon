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
  | "toolkit"
  | "history"
  | "robots"
  | "none";

interface TabItem {
  key: Mode;
  icon: string;
  label: string;
  category: "command" | "perimeter" | "threat" | "infra" | "toolkit";
}

const TABS: TabItem[] = [
  // Command & Compliance
  { key: "topology",    icon: "🕸️",  label: "Attack Topology",    category: "command" },
  { key: "report",      icon: "📑",  label: "Executive Audit",    category: "command" },
  { key: "diff",        icon: "⚖️",  label: "Surface Diff",       category: "command" },
  { key: "mitre",       icon: "🗺️",  label: "MITRE ATT&CK",       category: "command" },
  { key: "threat_feed", icon: "📡",  label: "CISA KEV Feed",      category: "command" },
  { key: "alerts",      icon: "🔔",  label: "Alert Webhooks",     category: "command" },
  
  // Perimeter & DNS
  { key: "domain",      icon: "🛡️",  label: "Domain Recon",       category: "perimeter" },
  { key: "subdomains",  icon: "🌳",  label: "Subdomain Finder",     category: "perimeter" },
  { key: "dns",         icon: "📡",  label: "DNS Intelligence",     category: "perimeter" },
  { key: "dns_prop",    icon: "🌐",  label: "DNS Propagation",    category: "perimeter" },
  { key: "whois",       icon: "🕵️",  label: "WHOIS Intel",          category: "perimeter" },
  { key: "ssl",         icon: "🔐",  label: "SSL Auditor",          category: "perimeter" },
  { key: "headers",     icon: "📋",  label: "Security Headers",     category: "perimeter" },
  
  // Threat & Forensics
  { key: "sandbox",     icon: "🧪",  label: "Sandbox",             category: "threat" },
  { key: "pwned",       icon: "☠️",  label: "Breach Intel",         category: "threat" },
  { key: "phishing",    icon: "🎣",  label: "Phishing Detect",      category: "threat" },
  { key: "mail_header", icon: "✉️",  label: "Mail Header Forensics",category: "threat" },
  { key: "cve",         icon: "🚨",  label: "CVE Lookup",           category: "threat" },
  { key: "osint",       icon: "👁️",  label: "OSINT Aggregate",      category: "threat" },
  
  // Infra & Cloud
  { key: "ip",          icon: "🌐",  label: "IP Threat Map",        category: "infra" },
  { key: "asn",         icon: "🏢",  label: "ASN Intel",            category: "infra" },
  { key: "ports",       icon: "🚪",  label: "Port Scanner",         category: "infra" },
  { key: "tech",        icon: "🎯",  label: "Stack Fingerprint",    category: "infra" },
  { key: "buckets",     icon: "🪣",  label: "Cloud Bucket Hunter",  category: "infra" },
  { key: "waf",         icon: "🧱",  label: "WAF Detector",         category: "infra" },
  
  // Toolkits
  { key: "email",       icon: "📧",  label: "DMARC/SPF Audit",      category: "toolkit" },
  { key: "crawl",       icon: "🕷️",  label: "Crawler & Links",      category: "toolkit" },
  { key: "dorks",       icon: "🔍",  label: "Google Dorks",         category: "toolkit" },
  { key: "robots",      icon: "🤖",  label: "Robots.txt Intel",     category: "toolkit" },
  { key: "toolkit",     icon: "🔧",  label: "Utility Toolkit",      category: "toolkit" },
  { key: "history",     icon: "📜",  label: "Scan History",         category: "toolkit" },
];

export default function Home() {
  const [activeMode, setActiveMode] = useState<Mode>("none");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authModalProvider, setAuthModalProvider] = useState<ProviderType>("google");
  const [pendingTargetDomain, setPendingTargetDomain] = useState("");
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [utcTime, setUtcTime] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);

  useEffect(() => {
    try {
      const storedAuth = localStorage.getItem("thunder_recon_auth_user");
      if (storedAuth) setUser(JSON.parse(storedAuth));
    } catch {}
    
    const updateTime = () => setUtcTime(new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    updateTime();
    const int = setInterval(updateTime, 1000);
    return () => clearInterval(int);
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

  // Group tabs for sidebar
  const groupedTabs = {
    "Command & Tactics": TABS.filter(t => t.category === "command"),
    "Perimeter & DNS": TABS.filter(t => t.category === "perimeter"),
    "Threat Intelligence": TABS.filter(t => t.category === "threat"),
    "Infra & Cloud": TABS.filter(t => t.category === "infra"),
    "Toolkits": TABS.filter(t => t.category === "toolkit"),
  };

  return (
    <div className="flex h-screen w-full bg-[#000005] overflow-hidden text-mist font-sans">
      
      {/* ── Background Live Map ── */}
      <div className="absolute inset-0 z-0 opacity-80 pointer-events-auto">
        <LiveAttackMap isFullscreenBg={true} />
      </div>

      {/* ── Sidebar (Glassmorphic) ── */}
      <div className={`relative z-20 flex flex-col h-full bg-black/60 backdrop-blur-xl border-r border-white/10 transition-all duration-300 ${sidebarOpen ? 'w-64' : 'w-16'}`}>
        
        {/* Sidebar Header */}
        <div className="p-4 flex items-center justify-between border-b border-white/10 bg-black/40">
          {sidebarOpen && (
            <div className="flex items-center gap-2 overflow-hidden">
              <span className="text-cyan-signal font-mono text-xl">⚡</span>
              <span className="font-display font-extrabold text-white tracking-tight whitespace-nowrap">Thunder Recon</span>
            </div>
          )}
          {!sidebarOpen && <span className="text-cyan-signal font-mono text-xl mx-auto">⚡</span>}
        </div>

        {/* Sidebar Navigation */}
        <div className="flex-1 overflow-y-auto py-4 scrollbar-thin scrollbar-thumb-white/10">
          {Object.entries(groupedTabs).map(([category, items]) => (
            <div key={category} className="mb-6">
              {sidebarOpen && <div className="px-4 mb-2 text-[10px] font-mono text-mist/40 uppercase tracking-wider">{category}</div>}
              <div className="space-y-0.5 px-2">
                {items.map((tab) => {
                  const isActive = activeMode === tab.key;
                  return (
                    <button
                      key={tab.key}
                      onClick={() => { setActiveMode(tab.key); setResult(null); setError(null); }}
                      title={!sidebarOpen ? tab.label : undefined}
                      className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all text-left ${
                        isActive 
                          ? 'bg-cyan-signal/20 border-cyan-signal/50 text-cyan-300 border shadow-[0_0_15px_rgba(79,209,197,0.15)]' 
                          : 'border border-transparent text-mist/70 hover:bg-white/5 hover:text-white'
                      }`}
                    >
                      <span className="text-lg">{tab.icon}</span>
                      {sidebarOpen && <span className="text-sm font-semibold truncate">{tab.label}</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Sidebar Footer */}
        <div className="p-4 border-t border-white/10 bg-black/40 flex flex-col gap-3">
          <button 
            onClick={() => setIsCommandPaletteOpen(true)}
            className="w-full flex items-center justify-between px-3 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg transition-all text-xs"
          >
            {sidebarOpen ? (
              <>
                <span className="text-mist flex items-center gap-2"><span className="text-sm">🔍</span> Search Tools</span>
                <kbd className="text-[9px] bg-black px-1.5 py-0.5 rounded border border-white/20 font-mono text-cyan-signal">Cmd+K</kbd>
              </>
            ) : (
              <span className="text-sm mx-auto">🔍</span>
            )}
          </button>
          {sidebarOpen && (
            <div className="text-[9px] font-mono text-mist/30 text-center">
              Thunder Recon v4.0 • 31 Engines
            </div>
          )}
        </div>
      </div>

      {/* ── Main Workspace ── */}
      <div className="flex-1 relative z-10 flex flex-col h-full overflow-hidden pointer-events-none">
        
        {/* Top Navbar */}
        <header className="h-16 flex items-center justify-between px-6 border-b border-white/5 bg-black/20 backdrop-blur-sm pointer-events-auto">
          <div className="flex items-center gap-4">
            <button 
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="text-mist hover:text-white p-2 rounded-lg hover:bg-white/5 transition"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>
            <div className="hidden md:flex items-center gap-2 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-emerald-400/80">SYSTEMS NOMINAL</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden lg:flex items-center gap-2 text-[11px] font-mono text-cyan-400/70">
              <span>{utcTime}</span>
            </div>
            {user ? (
              <UserHeaderBadge user={user} onSignOut={handleSignOut} />
            ) : (
              <button onClick={() => setIsAuthModalOpen(true)} className="px-3 py-1.5 rounded-lg bg-cyan-signal/10 border border-cyan-signal/30 text-cyan-signal text-xs font-bold hover:bg-cyan-signal/20 transition">
                Sign In
              </button>
            )}
          </div>
        </header>

        {/* Content Area (Tools render here over the map) */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-8 flex justify-center pointer-events-auto scrollbar-thin scrollbar-thumb-white/10">
          
          {/* Default State: Show nothing but a floating welcome message, Map handles the rest */}
          {activeMode === "none" && (
            <div className="mt-20 flex flex-col items-center animate-fadeIn pointer-events-none">
              <div className="px-4 py-2 rounded-full bg-black/40 border border-white/10 backdrop-blur-md text-mist text-sm font-mono shadow-2xl flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-signal animate-ping" />
                Select a tool from the sidebar to begin reconnaissance.
              </div>
            </div>
          )}

          {/* Active Mode Container */}
          {activeMode !== "none" && (
            <div className="w-full max-w-6xl flex flex-col items-center animate-fadeInSlideUp">
              
              {/* Top Close Button for the tool */}
              <div className="w-full flex justify-end mb-2">
                <button 
                  onClick={() => setActiveMode("none")}
                  className="px-3 py-1 rounded bg-black/60 border border-white/10 hover:bg-red-500/20 hover:text-red-400 text-xs text-mist backdrop-blur-md transition-all flex items-center gap-1"
                >
                  ✕ Close Tool
                </button>
              </div>

              {/* The Glassmorphic Tool Wrapper */}
              <div className="w-full bg-black/60 backdrop-blur-2xl border border-white/10 rounded-2xl shadow-2xl overflow-hidden p-6 relative">
                
                {/* 1. Domain Recon */}
                {activeMode === "domain" && (
                  <div className="space-y-6">
                    <ScanForm onScan={handleScan} loading={loading} user={user} onUserChange={setUser} onRequestAuth={handleRequestAuth} />
                    {error && (
                      <div className="text-crimson-risk text-sm border border-crimson-risk/30 bg-crimson-risk/10 rounded-xl px-4 py-3 font-mono">
                        <span>⚠</span> {error}
                      </div>
                    )}
                    {result && <ResultsDashboard result={result} />}
                  </div>
                )}

                {/* All other components */}
                {activeMode === "topology" && <AttackGraph result={result} />}
                {activeMode === "sandbox" && <SandboxAnalyzer />}
                {activeMode === "report" && <ExecutiveReport />}
                {activeMode === "diff" && <AttackSurfaceDiff />}
                {activeMode === "mitre" && <MitreNavigator />}
                {activeMode === "threat_feed" && <LiveThreatFeed />}
                {activeMode === "alerts" && <MonitoringAlerts />}
                {activeMode === "dns_prop" && <DnsPropagation />}
                {activeMode === "ip" && <IpIntelligence />}
                {activeMode === "ssl" && <SslInspector />}
                {activeMode === "dns" && <DnsIntelligence />}
                {activeMode === "headers" && <SecurityHeaders />}
                {activeMode === "whois" && <WhoisLookup />}
                {activeMode === "tech" && <TechDetector />}
                {activeMode === "cve" && <CveSearch />}
                {activeMode === "mail_header" && <MailHeaderAnalyzer />}
                {activeMode === "pwned" && <BreachChecker />}
                {activeMode === "email" && <EmailSecurity />}
                {activeMode === "buckets" && <BucketFinder />}
                {activeMode === "phishing" && <PhishingDetector />}
                {activeMode === "ports" && <PortScanner />}
                {activeMode === "crawl" && <RobotsIntel />}
                {activeMode === "dorks" && <DorkGenerator />}
                {activeMode === "subdomains" && <SubdomainEnumerator />}
                {activeMode === "waf" && <WafTester />}
                {activeMode === "asn" && <AsnIntelligence />}
                {activeMode === "osint" && <OsintAggregator />}
                {activeMode === "toolkit" && <SecurityToolkit />}
                {activeMode === "history" && <ScanHistory />}

              </div>
            </div>
          )}
        </main>
      </div>

      <CommandPalette 
        isOpen={isCommandPaletteOpen} 
        onClose={() => setIsCommandPaletteOpen(false)} 
        onSelectMode={(mode) => setActiveMode(mode as Mode)} 
        onTriggerScan={(domain) => {
          setActiveMode("domain");
          // Optionally trigger scan if possible, or let the user type in the ScanForm
        }}
      />

      <AuthModal 
        isOpen={isAuthModalOpen} 
        onClose={() => setIsAuthModalOpen(false)} 
        onAuthenticated={handleAuthSuccess} 
        initialProvider={authModalProvider} 
        targetDomain=""
      />

    </div>
  );
}
