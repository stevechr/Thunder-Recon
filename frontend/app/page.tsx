"use client";

import { useState, useEffect } from "react";
import ScanForm from "@/components/ScanForm";
import ResultsDashboard from "@/components/ResultsDashboard";
import BreachChecker from "@/components/BreachChecker";
import SandboxAnalyzer from "@/components/SandboxAnalyzer";
import IpIntelligence from "@/components/IpIntelligence";
import SslInspector from "@/components/SslInspector";
import DnsIntelligence from "@/components/DnsIntelligence";
import CveSearch from "@/components/CveSearch";
import SecurityToolkit from "@/components/SecurityToolkit";
import SecurityHeaders from "@/components/SecurityHeaders";
import WhoisLookup from "@/components/WhoisLookup";
import AuthModal from "@/components/AuthModal";
import SubdomainEnumerator from "@/components/SubdomainEnumerator";
import EmailSecurity from "@/components/EmailSecurity";
import ExecutiveReport from "@/components/ExecutiveReport";
import CommandPalette from "@/components/CommandPalette";
import AttackGraph from "@/components/AttackGraph";
import LiveAttackMap from "@/components/LiveAttackMap";
import ThemeSelector from "@/components/ThemeSelector";
import CommandDashboard from "@/components/CommandDashboard";
import PostureScorecard from "@/components/PostureScorecard";
import { UserHeaderBadge, AuthUser, ProviderType } from "@/components/AuthProviders";
import { runScan, ScanResult } from "@/lib/api";

type Mode =
  | "domain"
  | "scorecard"
  | "subdomains"
  | "dns"
  | "ssl"
  | "headers"
  | "whois"
  | "ip"
  | "sandbox"
  | "pwned"
  | "cve"
  | "email"
  | "attack_map"
  | "topology"
  | "toolkit"
  | "report"
  | "none";

interface TabItem {
  key: Mode;
  icon: string;
  label: string;
  category: "recon" | "threat" | "ops";
}

const TABS: TabItem[] = [
  // Reconnaissance & Surface
  { key: "domain",      icon: "🛡️",  label: "Domain Recon Hub",   category: "recon" },
  { key: "scorecard",   icon: "📊",  label: "Threat Scorecard",   category: "recon" },
  { key: "subdomains",  icon: "🌳",  label: "Subdomain Finder",   category: "recon" },
  { key: "dns",         icon: "📡",  label: "DNS Intelligence",   category: "recon" },
  { key: "ssl",         icon: "🔐",  label: "SSL/TLS Auditor",    category: "recon" },
  { key: "headers",     icon: "📋",  label: "Security Headers",   category: "recon" },
  { key: "whois",       icon: "🕵️",  label: "WHOIS Forensics",    category: "recon" },
  
  // Threat & Forensics
  { key: "ip",          icon: "🌐",  label: "IP Threat Map",      category: "threat" },
  { key: "sandbox",     icon: "🧪",  label: "URL/File Sandbox",   category: "threat" },
  { key: "pwned",       icon: "☠️",  label: "Breach & Leaks",     category: "threat" },
  { key: "cve",         icon: "🚨",  label: "CVE Exploit Search", category: "threat" },
  { key: "email",       icon: "📧",  label: "Email DMARC/SPF",    category: "threat" },
  
  // Operations & Toolkit
  { key: "attack_map",  icon: "🌍",  label: "3D Attack Globe",    category: "ops" },
  { key: "topology",    icon: "🕸️",  label: "Attack Topology",    category: "ops" },
  { key: "toolkit",     icon: "🔧",  label: "Swiss Sec Toolkit",  category: "ops" },
  { key: "report",      icon: "📑",  label: "Executive Audit",    category: "ops" },
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
    "Reconnaissance & Surface": TABS.filter(t => t.category === "recon"),
    "Threat & Vulnerabilities": TABS.filter(t => t.category === "threat"),
    "Operations & Utilities": TABS.filter(t => t.category === "ops"),
  };

  return (
    <div className="flex h-screen w-full cyber-bg-pattern overflow-hidden text-slate-200 font-sans">
      
      {/* ── Sidebar (Glassmorphic) ── */}
      <div className={`relative z-20 flex flex-col h-full bg-[#090D15]/85 backdrop-blur-2xl border-r border-white/10 transition-all duration-300 ${sidebarOpen ? 'w-64' : 'w-16'}`}>
        
        {/* Sidebar Header */}
        <div 
          onClick={() => { setActiveMode("none"); setResult(null); setError(null); }}
          className="p-4 flex items-center justify-between border-b border-white/10 bg-black/40 cursor-pointer hover:bg-white/5 transition"
          title="Go to Command Dashboard"
        >
          {sidebarOpen && (
            <div className="flex items-center gap-2.5 overflow-hidden">
              <span className="text-cyan-400 font-mono text-xl drop-shadow-[0_0_10px_rgba(6,182,212,0.6)]">⚡</span>
              <div className="flex flex-col">
                <span className="font-display font-extrabold text-white tracking-tight whitespace-nowrap text-sm">THUNDER RECON</span>
                <span className="text-[9px] font-mono text-cyan-400/70 uppercase tracking-wider">Cyber Intelligence</span>
              </div>
            </div>
          )}
          {!sidebarOpen && <span className="text-cyan-400 font-mono text-xl mx-auto drop-shadow-[0_0_10px_rgba(6,182,212,0.6)]">⚡</span>}
        </div>

        {/* Sidebar Navigation */}
        <div className="flex-1 overflow-y-auto py-4 scrollbar-thin">
          {Object.entries(groupedTabs).map(([category, items]) => (
            <div key={category} className="mb-5">
              {sidebarOpen && <div className="px-4 mb-2 text-[10px] font-mono text-slate-400 uppercase tracking-wider">{category}</div>}
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
                          ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-300 border shadow-[0_0_15px_rgba(6,182,212,0.2)] font-semibold' 
                          : 'border border-transparent text-slate-400 hover:bg-white/5 hover:text-white'
                      }`}
                    >
                      <span className="text-base">{tab.icon}</span>
                      {sidebarOpen && <span className="text-xs truncate">{tab.label}</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Sidebar Footer */}
        <div className="p-3 border-t border-white/10 bg-black/40 flex flex-col gap-2.5">
          <button 
            onClick={() => setIsCommandPaletteOpen(true)}
            className="w-full flex items-center justify-between px-3 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg transition-all text-xs text-slate-300"
          >
            {sidebarOpen ? (
              <>
                <span className="flex items-center gap-2"><span className="text-xs">🔍</span> Search Tools</span>
                <kbd className="text-[9px] bg-black/80 px-1.5 py-0.5 rounded border border-white/20 font-mono text-cyan-400">Cmd+K</kbd>
              </>
            ) : (
              <span className="text-xs mx-auto">🔍</span>
            )}
          </button>
          {sidebarOpen && (
            <div className="text-[9px] font-mono text-slate-400 text-center">
              Thunder Recon v4.0 • Verified Suite
            </div>
          )}
        </div>
      </div>

      {/* ── Main Workspace ── */}
      <div className="flex-1 relative z-10 flex flex-col h-full overflow-hidden">
        
        {/* Top Navbar */}
        <header className="h-16 flex items-center justify-between px-6 border-b border-white/10 bg-[#090D15]/80 backdrop-blur-xl shrink-0">
          <div className="flex items-center gap-4">
            <button 
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="text-slate-400 hover:text-white p-2 rounded-lg hover:bg-white/5 transition"
              title="Toggle Sidebar"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>
            <div className="hidden md:flex items-center gap-2 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-emerald-400/90 font-semibold tracking-wider text-[11px]">SOC SYSTEMS NOMINAL</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Theme Selector Component */}
            <ThemeSelector />

            <div className="hidden lg:flex items-center gap-2 text-[11px] font-mono text-slate-400 bg-white/5 px-2.5 py-1.5 rounded-lg border border-white/10">
              <span className="text-cyan-400">⏱</span>
              <span>{utcTime}</span>
            </div>
            
            {user ? (
              <UserHeaderBadge user={user} onSignOut={handleSignOut} />
            ) : (
              <button 
                onClick={() => setIsAuthModalOpen(true)} 
                className="px-3.5 py-1.5 rounded-lg bg-cyan-500/15 border border-cyan-400/40 text-cyan-300 text-xs font-bold hover:bg-cyan-500/25 transition shadow-sm font-mono"
              >
                Sign In
              </button>
            )}
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 flex justify-center scrollbar-thin">
          
          {/* Landing State: Modern Cyber Command Dashboard */}
          {activeMode === "none" && (
            <CommandDashboard 
              onSelectMode={(mode) => { 
                setActiveMode(mode as Mode); 
                setResult(null); 
                setError(null); 
              }} 
              onQuickScan={(domain) => {
                setActiveMode("domain");
                handleScan(domain, false, true, false, "");
              }}
            />
          )}

          {/* Active Mode Container */}
          {activeMode !== "none" && (
            <div className="w-full max-w-6xl flex flex-col items-center animate-fadeIn">
              
              {/* Top Close / Return to Dashboard Button */}
              <div className="w-full flex justify-between items-center mb-4">
                <button
                  onClick={() => setActiveMode("none")}
                  className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 text-xs text-slate-300 transition-all flex items-center gap-2"
                >
                  <span>←</span> Return to Command Dashboard
                </button>

                <button 
                  onClick={() => setActiveMode("none")}
                  className="px-3 py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 hover:bg-rose-500/20 hover:text-rose-300 text-xs text-rose-400 transition-all flex items-center gap-1.5"
                >
                  ✕ Close Tool
                </button>
              </div>

              {/* The Glassmorphic Tool Wrapper */}
              <div className="w-full cyber-card rounded-2xl shadow-2xl p-4 sm:p-8 relative">
                
                {/* 1. Domain Recon */}
                {activeMode === "domain" && (
                  <div className="space-y-6">
                    <ScanForm onScan={handleScan} loading={loading} user={user} onUserChange={setUser} onRequestAuth={handleRequestAuth} />
                    {error && (
                      <div className="text-rose-400 text-sm border border-rose-500/30 bg-rose-500/10 rounded-xl px-4 py-3 font-mono">
                        <span>⚠</span> {error}
                      </div>
                    )}
                    {result && <ResultsDashboard result={result} />}
                  </div>
                )}

                {/* 2. Cyber Threat Scorecard */}
                {activeMode === "scorecard" && <PostureScorecard />}

                {/* 3. Subdomains */}
                {activeMode === "subdomains" && <SubdomainEnumerator />}

                {/* 3. DNS Intelligence */}
                {activeMode === "dns" && <DnsIntelligence />}

                {/* 4. SSL / TLS Auditor */}
                {activeMode === "ssl" && <SslInspector />}

                {/* 5. Security Headers */}
                {activeMode === "headers" && <SecurityHeaders />}

                {/* 6. WHOIS Forensics */}
                {activeMode === "whois" && <WhoisLookup />}

                {/* 7. IP Threat & Geolocation */}
                {activeMode === "ip" && <IpIntelligence />}

                {/* 8. URL & File Sandbox */}
                {activeMode === "sandbox" && <SandboxAnalyzer />}

                {/* 9. Breach & Leaks */}
                {activeMode === "pwned" && <BreachChecker />}

                {/* 10. CVE Exploit Search */}
                {activeMode === "cve" && <CveSearch />}

                {/* 11. Email DMARC/SPF */}
                {activeMode === "email" && <EmailSecurity />}

                {/* 12. 3D Attack Globe */}
                {activeMode === "attack_map" && <LiveAttackMap isFullscreenBg={false} />}

                {/* 13. Attack Topology */}
                {activeMode === "topology" && <AttackGraph result={result} />}

                {/* 14. Swiss Sec Toolkit */}
                {activeMode === "toolkit" && <SecurityToolkit />}

                {/* 15. Executive Audit Report */}
                {activeMode === "report" && <ExecutiveReport />}

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
          handleScan(domain, false, true, false, "");
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
