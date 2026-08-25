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
  { key: "attack_map",  icon: "🌐",  label: "Tactical Attack Radar", category: "ops" },
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
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);

  useEffect(() => {
    try {
      const storedAuth = localStorage.getItem("thunder_recon_auth_user");
      if (storedAuth) setUser(JSON.parse(storedAuth));
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

  const selectModeHandler = (mode: Mode) => {
    setActiveMode(mode);
    setResult(null);
    setError(null);
    setMobileDrawerOpen(false);
  };

  // Group tabs for sidebar
  const groupedTabs = {
    "Reconnaissance & Surface": TABS.filter(t => t.category === "recon"),
    "Threat & Vulnerabilities": TABS.filter(t => t.category === "threat"),
    "Operations & Utilities": TABS.filter(t => t.category === "ops"),
  };

  return (
    <div className="flex h-screen w-full cyber-bg-pattern overflow-hidden text-slate-200 font-sans">
      
      {/* ── Desktop Sidebar (Glassmorphic) ── */}
      <aside className={`hidden md:flex relative z-20 flex-col h-full bg-[#060912]/90 backdrop-blur-2xl border-r border-white/5 transition-all duration-300 ${sidebarOpen ? 'w-64' : 'w-16'}`}>
        
        {/* Sidebar Header */}
        <div 
          onClick={() => selectModeHandler("none")}
          className="p-4 flex items-center justify-between border-b border-white/5 bg-transparent cursor-pointer hover:bg-white/[0.03] transition"
          title="Go to Command Dashboard"
        >
          {sidebarOpen && (
            <div className="flex items-center gap-2.5 overflow-hidden">
              <span className="text-cyan-400 font-mono text-xl">⚡</span>
              <div className="flex flex-col">
                <span className="font-display font-bold text-white tracking-tight whitespace-nowrap text-sm">THUNDER RECON</span>
                <span className="text-[10px] font-sans text-slate-400 tracking-normal">Cyber Intelligence</span>
              </div>
            </div>
          )}
          {!sidebarOpen && <span className="text-cyan-400 font-mono text-xl mx-auto">⚡</span>}
        </div>

        {/* Sidebar Navigation */}
        <div className="flex-1 overflow-y-auto py-4 scrollbar-thin">
          {Object.entries(groupedTabs).map(([category, items]) => (
            <div key={category} className="mb-5">
              {sidebarOpen && <div className="px-4 mb-2 text-[10px] font-medium text-slate-400 uppercase tracking-wider">{category}</div>}
              <div className="space-y-0.5 px-2">
                {items.map((tab) => {
                  const isActive = activeMode === tab.key;
                  return (
                    <button
                      key={tab.key}
                      onClick={() => selectModeHandler(tab.key)}
                      title={!sidebarOpen ? tab.label : undefined}
                      className={`w-full flex items-center gap-3 px-3 py-2 rounded-xl transition-all text-left ${
                        isActive 
                          ? 'bg-cyan-500/15 border border-cyan-500/30 text-white font-medium shadow-[0_0_15px_rgba(0,245,212,0.1)]' 
                          : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-200'
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
        <div className="p-3 border-t border-white/5 bg-transparent flex flex-col gap-2">
          <button 
            onClick={() => setIsCommandPaletteOpen(true)}
            className="w-full flex items-center justify-between px-3 py-2 bg-white/[0.03] hover:bg-white/[0.06] border border-white/5 rounded-xl transition-all text-xs text-slate-300"
          >
            {sidebarOpen ? (
              <>
                <span className="flex items-center gap-2 text-xs text-slate-400"><span>🔍</span> Search Tools</span>
                <kbd className="text-[9px] bg-white/10 px-1.5 py-0.5 rounded text-slate-300 font-sans">⌘K</kbd>
              </>
            ) : (
              <span className="text-xs mx-auto">🔍</span>
            )}
          </button>
        </div>
      </aside>

      {/* ── Mobile Slide-Over Drawer Modal ── */}
      {mobileDrawerOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          {/* Backdrop Blur */}
          <div 
            onClick={() => setMobileDrawerOpen(false)} 
            className="fixed inset-0 bg-black/75 backdrop-blur-md animate-fadeIn" 
          />
          
          {/* Drawer Content */}
          <div className="relative z-10 w-4/5 max-w-sm h-full bg-[#060912] border-r border-white/10 flex flex-col p-4 shadow-2xl animate-fadeIn">
            <div className="flex items-center justify-between pb-4 border-b border-white/10">
              <div className="flex items-center gap-2.5">
                <span className="text-cyan-400 font-mono text-xl">⚡</span>
                <span className="font-display font-bold text-white tracking-tight text-sm">THUNDER RECON</span>
              </div>
              <button 
                onClick={() => setMobileDrawerOpen(false)}
                className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto py-4 space-y-4 no-scrollbar">
              {Object.entries(groupedTabs).map(([category, items]) => (
                <div key={category} className="space-y-1">
                  <div className="text-[10px] font-medium text-cyan-400/80 uppercase tracking-wider px-2">{category}</div>
                  <div className="space-y-1">
                    {items.map((tab) => {
                      const isActive = activeMode === tab.key;
                      return (
                        <button
                          key={tab.key}
                          onClick={() => selectModeHandler(tab.key)}
                          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all text-left text-xs ${
                            isActive
                              ? 'bg-cyan-500/15 border border-cyan-500/30 text-white font-semibold'
                              : 'text-slate-300 hover:bg-white/5'
                          }`}
                        >
                          <span className="text-base">{tab.icon}</span>
                          <span className="truncate">{tab.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>

            <div className="pt-3 border-t border-white/10">
              <button 
                onClick={() => { setMobileDrawerOpen(false); setIsCommandPaletteOpen(true); }}
                className="w-full py-2.5 px-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl text-xs text-slate-300 flex items-center justify-center gap-2"
              >
                <span>🔍</span> Search Tools &amp; Engines (⌘K)
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Main Workspace ── */}
      <div className="flex-1 relative z-10 flex flex-col h-full overflow-hidden">
        
        {/* Top Navbar */}
        <header className="h-14 sm:h-16 flex items-center justify-between px-3 sm:px-6 border-b border-white/5 bg-[#060912]/90 backdrop-blur-xl shrink-0">
          <div className="flex items-center gap-3">
            
            {/* Desktop Sidebar Toggle */}
            <button 
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="hidden md:flex text-slate-400 hover:text-white p-2 rounded-lg hover:bg-white/5 transition"
              title="Toggle Sidebar"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>

            {/* Mobile Drawer Button */}
            <button 
              onClick={() => setMobileDrawerOpen(true)}
              className="md:hidden text-slate-300 p-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 transition"
              title="Open Navigation Menu"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>

            {/* Brand in Mobile Navbar */}
            <div 
              onClick={() => selectModeHandler("none")}
              className="flex items-center gap-2 cursor-pointer"
            >
              <span className="text-cyan-400 font-mono text-lg">⚡</span>
              <span className="font-display font-bold text-white tracking-tight text-xs sm:text-sm">THUNDER RECON</span>
            </div>

            <div className="hidden sm:flex items-center gap-2 text-xs ml-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-slate-400 text-xs">Live Telemetry</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button 
              onClick={() => setIsCommandPaletteOpen(true)}
              className="p-2 sm:px-3 sm:py-1.5 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-xs text-slate-300 flex items-center gap-1.5"
              title="Search tools (⌘K)"
            >
              <span>🔍</span>
              <span className="hidden sm:inline">Search</span>
            </button>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-3 sm:p-6 lg:p-8 pb-24 md:pb-8 flex justify-center scrollbar-thin">
          
          {/* Landing State: Modern Cyber Command Dashboard */}
          {activeMode === "none" && (
            <CommandDashboard 
              onSelectMode={(mode) => selectModeHandler(mode as Mode)} 
              onQuickScan={(domain) => {
                setActiveMode("domain");
                handleScan(domain, true, true, true, user?.email || "anonymous@thunder-recon.local");
              }}
            />
          )}

          {/* Active Mode Container */}
          {activeMode !== "none" && (
            <div className="w-full max-w-[1600px] flex flex-col items-center animate-fadeIn">
              
              {/* Top Close / Return to Dashboard Button */}
              <div className="w-full flex justify-between items-center mb-4 gap-2">
                <button
                  onClick={() => selectModeHandler("none")}
                  className="px-3 py-1.5 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-xs text-slate-300 transition-all flex items-center gap-1.5"
                >
                  <span>←</span> Return to Hub
                </button>

                <button 
                  onClick={() => selectModeHandler("none")}
                  className="px-3 py-1.5 rounded-xl bg-rose-500/10 border border-rose-500/30 hover:bg-rose-500/20 hover:text-rose-300 text-xs text-rose-400 transition-all flex items-center gap-1.5"
                >
                  ✕ Close Tool
                </button>
              </div>

              {/* The Glassmorphic Tool Wrapper */}
              <div className="w-full cyber-card rounded-2xl shadow-2xl p-3 sm:p-6 lg:p-8 relative">
                
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

                {/* 4. DNS Intelligence */}
                {activeMode === "dns" && <DnsIntelligence />}

                {/* 5. SSL / TLS Auditor */}
                {activeMode === "ssl" && <SslInspector />}

                {/* 6. Security Headers */}
                {activeMode === "headers" && <SecurityHeaders />}

                {/* 7. WHOIS Forensics */}
                {activeMode === "whois" && <WhoisLookup />}

                {/* 8. IP Threat & Geolocation */}
                {activeMode === "ip" && <IpIntelligence />}

                {/* 9. URL & File Sandbox */}
                {activeMode === "sandbox" && <SandboxAnalyzer />}

                {/* 10. Breach & Leaks */}
                {activeMode === "pwned" && <BreachChecker />}

                {/* 11. CVE Exploit Search */}
                {activeMode === "cve" && <CveSearch />}

                {/* 12. Email DMARC/SPF */}
                {activeMode === "email" && <EmailSecurity />}

                {/* 13. 3D Attack Globe */}
                {activeMode === "attack_map" && <LiveAttackMap isFullscreenBg={false} />}

                {/* 14. Attack Topology */}
                {activeMode === "topology" && <AttackGraph result={result} />}

                {/* 15. Swiss Sec Toolkit */}
                {activeMode === "toolkit" && <SecurityToolkit />}

                {/* 16. Executive Audit Report */}
                {activeMode === "report" && <ExecutiveReport />}

              </div>
            </div>
          )}
        </main>

        {/* ── Fixed Mobile Bottom Navigation Bar (Next-Level Native App Feel) ── */}
        <nav className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-[#060912]/95 backdrop-blur-2xl border-t border-white/10 px-2 py-2 flex items-center justify-around safe-bottom shadow-[0_-10px_25px_rgba(0,0,0,0.5)]">
          <button
            onClick={() => selectModeHandler("none")}
            className={`flex flex-col items-center gap-1 py-1 px-2 rounded-xl transition-all ${
              activeMode === "none" ? "text-cyan-400" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span className="text-lg">⚡</span>
            <span className="text-[10px] font-medium tracking-tight">Hub</span>
          </button>

          <button
            onClick={() => selectModeHandler("domain")}
            className={`flex flex-col items-center gap-1 py-1 px-2 rounded-xl transition-all ${
              activeMode === "domain" ? "text-cyan-400" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span className="text-lg">🛡️</span>
            <span className="text-[10px] font-medium tracking-tight">Recon</span>
          </button>

          <button
            onClick={() => selectModeHandler("attack_map")}
            className={`flex flex-col items-center gap-1 py-1 px-2 rounded-xl transition-all ${
              activeMode === "attack_map" ? "text-cyan-400" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span className="text-lg">🌐</span>
            <span className="text-[10px] font-medium tracking-tight">Radar</span>
          </button>

          <button
            onClick={() => selectModeHandler("scorecard")}
            className={`flex flex-col items-center gap-1 py-1 px-2 rounded-xl transition-all ${
              activeMode === "scorecard" ? "text-cyan-400" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span className="text-lg">📊</span>
            <span className="text-[10px] font-medium tracking-tight">Score</span>
          </button>

          <button
            onClick={() => setMobileDrawerOpen(true)}
            className="flex flex-col items-center gap-1 py-1 px-2 rounded-xl text-slate-400 hover:text-slate-200 transition-all"
          >
            <span className="text-lg">🧰</span>
            <span className="text-[10px] font-medium tracking-tight">All Tools</span>
          </button>
        </nav>

      </div>

      <CommandPalette 
        isOpen={isCommandPaletteOpen} 
        onClose={() => setIsCommandPaletteOpen(false)} 
        onSelectMode={(mode) => selectModeHandler(mode as Mode)} 
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
