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
import { UserHeaderBadge, AuthUser, ProviderType } from "@/components/AuthProviders";
import { runScan, ScanResult } from "@/lib/api";

type Mode =
  | "domain"
  | "sandbox"
  | "ip"
  | "ssl"
  | "dns"
  | "headers"
  | "whois"
  | "tech"
  | "cve"
  | "mail_header"
  | "pwned"
  | "toolkit";

const TABS: { key: Mode; icon: string; label: string; accent?: string }[] = [
  { key: "domain",      icon: "🛡️",  label: "Domain Recon"       },
  { key: "sandbox",     icon: "🧪",  label: "Sandbox",            accent: "violet" },
  { key: "ip",          icon: "🌐",  label: "IP Threat Map"       },
  { key: "ssl",         icon: "🔐",  label: "SSL Auditor"         },
  { key: "dns",         icon: "📡",  label: "DNS Intelligence"    },
  { key: "headers",     icon: "📋",  label: "Security Headers"    },
  { key: "whois",       icon: "🕵️",  label: "WHOIS Intel"         },
  { key: "tech",        icon: "🎯",  label: "Stack Fingerprint"   },
  { key: "cve",         icon: "🔍",  label: "CVE Lookup"          },
  { key: "mail_header", icon: "📬",  label: "Mail Header"         },
  { key: "pwned",       icon: "⚡",  label: "Breach Leaks"        },
  { key: "toolkit",     icon: "🛠️",  label: "Cyber Toolkit"       },
];

export default function Home() {
  const [activeMode, setActiveMode] = useState<Mode>("domain");
  const [loading, setLoading]       = useState(false);
  const [result, setResult]         = useState<ScanResult | null>(null);
  const [error, setError]           = useState<string | null>(null);
  const [user, setUser]             = useState<AuthUser | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [pendingTargetDomain, setPendingTargetDomain] = useState("");
  const [authModalProvider, setAuthModalProvider]     = useState<ProviderType>("google");

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
            <span className="hidden sm:inline ml-2 text-[10px] font-mono text-cyan-signal/80 bg-cyan-signal/10 px-1.5 py-0.5 rounded border border-cyan-signal/20">v3.5 Enterprise</span>
          </div>
        </div>
        {user ? (
          <UserHeaderBadge user={user} onSignOut={handleSignOut} />
        ) : (
          <div className="text-[11px] font-mono text-mist/50 hidden sm:block">
            Unified Cybersecurity &amp; Threat Intelligence Suite
          </div>
        )}
      </header>

      {/* ── Hero ── */}
      <div className="relative flex flex-col items-center text-center mb-8 max-w-4xl w-full">
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
          Enterprise Security Reconnaissance, Threat Intel &amp; Detonation Platform
        </p>

        {/* ── Mode Tabs ── */}
        <div className="flex flex-wrap justify-center bg-panel/90 border border-panelBorder p-1.5 rounded-2xl mt-6 gap-1 shadow-lg backdrop-blur-sm max-w-5xl">
          {TABS.map((tab) => {
            const isActive = activeMode === tab.key;
            const isViolet = tab.accent === "violet";
            return (
              <button
                key={tab.key}
                onClick={() => { setActiveMode(tab.key); setResult(null); setError(null); }}
                className={`relative px-3 py-1.5 rounded-xl font-display text-xs md:text-sm font-semibold transition-all duration-200 ${
                  isActive
                    ? isViolet
                      ? "bg-violet-500 text-white shadow-md shadow-violet-500/25"
                      : "bg-cyan-signal text-void shadow-md shadow-cyan-signal/25"
                    : "text-mist hover:text-white hover:bg-void/60"
                }`}
              >
                <span className="mr-1">{tab.icon}</span>
                {tab.label}
                {isActive && (
                  <span className={`absolute bottom-0 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full ${isViolet ? "bg-violet-300" : "bg-void"} -mb-0.5`} />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Tab Content ── */}

      {/* 1. Domain Recon */}
      {activeMode === "domain" && (
        <div className="w-full flex flex-col items-center animate-fadeIn">
          <ScanForm
            onScan={handleScan}
            loading={loading}
            user={user}
            onUserChange={setUser}
            onRequestAuth={handleRequestAuth}
          />
          {error && (
            <div className="mt-6 flex items-center gap-2 text-crimson-risk text-sm border border-crimson-risk/30 bg-crimson-risk/10 rounded-xl px-4 py-3 font-mono max-w-2xl w-full">
              <span>⚠</span> {error}
            </div>
          )}
          {loading && (
            <div className="mt-10 flex flex-col items-center gap-3">
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
            <div className="mt-10 w-full flex justify-center">
              <ResultsDashboard result={result} />
            </div>
          )}
        </div>
      )}

      {/* 2. Sandbox */}
      {activeMode === "sandbox" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <SandboxAnalyzer />
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

      {/* 12. Cyber Security Toolkit */}
      {activeMode === "toolkit" && (
        <div className="w-full flex justify-center animate-fadeIn">
          <SecurityToolkit />
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

      {/* ── Platform Summary Footer ── */}
      <footer className="w-full max-w-6xl mt-16 pt-8 border-t border-panelBorder/60 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-mist/60">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Thunder Recon v3.5 Enterprise Engine • All Systems Operational</span>
        </div>
        <div className="flex items-center gap-4">
          <span>12 Security Modules</span>
          <span>•</span>
          <span>15B+ Breach Records</span>
          <span>•</span>
          <span>30+ AV Engines</span>
        </div>
      </footer>
    </main>
  );
}
