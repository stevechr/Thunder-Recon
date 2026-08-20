"use client";

import { useState, useEffect, useRef } from "react";

interface CommandItem {
  id: string;
  title: string;
  category: string;
  icon: string;
  action: () => void;
  keywords?: string[];
}

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectMode: (modeKey: string) => void;
  onTriggerScan: (domain: string) => void;
}

export default function CommandPalette({ isOpen, onClose, onSelectMode, onTriggerScan }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands: CommandItem[] = [
    { id: "domain", title: "Domain Recon (Core Scanner)", category: "Perimeter", icon: "🛡️", action: () => onSelectMode("domain"), keywords: ["scan", "whois", "dns", "ssl"] },
    { id: "report", title: "Executive Pentest & Compliance Audit", category: "Command & Compliance", icon: "📑", action: () => onSelectMode("report"), keywords: ["pdf", "ciso", "soc2", "iso27001", "compliance"] },
    { id: "diff", title: "Attack Surface Diff & Drift", category: "Command & Compliance", icon: "⚖️", action: () => onSelectMode("diff"), keywords: ["compare", "staging", "drift"] },
    { id: "mitre", title: "MITRE ATT&CK Matrix Navigator", category: "Command & Compliance", icon: "🗺️", action: () => onSelectMode("mitre"), keywords: ["ttps", "d3fend", "adversary"] },
    { id: "threat_feed", title: "CISA KEV Live Threat Feed", category: "Command & Compliance", icon: "📡", action: () => onSelectMode("threat_feed"), keywords: ["cve", "zero-day", "exploit", "cisa"] },
    { id: "alerts", title: "Alert Webhooks & Monitoring", category: "Command & Compliance", icon: "🔔", action: () => onSelectMode("alerts"), keywords: ["slack", "discord", "notify"] },
    { id: "email", title: "Email Security & Spoofing (SPF/DMARC)", category: "Threat & Forensics", icon: "📧", action: () => onSelectMode("email"), keywords: ["spf", "dkim", "dmarc", "spoof"] },
    { id: "buckets", title: "Cloud Storage Bucket Hunter (S3/GCS)", category: "Infrastructure", icon: "🪣", action: () => onSelectMode("buckets"), keywords: ["s3", "aws", "google", "azure", "storage"] },
    { id: "phishing", title: "Phishing & Malicious URL Scanner", category: "Threat & Forensics", icon: "🎣", action: () => onSelectMode("phishing"), keywords: ["urlhaus", "malware", "homoglyph"] },
    { id: "ports", title: "Dedicated TCP Port Scanner", category: "Infrastructure", icon: "🔌", action: () => onSelectMode("ports"), keywords: ["nmap", "tcp", "banner", "syn"] },
    { id: "dns_prop", title: "Global DNS Propagation Auditor", category: "Perimeter", icon: "🌐", action: () => onSelectMode("dns_prop"), keywords: ["propagation", "resolvers", "google", "cloudflare"] },
    { id: "crawl", title: "Robots.txt & Sitemap Crawler", category: "Infrastructure", icon: "🤖", action: () => onSelectMode("crawl"), keywords: ["robots", "sitemap", "sensitive", "probe"] },
    { id: "dorks", title: "OSINT Dork Generator (Google/Shodan)", category: "Infrastructure", icon: "🎯", action: () => onSelectMode("dorks"), keywords: ["google", "shodan", "github", "censys"] },
    { id: "subdomains", title: "Subdomain Enumerator & Takeover", category: "Perimeter", icon: "🕸️", action: () => onSelectMode("subdomains"), keywords: ["subdomain", "crt.sh", "takeover"] },
    { id: "waf", title: "WAF & Firewall Tester", category: "Perimeter", icon: "🛡️", action: () => onSelectMode("waf"), keywords: ["waf", "cloudflare", "fuzz", "bypass"] },
    { id: "asn", title: "ASN & BGP Routing Intelligence", category: "Perimeter", icon: "🌍", action: () => onSelectMode("asn"), keywords: ["bgp", "asn", "prefix", "peer"] },
    { id: "osint", title: "OSINT Intelligence Aggregator", category: "Threat & Forensics", icon: "📡", action: () => onSelectMode("osint"), keywords: ["wayback", "archive", "leaks"] },
    { id: "sandbox", title: "Sandbox Analyzer (Detonation)", category: "Threat & Forensics", icon: "🧪", action: () => onSelectMode("sandbox"), keywords: ["malware", "virustotal", "detonate"] },
    { id: "toolkit", title: "Cyber Swiss Toolkit (JWT/Hash/Subnet)", category: "Toolkits", icon: "🛠️", action: () => onSelectMode("toolkit"), keywords: ["jwt", "hash", "cookie", "subnet", "shell"] },
    { id: "history", title: "Scan History & Offline Storage", category: "Toolkits", icon: "📊", action: () => onSelectMode("history"), keywords: ["recent", "saved", "export"] },
  ];

  const filtered = commands.filter((c) => {
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return (
      c.title.toLowerCase().includes(q) ||
      c.category.toLowerCase().includes(q) ||
      c.keywords?.some((k) => k.toLowerCase().includes(q))
    );
  });

  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (isOpen) onClose();
        else onSelectMode(commands[0].id); // or trigger open
      }
      if (!isOpen) return;

      if (e.key === "Escape") {
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev + 1) % (filtered.length || 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev - 1 + filtered.length) % (filtered.length || 1));
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (filtered[selectedIndex]) {
          filtered[selectedIndex].action();
          onClose();
        } else if (query.includes(".")) {
          onTriggerScan(query.trim());
          onClose();
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, filtered, selectedIndex, query]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-void/80 backdrop-blur-md animate-fadeIn">
      <div className="w-full max-w-xl bg-surface/95 border border-cyan-500/40 rounded-2xl shadow-2xl shadow-cyan-500/10 overflow-hidden space-y-0 font-sans">
        {/* Search Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-border/60 bg-void/60">
          <span className="text-cyan-400 text-lg">⚡</span>
          <input
            ref={inputRef}
            type="text"
            placeholder="Search all 29 tools or enter a domain to scan..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            className="flex-1 bg-transparent text-sm text-white placeholder-mist/40 outline-none font-medium"
          />
          <kbd className="px-2 py-0.5 rounded bg-void border border-border text-[10px] font-mono text-mist">
            ESC to close
          </kbd>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto p-2 space-y-1">
          {filtered.length > 0 ? (
            filtered.map((item, idx) => (
              <div
                key={item.id}
                onClick={() => {
                  item.action();
                  onClose();
                }}
                onMouseEnter={() => setSelectedIndex(idx)}
                className={`p-3 rounded-xl flex items-center justify-between transition cursor-pointer ${
                  selectedIndex === idx
                    ? "bg-cyan-500/20 border border-cyan-500/30 text-white"
                    : "text-mist/90 hover:bg-void/40"
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-base">{item.icon}</span>
                  <div>
                    <div className="text-xs font-bold text-white">{item.title}</div>
                    <div className="text-[10px] text-mist/60 font-mono">{item.category}</div>
                  </div>
                </div>

                <div className="text-[10px] font-mono text-cyan-400">
                  {selectedIndex === idx ? "↵ Jump" : ""}
                </div>
              </div>
            ))
          ) : query.includes(".") ? (
            <div
              onClick={() => {
                onTriggerScan(query.trim());
                onClose();
              }}
              className="p-4 text-center cursor-pointer hover:bg-cyan-500/10 rounded-xl transition space-y-1"
            >
              <div className="text-xs font-bold text-cyan-400">
                🛡️ Launch Full Perimeter Recon on &quot;{query.trim()}&quot;
              </div>
              <div className="text-[10px] text-mist font-mono">Press Enter to execute scan</div>
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-mist font-mono">
              No matching modules found for &quot;{query}&quot;.
            </div>
          )}
        </div>

        {/* Footer info */}
        <div className="px-4 py-2 bg-void/80 border-t border-border/40 flex items-center justify-between text-[10px] font-mono text-mist/60">
          <span>Thunder Recon Global Quick Launcher</span>
          <div className="flex gap-2">
            <span>↑↓ Navigate</span>
            <span>•</span>
            <span>↵ Select</span>
          </div>
        </div>
      </div>
    </div>
  );
}
