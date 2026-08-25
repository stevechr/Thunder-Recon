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
    { id: "domain", title: "Domain Recon Hub (Full Scan)", category: "Reconnaissance", icon: "🛡️", action: () => onSelectMode("domain"), keywords: ["scan", "whois", "dns", "ssl", "domain"] },
    { id: "subdomains", title: "Subdomain Enumerator (crt.sh & DNS)", category: "Reconnaissance", icon: "🌳", action: () => onSelectMode("subdomains"), keywords: ["subdomain", "crt.sh", "takeover"] },
    { id: "dns", title: "DNS Intelligence & Security Records", category: "Reconnaissance", icon: "📡", action: () => onSelectMode("dns"), keywords: ["dns", "mx", "txt", "ns", "dnssec"] },
    { id: "ssl", title: "SSL/TLS Certificate Auditor", category: "Reconnaissance", icon: "🔐", action: () => onSelectMode("ssl"), keywords: ["ssl", "tls", "certificate", "https", "cipher"] },
    { id: "headers", title: "HTTP Security Headers Inspector", category: "Reconnaissance", icon: "📋", action: () => onSelectMode("headers"), keywords: ["headers", "csp", "hsts", "cors", "x-frame"] },
    { id: "whois", title: "WHOIS Registrar & Ownership Forensics", category: "Reconnaissance", icon: "🕵️", action: () => onSelectMode("whois"), keywords: ["whois", "registrar", "expiry", "nameserver"] },
    { id: "ip", title: "IP Geolocation & Threat Map", category: "Threat Intelligence", icon: "🌐", action: () => onSelectMode("ip"), keywords: ["ip", "asn", "geo", "threat", "isp"] },
    { id: "sandbox", title: "URL & File Detonation Sandbox", category: "Threat Intelligence", icon: "🧪", action: () => onSelectMode("sandbox"), keywords: ["sandbox", "malware", "detonate", "virustotal", "url"] },
    { id: "pwned", title: "Breach & Credential Leak Hunter", category: "Threat Intelligence", icon: "☠️", action: () => onSelectMode("pwned"), keywords: ["breach", "pwned", "password", "leak", "compromised"] },
    { id: "cve", title: "CVE Exploit & Vulnerability Search", category: "Threat Intelligence", icon: "🚨", action: () => onSelectMode("cve"), keywords: ["cve", "nvd", "vulnerability", "cvss", "exploit"] },
    { id: "email", title: "Email DMARC / SPF Spoofing Audit", category: "Threat Intelligence", icon: "📧", action: () => onSelectMode("email"), keywords: ["email", "spf", "dmarc", "dkim", "mail"] },
    { id: "attack_map", title: "3D Live Cyber Attack Globe", category: "Operations", icon: "🌍", action: () => onSelectMode("attack_map"), keywords: ["map", "globe", "3d", "attacks", "defcon"] },
    { id: "topology", title: "Attack Topology & Node Visualizer", category: "Operations", icon: "🕸️", action: () => onSelectMode("topology"), keywords: ["graph", "topology", "nodes", "network"] },
    { id: "toolkit", title: "Swiss Army Cyber Toolkit", category: "Operations", icon: "🔧", action: () => onSelectMode("toolkit"), keywords: ["tools", "hash", "subnet", "cidr", "base64", "dorks"] },
    { id: "report", title: "Executive Audit & Pentest Report", category: "Operations", icon: "📑", action: () => onSelectMode("report"), keywords: ["report", "pdf", "compliance", "executive", "audit"] },
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
    setSelectedIndex(0);
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (filtered.length || 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + (filtered.length || 1)) % (filtered.length || 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (filtered[selectedIndex]) {
        filtered[selectedIndex].action();
        onClose();
      } else if (query.trim()) {
        onTriggerScan(query.trim());
        onClose();
      }
    } else if (e.key === "Escape") {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4 bg-black/70 backdrop-blur-md animate-fadeIn">
      <div 
        className="w-full max-w-xl rounded-2xl bg-[#0e131d] border border-white/15 shadow-2xl overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-4 border-b border-white/10 flex items-center gap-3">
          <span className="text-cyan-400 font-mono text-base">⚡</span>
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a tool name, category, or domain to scan..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-transparent text-white placeholder-slate-400 text-sm font-sans focus:outline-none"
          />
          <kbd className="text-[10px] bg-white/10 px-2 py-0.5 rounded text-slate-300 font-mono">ESC</kbd>
        </div>

        <div className="max-h-80 overflow-y-auto p-2 space-y-1 scrollbar-thin">
          {filtered.length === 0 ? (
            <div className="p-4 text-center text-xs text-slate-400 font-mono">
              No matching tools. Press <span className="text-cyan-400 font-bold">Enter</span> to launch Quick Recon for "{query}".
            </div>
          ) : (
            filtered.map((item, idx) => (
              <button
                key={item.id}
                onClick={() => { item.action(); onClose(); }}
                className={`w-full flex items-center justify-between p-2.5 rounded-xl text-left transition-all ${
                  idx === selectedIndex 
                    ? "bg-cyan-500/20 text-white border border-cyan-500/40" 
                    : "text-slate-300 hover:bg-white/5 hover:text-white"
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-lg">{item.icon}</span>
                  <div>
                    <div className="text-xs font-semibold">{item.title}</div>
                    <div className="text-[10px] text-slate-400 font-mono">{item.category}</div>
                  </div>
                </div>
                <span className="text-xs font-mono text-cyan-400 opacity-60">↵</span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
