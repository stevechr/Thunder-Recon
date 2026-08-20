"use client";

import { useState } from "react";

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  relevance: string;
  adversaryBehavior: string;
  d3fendCountermeasure: string;
  detectedSignals: string[];
}

const TACTICS = [
  { name: "Reconnaissance", id: "TA0043", color: "text-cyan-400" },
  { name: "Resource Dev", id: "TA0042", color: "text-blue-400" },
  { name: "Initial Access", id: "TA0001", color: "text-red-400" },
  { name: "Discovery", id: "TA0007", color: "text-amber-400" },
  { name: "Defense Evasion", id: "TA0005", color: "text-purple-400" },
  { name: "Credential Access", id: "TA0006", color: "text-orange-400" },
];

const TECHNIQUES: MitreTechnique[] = [
  {
    id: "T1596",
    name: "Search Open Technical Databases",
    tactic: "Reconnaissance",
    severity: "HIGH",
    relevance: "DNS records, WHOIS registrant, and Certificate Transparency (crt.sh) logs are publicly indexed.",
    adversaryBehavior: "Adversaries query public DNS, BGP routing tables, and CT logs to map all company subdomains without touching target servers.",
    d3fendCountermeasure: "D3-DNSDEC (DNS Decoy Query Analysis) & WHOIS Privacy Masking.",
    detectedSignals: ["Exposed crt.sh Subdomain Tree", "Public WHOIS Registrant Email", "BGPview ASN Allocation Records"],
  },
  {
    id: "T1595.002",
    name: "Vulnerability Scanning",
    tactic: "Reconnaissance",
    severity: "MEDIUM",
    relevance: "Public web endpoints disclose server banners (Apache, Nginx, Express) and software versions.",
    adversaryBehavior: "Automated scanners search for known unpatched CVEs on detected tech stack components.",
    d3fendCountermeasure: "D3-SRO (Server Response Obfuscation) & Banner Stripping.",
    detectedSignals: ["Server: Nginx/1.18.0 Header", "X-Powered-By: Express Header", "Unmasked CMS Version"],
  },
  {
    id: "T1566",
    name: "Phishing (Email Impersonation)",
    tactic: "Initial Access",
    severity: "HIGH",
    relevance: "DMARC policy configured as 'none' allows attackers to spoof domain emails.",
    adversaryBehavior: "Adversaries craft fake emails claiming to be company executives to conduct Business Email Compromise (BEC).",
    d3fendCountermeasure: "D3-DMARCV (DMARC Record Verification) & Inbound DKIM Cryptographic Enforcement.",
    detectedSignals: ["p=none in _dmarc TXT record", "SPF softfail (~all) qualifier"],
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "Initial Access",
    severity: "HIGH",
    relevance: "Open TCP ports (e.g. 8080, 8443, 3000) and unauthenticated API endpoints.",
    adversaryBehavior: "Attackers send crafted exploit payloads targeting exposed Web APIs or debug endpoints.",
    d3fendCountermeasure: "D3-WAF (Web Application Firewall Rule Enforcement) & Reverse Proxy Authentication.",
    detectedSignals: ["Open Port 8080 (HTTP-Alt)", "Exposed /swagger-ui API Docs"],
  },
  {
    id: "T1046",
    name: "Network Service Discovery",
    tactic: "Discovery",
    severity: "MEDIUM",
    relevance: "Perimeter allows direct TCP SYN connections across multiple non-standard ports.",
    adversaryBehavior: "Adversaries map network perimeter services using port scanners to locate entry points.",
    d3fendCountermeasure: "D3-IBPA (Inbound Port Filtering & Perimeter Stateful Firewall).",
    detectedSignals: ["Multiple Open TCP Ports without IP whitelisting"],
  },
  {
    id: "T1562.001",
    name: "Disable / Impair Security Defenses",
    tactic: "Defense Evasion",
    severity: "HIGH",
    relevance: "No WAF (Cloudflare/AWS WAF) signature detected on target root domain.",
    adversaryBehavior: "Adversaries bypass application filters when perimeter inspection engines are absent.",
    d3fendCountermeasure: "D3-WAF (Cloud Edge Web Application Firewall & Rate Limiting).",
    detectedSignals: ["WAF Detection: None Identified", "Rate Limiting: Disabled"],
  },
];

export default function MitreNavigator() {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(TECHNIQUES[0]);
  const [activeTactic, setActiveTactic] = useState<string>("all");

  const filteredTechniques = TECHNIQUES.filter(
    (t) => activeTactic === "all" || t.tactic === activeTactic
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">🗺️</span>
            MITRE ATT&CK® Enterprise Navigator
          </h2>
          <p className="text-sm text-mist mt-1">
            Map reconnaissance findings & attack surfaces directly to adversary techniques and D3FEND defensive controls.
          </p>
        </div>
      </div>

      {/* Tactics Selector Bar */}
      <div className="flex flex-wrap gap-2 p-3 bg-surface/60 border border-border/60 rounded-2xl">
        <button
          onClick={() => setActiveTactic("all")}
          className={`text-xs px-3 py-1.5 rounded-lg border transition ${
            activeTactic === "all"
              ? "bg-red-500/20 text-red-400 border-red-500/40 font-bold"
              : "bg-void text-mist border-border hover:text-white"
          }`}
        >
          All Tactics ({TECHNIQUES.length})
        </button>
        {TACTICS.map((tac) => {
          const count = TECHNIQUES.filter((t) => t.tactic === tac.name).length;
          return (
            <button
              key={tac.id}
              onClick={() => setActiveTactic(tac.name)}
              className={`text-xs px-3 py-1.5 rounded-lg border transition flex items-center gap-1.5 ${
                activeTactic === tac.name
                  ? "bg-void text-white border-red-500/60 font-bold"
                  : "bg-void/40 text-mist border-border hover:text-white"
              }`}
            >
              <span className={tac.color}>●</span>
              <span>{tac.name}</span>
              <span className="text-[10px] opacity-60">({count})</span>
            </button>
          );
        })}
      </div>

      {/* Main Grid: Matrix Columns & Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Techniques List Column */}
        <div className="lg:col-span-1 space-y-2.5">
          <span className="text-[10px] font-mono uppercase tracking-widest text-mist font-bold block mb-1">
            Mapped Adversary Techniques
          </span>
          <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            {filteredTechniques.map((t) => (
              <div
                key={t.id}
                onClick={() => setSelectedTechnique(t)}
                className={`p-3.5 rounded-xl border transition cursor-pointer space-y-1.5 ${
                  selectedTechnique?.id === t.id
                    ? "bg-void border-red-500/80 shadow-lg shadow-red-500/10"
                    : "bg-surface/80 border-border hover:border-border/80"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-red-400">{t.id}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-void border border-border text-mist font-mono">
                    {t.tactic}
                  </span>
                </div>
                <div className="font-bold text-white text-xs">{t.name}</div>
                <div className="text-[10px] text-mist/70 truncate">{t.relevance}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Technique Detail & Countermeasure Drawer */}
        <div className="lg:col-span-2">
          {selectedTechnique ? (
            <div className="bg-surface/90 border border-border rounded-2xl p-6 space-y-5 animate-fadeIn">
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/40 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                      {selectedTechnique.id}
                    </span>
                    <span className="text-xs text-mist font-mono">Tactic: {selectedTechnique.tactic}</span>
                  </div>
                  <h3 className="text-xl font-bold text-white mt-1">{selectedTechnique.name}</h3>
                </div>

                <a
                  href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace(".", "/")}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs px-3 py-1.5 rounded-xl bg-void hover:bg-void/80 border border-border text-red-400 font-sans transition inline-flex items-center gap-1 shrink-0"
                >
                  <span>MITRE Reference</span>
                  <span>↗</span>
                </a>
              </div>

              {/* Exposure in Target Scan */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-amber-400 uppercase tracking-wider block font-mono">
                  🚨 Observed Exposure on Target Perimeter
                </span>
                <p className="text-xs text-white/90 bg-void/60 border border-border p-3 rounded-xl leading-relaxed">
                  {selectedTechnique.relevance}
                </p>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {selectedTechnique.detectedSignals.map((sig, i) => (
                    <span key={i} className="text-[11px] px-2.5 py-1 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 font-mono">
                      ⚡ {sig}
                    </span>
                  ))}
                </div>
              </div>

              {/* Adversary Behavior Breakdown */}
              <div className="space-y-1.5">
                <span className="text-xs font-bold text-mist uppercase tracking-wider block font-mono">
                  ⚔️ Adversary Threat Vector & TTP
                </span>
                <p className="text-xs text-mist/90 bg-void/40 border border-border/60 p-3 rounded-xl leading-relaxed">
                  {selectedTechnique.adversaryBehavior}
                </p>
              </div>

              {/* MITRE D3FEND Countermeasure */}
              <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-2xl space-y-2">
                <div className="flex items-center gap-2">
                  <span>🛡️</span>
                  <span className="text-xs font-bold text-emerald-400 font-mono uppercase tracking-wider">
                    MITRE D3FEND™ Defensive Countermeasure
                  </span>
                </div>
                <p className="text-xs text-emerald-200 font-semibold">{selectedTechnique.d3fendCountermeasure}</p>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center p-12 bg-surface/40 border border-border rounded-2xl text-mist text-xs">
              Select a MITRE ATT&CK technique on the left to view threat analysis and defensive mitigations.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
