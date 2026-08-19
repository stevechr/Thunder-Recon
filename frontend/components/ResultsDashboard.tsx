"use client";

import { useState } from "react";
import { ScanResult } from "@/lib/api";
import RiskGauge from "./RiskGauge";

function Badge({ status }: { status: string }) {
  if (status === "PASS" || status === "harmless" || status === "clean") {
    return (
      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
        ✓ CLEAN / PASS
      </span>
    );
  }
  if (status === "WARN" || status === "suspicious") {
    return (
      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
        ▲ ATTENTION
      </span>
    );
  }
  if (status === "DANGER" || status === "malicious" || status === "Critical" || status === "High") {
    return (
      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse">
        ⚠ COMPROMISE / RISK
      </span>
    );
  }
  return (
    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
      ● INFO
    </span>
  );
}

function ModuleCard({
  num,
  title,
  status,
  summary,
  children,
}: {
  num: string;
  title: string;
  status: string;
  summary: string;
  children?: React.ReactNode;
}) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className="bg-panel border border-panelBorder rounded-xl overflow-hidden shadow-sm transition hover:border-cyan-signal/40">
      <div
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between p-4 bg-void/40 border-b border-panelBorder/70 cursor-pointer select-none hover:bg-void/60 transition"
      >
        <div className="flex items-center gap-2.5">
          <span className="font-mono text-xs font-bold text-cyan-signal">{num}</span>
          <h4 className="font-display text-sm font-semibold text-white tracking-tight">{title}</h4>
        </div>
        <div className="flex items-center gap-3">
          <Badge status={status} />
          <span className="text-xs text-mist">{expanded ? "▼" : "▶"}</span>
        </div>
      </div>

      <div className="p-4 space-y-3">
        <p className="text-xs text-mist leading-relaxed font-mono">{summary}</p>
        {expanded && children && <div className="pt-2 border-t border-panelBorder/50">{children}</div>}
      </div>
    </div>
  );
}

export default function ResultsDashboard({ result }: { result: ScanResult }) {
  const { dns_records, whois, ip_intel, ssl, ports, technology, breaches, risk, audit_modules, threat_intel, virustotal } = result;
  
  const [activeTab, setActiveTab] = useState<"overview" | "audit12" | "virustotal" | "remediations" | "subdomains">("overview");
  const [showAllEngines, setShowAllEngines] = useState(false);
  const [subdomainSearch, setSubdomainSearch] = useState("");

  const downloadReportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `thunder-recon-${result.domain}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const downloadReportMarkdown = () => {
    const mdContent = `# Thunder Recon Security Audit: ${result.domain}
- **Target Domain**: ${result.domain}
- **Assigned Account**: ${result.email || "N/A"}
- **IP Address**: ${result.ip || "N/A"}
- **Risk Score**: ${risk.score}/100 (${risk.rating})
- **Integrity Score**: ${threat_intel?.integrity_score ?? 100}/100 (${threat_intel?.integrity_rating ?? "Clean"})
- **Multi-AV Detections**: ${virustotal?.malicious_count ?? 0} / ${virustotal?.total_engines ?? 0} vendors flagged

## Threat & Compromise Assessment
- **Defacement Status**: ${threat_intel?.defacement?.is_defaced ? "DEFACED" : "Clean"}
- **Planted Malware**: ${threat_intel?.malware_planted?.is_infected ? "INFECTED" : "Clean"}
- **DNS Spoofing**: ${threat_intel?.dns_spoofing?.is_spoofed ? "SPOOFED" : "Consistent"}
- **SEO Spamming**: ${threat_intel?.seo_spam?.is_spammed ? "DETECTED" : "Clean"}

## 12-Point Comprehensive Audit
${Object.entries(audit_modules || {}).filter(([k]) => !k.startsWith("_")).map(([k, v]: [string, any]) => `### ${v.title}
- **Status**: ${v.status}
- **Summary**: ${v.summary}
`).join("\n")}
`;
    const dataStr = "data:text/markdown;charset=utf-8," + encodeURIComponent(mdContent);
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `thunder-recon-${result.domain}.md`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const m01 = audit_modules?.["01_asset_subdomains"];
  const m02 = audit_modules?.["02_cdn_waf"];
  const m03 = audit_modules?.["03_ports_services"];
  const m04 = audit_modules?.["04_tech_fingerprinting"];
  const m05 = audit_modules?.["05_tls_certificate"];
  const m06 = audit_modules?.["06_http_headers"];
  const m07 = audit_modules?.["07_dns_security"];
  const m08 = audit_modules?.["08_email_security"];
  const m09 = audit_modules?.["09_sensitive_files"];
  const m10 = audit_modules?.["10_api_discovery"];
  const m11 = audit_modules?.["11_authentication_testing"];
  const m12 = audit_modules?.["12_authorization_idor"];
  const remediations = audit_modules?.["_remediations"] || [];

  const filteredSubdomains = (m01?.assets || []).filter((a: any) =>
    a.subdomain.toLowerCase().includes(subdomainSearch.toLowerCase()) ||
    (a.ips || []).some((ip: string) => ip.includes(subdomainSearch))
  );

  return (
    <div className="w-full max-w-6xl space-y-6 animate-fadeIn">
      {/* Header + Risk summary */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-6 bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-mist uppercase tracking-widest font-mono">Target Domain</span>
            {result.email && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-signal/15 text-cyan-signal border border-cyan-signal/30">
                Verified: {result.email}
              </span>
            )}
          </div>
          <div className="font-display text-2xl sm:text-3xl font-extrabold mt-1 text-white tracking-tight">
            {result.domain}
          </div>
          <div className="text-xs font-mono text-mist mt-1">
            IP: <span className="text-cyan-signal">{result.ip || "Unresolved"}</span> • Host: {whois?.registrar || ip_intel?.isp || "Cloud Edge"}
          </div>

          {/* Export Actions */}
          <div className="flex items-center gap-3 mt-4">
            <button
              onClick={downloadReportJson}
              className="px-3.5 py-1.5 rounded-lg text-xs font-mono border border-cyan-signal/40 text-cyan-signal hover:bg-cyan-signal/10 transition shadow-sm"
            >
              ↓ Export JSON
            </button>
            <button
              onClick={downloadReportMarkdown}
              className="px-3.5 py-1.5 rounded-lg text-xs font-mono border border-panelBorder text-mist hover:text-white transition shadow-sm"
            >
              ↓ Export Markdown
            </button>
          </div>
        </div>
        <RiskGauge score={risk.score} rating={risk.rating} />
      </div>

      {/* Navigation Tab Bar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-panelBorder/70 pb-3">
        <button
          onClick={() => setActiveTab("overview")}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition ${
            activeTab === "overview"
              ? "bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/40 shadow-sm"
              : "bg-void/60 text-mist hover:text-white border border-panelBorder"
          }`}
        >
          🛡️ Overview & Threats
        </button>
        <button
          onClick={() => setActiveTab("audit12")}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition ${
            activeTab === "audit12"
              ? "bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/40 shadow-sm"
              : "bg-void/60 text-mist hover:text-white border border-panelBorder"
          }`}
        >
          🔍 12-Point Audit Matrix
        </button>
        <button
          onClick={() => setActiveTab("virustotal")}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition ${
            activeTab === "virustotal"
              ? "bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/40 shadow-sm"
              : "bg-void/60 text-mist hover:text-white border border-panelBorder"
          }`}
        >
          ⚡ VirusTotal & Multi-AV ({virustotal?.total_engines || 30})
        </button>
        <button
          onClick={() => setActiveTab("subdomains")}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition ${
            activeTab === "subdomains"
              ? "bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/40 shadow-sm"
              : "bg-void/60 text-mist hover:text-white border border-panelBorder"
          }`}
        >
          🌐 Subdomains & CT Logs ({m01?.count || 0})
        </button>
        <button
          onClick={() => setActiveTab("remediations")}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition ${
            activeTab === "remediations"
              ? "bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/40 shadow-sm"
              : "bg-void/60 text-mist hover:text-white border border-panelBorder"
          }`}
        >
          🔧 Remediation Roadmap ({remediations.length})
        </button>
      </div>

      {/* TAB 1: OVERVIEW & THREATS */}
      {(activeTab === "overview" || activeTab === "virustotal") && virustotal && (
        <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-panelBorder/70 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-signal border border-cyan-500/30">
                  VIRUSTOTAL MULTI-AV INTEL
                </span>
                <h3 className="font-display text-lg font-bold text-white">
                  Multi-Engine Threat Analysis
                </h3>
              </div>
              <p className="text-xs text-mist font-mono mt-0.5">
                Aggregated telemetry across {virustotal.total_engines} global antivirus and threat intelligence engines.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <a
                href={virustotal.vt_link}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1 text-xs font-mono rounded bg-void border border-cyan-signal/40 text-cyan-signal hover:bg-cyan-signal/10 transition shadow-sm"
              >
                VirusTotal Graph ↗
              </a>
              <span className={`text-xs font-mono font-bold px-3 py-1 rounded ${
                virustotal.malicious_count === 0
                  ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                  : "bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse"
              }`}>
                {virustotal.malicious_count} / {virustotal.total_engines} Flagged Malicious
              </span>
            </div>
          </div>

          {/* Stats Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1 text-center font-mono">
            <div className="bg-void/60 border border-panelBorder p-2.5 rounded-xl">
              <span className="text-[10px] text-mist block uppercase">Harmless / Clean</span>
              <span className="text-base font-bold text-emerald-400">{virustotal.harmless_count}</span>
            </div>
            <div className="bg-void/60 border border-panelBorder p-2.5 rounded-xl">
              <span className="text-[10px] text-mist block uppercase">Malicious</span>
              <span className={`text-base font-bold ${virustotal.malicious_count > 0 ? "text-rose-400" : "text-mist"}`}>
                {virustotal.malicious_count}
              </span>
            </div>
            <div className="bg-void/60 border border-panelBorder p-2.5 rounded-xl">
              <span className="text-[10px] text-mist block uppercase">Suspicious</span>
              <span className="text-base font-bold text-amber-300">{virustotal.suspicious_count}</span>
            </div>
            <div className="bg-void/60 border border-panelBorder p-2.5 rounded-xl">
              <span className="text-[10px] text-mist block uppercase">Reputation Score</span>
              <span className="text-base font-bold text-cyan-signal">{virustotal.reputation}/100</span>
            </div>
          </div>

          {/* Engine Results Matrix */}
          <div className="space-y-2 pt-2">
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-mist uppercase tracking-widest">Security Vendor Verdicts:</span>
              <button
                onClick={() => setShowAllEngines(!showAllEngines)}
                className="text-cyan-signal hover:underline"
              >
                {showAllEngines ? "Show Top Engines ▲" : `Show All ${virustotal.engine_results.length} Engines ▼`}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-64 overflow-y-auto pr-1">
              {(showAllEngines ? virustotal.engine_results : virustotal.engine_results.slice(0, 12)).map((eng, idx) => (
                <div key={idx} className="flex justify-between items-center bg-void/60 border border-panelBorder/70 px-3 py-2 rounded-lg text-xs font-mono">
                  <span className="text-white font-medium truncate max-w-[140px]">{eng.engine_name}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                    eng.category === "malicious"
                      ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                      : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                  }`}>
                    {eng.result.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Threat & Defacement Section */}
      {(activeTab === "overview" || activeTab === "virustotal") && threat_intel && (
        <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-panelBorder/70 pb-3">
            <div>
              <h3 className="font-display text-lg font-bold text-white flex items-center gap-2">
                <span>🛡️ Threat, Defacement & Compromise Scanner</span>
              </h3>
              <p className="text-xs text-mist font-mono">Real-time inspection for planted malware, web defacement, DNS spoofing, and SEO spam.</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-mist">Integrity Score:</span>
              <span className={`text-xs font-mono font-bold px-2.5 py-1 rounded ${
                threat_intel.integrity_score >= 80 ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-rose-500/20 text-rose-400 border border-rose-500/30"
              }`}>
                {threat_intel.integrity_score}/100 • {threat_intel.integrity_rating}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
            {/* Defacement Check */}
            <div className="bg-void/60 border border-panelBorder p-3.5 rounded-xl space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-mist">Defacement:</span>
                <Badge status={threat_intel.defacement.status} />
              </div>
              <p className="text-[11px] text-white font-mono leading-tight">{threat_intel.defacement.summary}</p>
            </div>

            {/* Planted Malware */}
            <div className="bg-void/60 border border-panelBorder p-3.5 rounded-xl space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-mist">Planted Malware:</span>
                <Badge status={threat_intel.malware_planted.status} />
              </div>
              <p className="text-[11px] text-white font-mono leading-tight">{threat_intel.malware_planted.summary}</p>
            </div>

            {/* DNS Spoofing */}
            <div className="bg-void/60 border border-panelBorder p-3.5 rounded-xl space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-mist">DNS Spoofing:</span>
                <Badge status={threat_intel.dns_spoofing.status} />
              </div>
              <p className="text-[11px] text-white font-mono leading-tight">{threat_intel.dns_spoofing.details}</p>
            </div>

            {/* SEO Spamming */}
            <div className="bg-void/60 border border-panelBorder p-3.5 rounded-xl space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-mist">SEO Spam Cloaking:</span>
                <Badge status={threat_intel.seo_spam.status} />
              </div>
              <p className="text-[11px] text-white font-mono leading-tight">{threat_intel.seo_spam.summary}</p>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: 12-POINT AUDIT MATRIX */}
      {(activeTab === "overview" || activeTab === "audit12") && (
        <div className="space-y-4">
          <div className="flex items-center justify-between pt-2">
            <div>
              <h3 className="font-display text-lg font-bold text-white">12-Point Security Audit Matrix</h3>
              <p className="text-xs text-mist font-mono">Detailed posture inspection across network, web application, and infrastructure layers.</p>
            </div>
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-cyan-signal/10 text-cyan-signal border border-cyan-signal/30">
              12 Active Controls
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* [01] Asset & Subdomain Discovery */}
            <ModuleCard
              num="[01]"
              title="Asset & Subdomain Discovery"
              status={m01?.status || "PASS"}
              summary={m01?.summary || `Enumerated DNS subdomains for ${result.domain}.`}
            >
              {m01?.assets && m01.assets.length > 0 ? (
                <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                  {m01.assets.map((a: any, idx: number) => (
                    <div key={idx} className="flex justify-between items-center bg-void/60 px-2.5 py-1 rounded text-xs font-mono">
                      <span className="text-white font-semibold">{a.subdomain}</span>
                      <span className="text-cyan-signal text-[11px]">{a.ips?.join(", ")}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-mist font-mono">No common active subdomains detected via public DNS.</div>
              )}
            </ModuleCard>

            {/* [02] CDN/WAF & Origin Detection */}
            <ModuleCard
              num="[02]"
              title="CDN/WAF & Origin Detection"
              status={m02?.status || "PASS"}
              summary={m02?.summary || "Analyzed edge headers for WAF masking and proxy routing."}
            >
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">Edge Providers:</span>
                  <span className="text-white font-semibold">{m02?.providers?.join(", ") || "Direct Origin"}</span>
                </div>
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">Origin IP Masking:</span>
                  <span className={m02?.origin_masked ? "text-emerald-400" : "text-amber-300"}>
                    {m02?.origin_masked ? "Protected by Edge Proxy" : "Exposed Origin IP"}
                  </span>
                </div>
              </div>
            </ModuleCard>

            {/* [03] Port/Service Verification */}
            <ModuleCard
              num="[03]"
              title="Port/Service Verification"
              status={m03?.status || "PASS"}
              summary={m03?.summary || `Verified open listening ports on ${result.ip}.`}
            >
              {ports.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {ports.map((p, i) => (
                    <span key={i} className="px-2 py-0.5 bg-void border border-panelBorder rounded text-xs font-mono text-cyan-signal">
                      {p.port} ({p.service})
                    </span>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-mist font-mono">No unauthorized open ports detected.</div>
              )}
            </ModuleCard>

            {/* [04] Web Technology Fingerprinting */}
            <ModuleCard
              num="[04]"
              title="Web Technology Fingerprinting"
              status={m04?.status || "INFO"}
              summary={m04?.summary || "Fingerprinted server runtime, CMS, and framework signatures."}
            >
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="bg-void/60 p-2 rounded">
                  <span className="text-mist block text-[10px]">SERVER:</span>
                  <span className="text-white font-semibold">{technology.server || "Masked"}</span>
                </div>
                <div className="bg-void/60 p-2 rounded">
                  <span className="text-mist block text-[10px]">CMS / STACK:</span>
                  <span className="text-white font-semibold">{technology.cms?.join(", ") || technology.powered_by || "Custom Web App"}</span>
                </div>
              </div>
            </ModuleCard>

            {/* [05] TLS/Certificate Security */}
            <ModuleCard
              num="[05]"
              title="TLS/Certificate Security"
              status={m05?.status || "PASS"}
              summary={m05?.summary || "Validated SSL/TLS certificate chain and cipher suites."}
            >
              <div className="space-y-1 text-xs font-mono">
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">Issuer:</span>
                  <span className="text-white">{ssl.issuer || "N/A"}</span>
                </div>
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">Valid To:</span>
                  <span className="text-white">{ssl.valid_to?.slice(0, 10) || "N/A"} ({ssl.days_remaining}d left)</span>
                </div>
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">Protocol:</span>
                  <span className="text-emerald-400">{ssl.tls_version || "TLSv1.3"}</span>
                </div>
              </div>
            </ModuleCard>

            {/* [06] HTTP Security Headers */}
            <ModuleCard
              num="[06]"
              title="HTTP Security Headers"
              status={m06?.status || "WARN"}
              summary={m06?.summary || "Audited HTTP response security hardening headers."}
            >
              <div className="space-y-1 text-xs font-mono">
                {m06?.headers && Object.entries(m06.headers).map(([k, v]: [string, any], idx: number) => (
                  <div key={idx} className="flex justify-between bg-void/60 px-2 py-0.5 rounded text-[11px]">
                    <span className="text-mist">{k}:</span>
                    <span className={v.includes("Missing") || v.includes("Not Configured") ? "text-amber-300" : "text-emerald-400"}>
                      {v}
                    </span>
                  </div>
                ))}
              </div>
            </ModuleCard>

            {/* [07] DNS Security */}
            <ModuleCard
              num="[07]"
              title="DNS Security"
              status={m07?.status || "PASS"}
              summary={m07?.summary || "Checked CAA certificates locking, nameserver redundancy, and SOA."}
            >
              <div className="space-y-1 text-xs font-mono">
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">Nameservers:</span>
                  <span className="text-white">{dns_records.NS?.length || 0} configured</span>
                </div>
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">CAA Record:</span>
                  <span className={dns_records.CAA?.length ? "text-emerald-400" : "text-amber-300"}>
                    {dns_records.CAA?.length ? "Enforced" : "Missing CAA"}
                  </span>
                </div>
              </div>
            </ModuleCard>

            {/* [08] Email Security */}
            <ModuleCard
              num="[08]"
              title="Email Security (SPF & DMARC)"
              status={m08?.status || "PASS"}
              summary={m08?.summary || "Audited email spoofing and anti-phishing defense records."}
            >
              <div className="space-y-1 text-xs font-mono">
                <div className="bg-void/60 p-2 rounded">
                  <span className="text-mist block text-[10px]">SPF RECORD:</span>
                  <span className="text-cyan-signal break-all">{m08?.spf || "Missing SPF"}</span>
                </div>
                <div className="bg-void/60 p-2 rounded">
                  <span className="text-mist block text-[10px]">DMARC RECORD:</span>
                  <span className="text-cyan-signal break-all">{m08?.dmarc || "Missing DMARC"}</span>
                </div>
              </div>
            </ModuleCard>

            {/* [09] Sensitive File Discovery */}
            <ModuleCard
              num="[09]"
              title="Sensitive File Discovery"
              status={m09?.status || "PASS"}
              summary={m09?.summary || "Probed standard configuration files, sitemaps, and robots declarations."}
            >
              {m09?.discovered && m09.discovered.length > 0 ? (
                <div className="space-y-1 text-xs font-mono">
                  {m09.discovered.map((d: any, idx: number) => (
                    <div key={idx} className="flex justify-between bg-void/60 px-2 py-1 rounded text-[11px]">
                      <span className="text-white">{d.path} ({d.label})</span>
                      <span className="text-cyan-signal">HTTP {d.status_code}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-mist font-mono">No exposed configuration or backup files detected.</div>
              )}
            </ModuleCard>

            {/* [10] API Discovery */}
            <ModuleCard
              num="[10]"
              title="API Discovery"
              status={m10?.status || "INFO"}
              summary={m10?.summary || "Searched for REST APIs, GraphQL, Swagger, and OpenAPI specs."}
            >
              {m10?.apis_detected && m10.apis_detected.length > 0 ? (
                <div className="space-y-1 text-xs font-mono">
                  {m10.apis_detected.map((a: any, idx: number) => (
                    <div key={idx} className="flex justify-between bg-void/60 px-2 py-1 rounded text-[11px]">
                      <span className="text-white">{a.path} ({a.type})</span>
                      <span className="text-emerald-400">HTTP {a.status_code}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-mist font-mono">No public Swagger or GraphQL endpoints openly exposed.</div>
              )}
            </ModuleCard>

            {/* [11] Authentication Testing */}
            <ModuleCard
              num="[11]"
              title="Authentication Testing"
              status={m11?.status || "PASS"}
              summary={m11?.summary || "Audited authentication entrypoints and session cookie flags."}
            >
              <div className="space-y-1.5 text-xs font-mono">
                {m11?.cookie_security && (
                  <div className="grid grid-cols-3 gap-1.5">
                    <div className="bg-void/60 p-1.5 rounded text-center">
                      <span className="text-[10px] text-mist block">SECURE</span>
                      <span className="text-emerald-400 font-bold">{m11.cookie_security.Secure_flag}</span>
                    </div>
                    <div className="bg-void/60 p-1.5 rounded text-center">
                      <span className="text-[10px] text-mist block">HTTPONLY</span>
                      <span className="text-emerald-400 font-bold">{m11.cookie_security.HttpOnly_flag}</span>
                    </div>
                    <div className="bg-void/60 p-1.5 rounded text-center">
                      <span className="text-[10px] text-mist block">SAMESITE</span>
                      <span className="text-emerald-400 font-bold">{m11.cookie_security.SameSite_flag}</span>
                    </div>
                  </div>
                )}
              </div>
            </ModuleCard>

            {/* [12] Authorization / IDOR Testing */}
            <ModuleCard
              num="[12]"
              title="Authorization / IDOR Testing"
              status={m12?.status || "PASS"}
              summary={m12?.summary || "Inspected administrative surfaces, CORS policies, and access controls."}
            >
              <div className="space-y-1 text-xs font-mono">
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">CORS Access-Control:</span>
                  <span className="text-white">{m12?.cors_policy?.allow_origin || "Same-Origin (Restricted)"}</span>
                </div>
                <div className="flex justify-between bg-void/60 px-2.5 py-1 rounded">
                  <span className="text-mist">Admin Endpoints:</span>
                  <span className={m12?.admin_interfaces?.length ? "text-amber-300" : "text-emerald-400"}>
                    {m12?.admin_interfaces?.length ? `${m12.admin_interfaces.length} Interfaces Found` : "Access Restricted"}
                  </span>
                </div>
              </div>
            </ModuleCard>
          </div>
        </div>
      )}

      {/* TAB 3: SUBDOMAINS & CT LOGS */}
      {activeTab === "subdomains" && (
        <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-panelBorder/70 pb-3">
            <div>
              <h3 className="font-display text-lg font-bold text-white">
                Discovered Subdomains & Certificate Transparency Logs
              </h3>
              <p className="text-xs text-mist font-mono">
                Real subdomains extracted via crt.sh CT logs and verified via active DNS resolution.
              </p>
            </div>
            <input
              type="text"
              placeholder="Search subdomains or IPs..."
              value={subdomainSearch}
              onChange={(e) => setSubdomainSearch(e.target.value)}
              className="px-3 py-1.5 text-xs font-mono bg-void border border-panelBorder rounded-lg text-white focus:outline-none focus:border-cyan-signal w-full sm:w-64"
            />
          </div>

          <div className="space-y-2">
            {filteredSubdomains.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-96 overflow-y-auto pr-1">
                {filteredSubdomains.map((sub: any, idx: number) => (
                  <div key={idx} className="bg-void/70 border border-panelBorder/70 p-3 rounded-xl flex justify-between items-center text-xs font-mono">
                    <div>
                      <span className="text-white font-bold block">{sub.subdomain}</span>
                      <span className="text-[11px] text-cyan-signal font-mono">{sub.ips?.join(", ")}</span>
                    </div>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      ACTIVE
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-6 text-center text-mist font-mono text-xs bg-void/50 rounded-xl border border-panelBorder">
                No matching subdomains found for "{subdomainSearch}".
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: REMEDIATION ROADMAP */}
      {activeTab === "remediations" && (
        <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
          <div className="border-b border-panelBorder/70 pb-3">
            <h3 className="font-display text-lg font-bold text-white">
              Actionable Security Remediation Roadmap
            </h3>
            <p className="text-xs text-mist font-mono">
              Step-by-step hardened configuration guides to mitigate discovered risks.
            </p>
          </div>

          {remediations.length === 0 ? (
            <div className="p-6 text-center text-emerald-400 font-mono text-xs bg-emerald-500/10 rounded-xl border border-emerald-500/30">
              ✓ Excellent security posture! No high-priority remediations required.
            </div>
          ) : (
            <div className="space-y-3">
              {remediations.map((rem: any, idx: number) => (
                <div key={idx} className="bg-void/70 border border-panelBorder p-4 rounded-xl space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-mono text-cyan-signal font-bold uppercase tracking-wider">{rem.category}</span>
                    <Badge status={rem.priority} />
                  </div>
                  <h4 className="text-sm font-bold text-white">{rem.issue}</h4>
                  <p className="text-xs text-mist font-mono leading-relaxed bg-void/90 p-2.5 rounded-lg border border-panelBorder/60">
                    💡 <strong className="text-white">Recommended Action:</strong> {rem.action}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Breach Intelligence Section */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
        <h3 className="font-display text-lg font-bold text-white">
          Data Breach & Leak Intelligence ({breaches?.breach_count || 0} breaches)
        </h3>

        {(!breaches || breaches.breach_count === 0) ? (
          <div className="flex items-center gap-3 p-3.5 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-sm text-emerald-400 font-mono">
            <span>✓</span>
            <span>No historical data breaches or credential dumps detected for {result.domain}.</span>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 p-3.5 bg-crimson-risk/10 border border-crimson-risk/30 rounded-xl">
              <div className="text-sm text-crimson-risk font-semibold font-mono">
                ⚠️ Domain exposed in {breaches.breach_count} known data breaches ({breaches.total_pwned_accounts ? breaches.total_pwned_accounts.toLocaleString() : "Multiple"} compromised accounts).
              </div>
              <span className="text-xs font-mono font-bold px-2.5 py-1 bg-crimson-risk text-white rounded-lg">
                {breaches.risk_level}
              </span>
            </div>

            {breaches.exposed_data_types && breaches.exposed_data_types.length > 0 && (
              <div className="text-xs font-mono">
                <span className="text-mist">EXPOSED ATTRIBUTES: </span>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {breaches.exposed_data_types.map((dt, i) => (
                    <span key={i} className="px-2 py-0.5 bg-panelBorder text-amber-warn rounded font-mono text-[11px]">
                      {dt}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <div className="text-xs font-mono text-mist uppercase tracking-widest">Breach Event Records:</div>
              {breaches.breaches.map((b, idx) => (
                <div key={idx} className="bg-void/80 border border-panelBorder/70 p-3.5 rounded-xl text-xs space-y-1">
                  <div className="flex justify-between font-bold text-amber-warn text-sm">
                    <span>{b.title || b.name}</span>
                    <span className="text-mist font-mono text-xs">{b.breach_date}</span>
                  </div>
                  {b.description && (
                    <p className="text-mist leading-relaxed" dangerouslySetInnerHTML={{ __html: b.description }} />
                  )}
                  {b.data_classes && b.data_classes.length > 0 && (
                    <div className="flex flex-wrap gap-1 pt-1">
                      {b.data_classes.map((dc, k) => (
                        <span key={k} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-crimson-risk/20 text-crimson-risk">
                          {dc}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
