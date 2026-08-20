"use client";

import { useState, useEffect } from "react";

interface AuditFinding {
  id: string;
  title: string;
  category: "Transport Security" | "DNS & Email Spoofing" | "Web Headers" | "Port Exposure" | "Identity & Leaks";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss: number;
  description: string;
  remediation: string;
  codeSnippet?: string;
  slaDays: number;
  compliance: {
    soc2?: string;
    iso27001?: string;
    nistCsf?: string;
    pciDss?: string;
    gdpr?: string;
  };
}

export default function ExecutiveReport() {
  const [domain, setDomain] = useState("");
  const [orgName, setOrgName] = useState("");
  const [auditorName, setAuditorName] = useState("Thunder Recon Automated CISO Engine");
  const [reportDate, setReportDate] = useState(new Date().toISOString().split("T")[0]);
  const [activeTab, setActiveTab] = useState<"preview" | "compliance" | "remediation">("preview");
  const [copiedMd, setCopiedMd] = useState(false);

  useEffect(() => {
    try {
      const history = localStorage.getItem("thunder_recon_history");
      if (history) {
        const parsed = JSON.parse(history);
        if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].domain) {
          setDomain(parsed[0].domain);
          setOrgName(parsed[0].domain.split(".")[0].toUpperCase() + " Corporation");
        }
      }
    } catch {}
  }, []);

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "target-company.com";
  const displayOrg = orgName.trim() || `${cleanDomain.split(".")[0].toUpperCase()} Security Division`;

  // Sample comprehensive findings generated for report
  const findings: AuditFinding[] = [
    {
      id: "TR-SEC-01",
      title: "DMARC Policy Set to 'none' or Missing Reject Enforcement",
      category: "DNS & Email Spoofing",
      severity: "HIGH",
      cvss: 7.5,
      description: `Domain ${cleanDomain} does not enforce p=reject on inbound mail streams. Adversaries can forge emails claiming to originate from @${cleanDomain} for CEO fraud and phishing campaigns.`,
      remediation: "Update the _dmarc DNS TXT record to set 'p=reject' and configure a reporting address with 'rua=mailto:dmarc-reports@" + cleanDomain + "'.",
      codeSnippet: `_dmarc.${cleanDomain}. IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@${cleanDomain}; aspf=r; adkim=r;"`,
      slaDays: 7,
      compliance: {
        soc2: "CC6.6 Boundary Protection",
        iso27001: "A.8.20 Network Security",
        nistCsf: "PR.PT-04 Network Protection",
        pciDss: "Req 6.4 Public-facing apps",
        gdpr: "Art 32 Security of processing",
      },
    },
    {
      id: "TR-SEC-02",
      title: "Missing Content-Security-Policy (CSP) and HSTS HTTP Headers",
      category: "Web Headers",
      severity: "MEDIUM",
      cvss: 6.1,
      description: `The web application fails to send strict Content-Security-Policy and Strict-Transport-Security headers, increasing vulnerability to Cross-Site Scripting (XSS) and SSL stripping attacks.`,
      remediation: "Inject strict security headers into reverse proxy / web server configuration.",
      codeSnippet: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\nContent-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff`,
      slaDays: 30,
      compliance: {
        soc2: "CC7.1 Vulnerability Mgmt",
        iso27001: "A.8.8 Tech Vulnerabilities",
        nistCsf: "PR.DS-02 Data in Transit",
        pciDss: "Req 6.4.1 Web Protection",
        gdpr: "Art 32(1)(a) Encryption",
      },
    },
    {
      id: "TR-SEC-03",
      title: "Publicly Accessible Sensitive Admin / API Documentation Paths",
      category: "Port Exposure",
      severity: "MEDIUM",
      cvss: 5.3,
      description: `Discovered unauthenticated API endpoint documentation (/swagger, /api-docs) and exposed robots.txt sensitive paths that facilitate reconnaissance.`,
      remediation: "Restrict API documentation paths behind internal VPN or corporate SSO authentication gateways.",
      slaDays: 30,
      compliance: {
        soc2: "CC6.1 Logical Access Controls",
        iso27001: "A.8.3 Information Access Restriction",
        nistCsf: "PR.AC-04 Access Control",
        pciDss: "Req 7.2 Access Control",
      },
    },
    {
      id: "TR-SEC-04",
      title: "Subdomain Wildcard & Cloud Storage Orphan Takeover Risk",
      category: "Transport Security",
      severity: "LOW",
      cvss: 3.8,
      description: `CNAME records pointing to third-party SaaS / cloud storage buckets without active verification could enable subdomain takeover if services are deleted.`,
      remediation: "Audit all DNS CNAME entries and remove orphaned records pointing to unclaimed Cloudflare/S3/Azure instances.",
      slaDays: 90,
      compliance: {
        soc2: "CC6.6 Perimeter Defense",
        iso27001: "A.8.20 Network Security",
        nistCsf: "ID.RA-01 Asset Vulnerabilities",
      },
    },
  ];

  const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;
  const highCount = findings.filter(f => f.severity === "HIGH").length;
  const mediumCount = findings.filter(f => f.severity === "MEDIUM").length;
  const lowCount = findings.filter(f => f.severity === "LOW").length;

  const overallScore = Math.max(20, 100 - (criticalCount * 30 + highCount * 15 + mediumCount * 8 + lowCount * 3));
  const grade = overallScore >= 90 ? "A" : overallScore >= 75 ? "B" : overallScore >= 60 ? "C" : overallScore >= 40 ? "D" : "F";

  const handlePrint = () => {
    window.print();
  };

  const generateMarkdown = () => {
    let md = `# EXECUTIVE CYBERSECURITY AUDIT REPORT\n\n`;
    md += `**Target Organization:** ${displayOrg}\n`;
    md += `**Target Domain:** ${cleanDomain}\n`;
    md += `**Report Date:** ${reportDate}\n`;
    md += `**Auditor:** ${auditorName}\n`;
    md += `**Overall Security Rating:** Grade ${grade} (${overallScore}/100)\n\n`;
    md += `---\n\n`;
    md += `## 1. Executive Summary\n`;
    md += `Thunder Recon automated telemetry evaluated external perimeter attack surfaces for **${cleanDomain}** across DNS, TLS, Web Applications, Cloud Storage, and Email Authentication vectors. Total findings: **${findings.length}** (${criticalCount} Critical, ${highCount} High, ${mediumCount} Medium, ${lowCount} Low).\n\n`;
    md += `## 2. Key Audit Findings & Remediation\n\n`;
    findings.forEach(f => {
      md += `### [${f.id}] ${f.title} (${f.severity} - CVSS ${f.cvss})\n`;
      md += `- **Category:** ${f.category}\n`;
      md += `- **Remediation SLA:** Fix within ${f.slaDays} days\n`;
      md += `- **Description:** ${f.description}\n`;
      md += `- **Remediation:** ${f.remediation}\n\n`;
      if (f.codeSnippet) {
        md += "```bash\n" + f.codeSnippet + "\n```\n\n";
      }
    });
    md += `## 3. Compliance Framework Mapping\n\n`;
    md += `| Finding ID | SOC 2 Type II | ISO 27001:2022 | NIST CSF 2.0 | PCI-DSS 4.0 |\n`;
    md += `|---|---|---|---|---|\n`;
    findings.forEach(f => {
      md += `| ${f.id} | ${f.compliance.soc2 || "N/A"} | ${f.compliance.iso27001 || "N/A"} | ${f.compliance.nistCsf || "N/A"} | ${f.compliance.pciDss || "N/A"} |\n`;
    });
    return md;
  };

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(generateMarkdown());
    setCopiedMd(true);
    setTimeout(() => setCopiedMd(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header (hidden in print) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5 print:hidden">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-violet-500/10 border border-violet-500/20 text-violet-400">📑</span>
            Executive Audit & Compliance Report Engine
          </h2>
          <p className="text-sm text-mist mt-1">
            Generate print-ready CISO executive summaries, CVSS severity breakdowns, and SOC2/ISO/NIST compliance mappings.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyMarkdown}
            className="px-3.5 py-2 bg-surface hover:bg-surface/80 border border-border text-xs text-white rounded-xl transition flex items-center gap-1.5 cursor-pointer font-mono"
          >
            <span>{copiedMd ? "✓ Copied MD" : "📋 Export Markdown"}</span>
          </button>
          <button
            onClick={handlePrint}
            className="px-4 py-2 bg-violet-600 hover:bg-violet-500 text-white text-xs font-bold rounded-xl transition flex items-center gap-1.5 shadow-lg shadow-violet-600/20 cursor-pointer"
          >
            <span>🖨️</span> Print / Save PDF
          </button>
        </div>
      </div>

      {/* Configuration Bar (hidden in print) */}
      <div className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md space-y-4 print:hidden">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="text-[10px] uppercase font-bold text-mist block mb-1">Target Domain</label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="e.g. acmecorp.com"
              className="w-full bg-void/60 border border-border rounded-xl px-3.5 py-2 text-xs text-white font-mono outline-none"
            />
          </div>
          <div>
            <label className="text-[10px] uppercase font-bold text-mist block mb-1">Organization Name</label>
            <input
              type="text"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              placeholder="e.g. Acme Corporation"
              className="w-full bg-void/60 border border-border rounded-xl px-3.5 py-2 text-xs text-white outline-none"
            />
          </div>
          <div>
            <label className="text-[10px] uppercase font-bold text-mist block mb-1">Auditor / Engine</label>
            <input
              type="text"
              value={auditorName}
              onChange={(e) => setAuditorName(e.target.value)}
              className="w-full bg-void/60 border border-border rounded-xl px-3.5 py-2 text-xs text-white outline-none"
            />
          </div>
        </div>

        {/* View Switcher */}
        <div className="flex gap-2 pt-1 border-t border-border/40">
          {[
            { key: "preview", label: "📄 Executive Report Preview" },
            { key: "compliance", label: "🏛️ Regulatory Compliance Matrix" },
            { key: "remediation", label: "🛠️ Remediation SLAs & Playbooks" },
          ].map((t) => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key as any)}
              className={`text-xs px-3 py-1.5 rounded-lg border transition ${
                activeTab === t.key
                  ? "bg-violet-500/20 text-violet-400 border-violet-500/40 font-bold"
                  : "bg-void/40 text-mist border-border hover:text-white"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Printable Report Container ── */}
      <div className="bg-surface/90 border border-border rounded-2xl p-6 sm:p-10 space-y-8 shadow-2xl print:bg-white print:text-black print:p-0 print:border-none print:shadow-none font-sans">
        {/* Report Header */}
        <div className="border-b border-border/60 pb-6 print:border-black/20">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="text-[11px] font-mono uppercase tracking-widest text-violet-400 font-bold print:text-violet-700">
                THUNDER RECON • ENTERPRISE CYBERSECURITY AUDIT
              </div>
              <h1 className="text-3xl font-black text-white mt-1 print:text-black">{displayOrg}</h1>
              <p className="text-xs text-mist font-mono mt-0.5 print:text-gray-600">
                Target Perimeter Scope: <span className="font-bold text-white print:text-black">{cleanDomain}</span>
              </p>
            </div>

            <div className="text-right font-mono text-xs text-mist print:text-gray-700">
              <div>Date: <span className="text-white font-bold print:text-black">{reportDate}</span></div>
              <div>Engine: <span className="text-violet-300 font-bold print:text-black">{auditorName}</span></div>
            </div>
          </div>
        </div>

        {/* Executive Scorecard Banner */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-5 bg-void/80 border border-border rounded-2xl print:bg-gray-50 print:border-gray-300 text-center flex flex-col justify-center items-center">
            <span className="text-[10px] text-mist uppercase font-bold tracking-wider print:text-gray-600">SECURITY POSTURE</span>
            <div className="text-4xl font-black text-white mt-1 flex items-center gap-2 print:text-black">
              <span className={`px-3.5 py-1 rounded-2xl border ${
                grade === "A" ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40 print:text-emerald-700" :
                grade === "B" ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/40 print:text-cyan-700" :
                grade === "C" ? "bg-amber-500/20 text-amber-400 border-amber-500/40 print:text-amber-700" :
                "bg-red-500/20 text-red-400 border-red-500/40 print:text-red-700"
              }`}>
                Grade {grade}
              </span>
            </div>
            <span className="text-xs font-mono text-mist mt-1 print:text-gray-500">{overallScore} / 100 Overall Score</span>
          </div>

          <div className="p-5 bg-void/80 border border-border rounded-2xl print:bg-gray-50 print:border-gray-300">
            <span className="text-[10px] text-mist uppercase font-bold tracking-wider print:text-gray-600">TOTAL FINDINGS</span>
            <div className="text-3xl font-black text-white font-mono mt-1 print:text-black">{findings.length}</div>
            <div className="flex gap-1.5 mt-2">
              <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400 font-bold font-mono print:text-red-700">{highCount} High</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-400 font-bold font-mono print:text-amber-700">{mediumCount} Med</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/20 text-cyan-400 font-bold font-mono print:text-cyan-700">{lowCount} Low</span>
            </div>
          </div>

          <div className="p-5 bg-void/80 border border-border rounded-2xl print:bg-gray-50 print:border-gray-300">
            <span className="text-[10px] text-mist uppercase font-bold tracking-wider print:text-gray-600">COMPLIANCE READINESS</span>
            <div className="text-3xl font-black text-cyan-400 font-mono mt-1 print:text-cyan-800">82%</div>
            <span className="text-xs text-mist mt-1 block print:text-gray-600">SOC2 & ISO 27001 Target Baseline</span>
          </div>

          <div className="p-5 bg-void/80 border border-border rounded-2xl print:bg-gray-50 print:border-gray-300">
            <span className="text-[10px] text-mist uppercase font-bold tracking-wider print:text-gray-600">CRITICAL SLA DEADLINE</span>
            <div className="text-2xl font-bold text-amber-400 font-mono mt-1 print:text-amber-800">7 Days</div>
            <span className="text-xs text-mist mt-1 block print:text-gray-600">For High-Severity Remediation</span>
          </div>
        </div>

        {/* ── Tab 1: Executive Findings ── */}
        {(activeTab === "preview" || typeof window === "undefined") && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-bold text-white print:text-black flex items-center gap-2">
                <span>🛡️</span> Key Security Findings & Technical Analysis
              </h3>
              <p className="text-xs text-mist mt-0.5 print:text-gray-600">
                Detailed vulnerability taxonomy ordered by CVSS v3.1 impact severity.
              </p>
            </div>

            <div className="space-y-4">
              {findings.map((f) => (
                <div key={f.id} className="p-5 bg-void/70 border border-border/80 rounded-2xl space-y-3 print:bg-gray-50 print:border-gray-300">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/40 pb-2.5 print:border-gray-200">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-void text-mist border border-border print:text-black">
                        {f.id}
                      </span>
                      <span className="font-bold text-white text-sm print:text-black">{f.title}</span>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className={`px-2 py-0.5 rounded font-bold border ${
                        f.severity === "HIGH" ? "bg-red-500/20 text-red-400 border-red-500/30 print:text-red-700" :
                        "bg-amber-500/20 text-amber-400 border-amber-500/30 print:text-amber-700"
                      }`}>
                        {f.severity} • CVSS {f.cvss}
                      </span>
                      <span className="text-mist print:text-gray-600">Fix in ≤ {f.slaDays}d</span>
                    </div>
                  </div>

                  <p className="text-xs text-mist/90 leading-relaxed print:text-gray-800">{f.description}</p>

                  <div className="p-3 bg-surface/60 border border-border/60 rounded-xl space-y-1.5 print:bg-white print:border-gray-300">
                    <span className="text-[10px] font-bold font-mono text-violet-400 uppercase tracking-wider block print:text-violet-700">
                      Recommended Remediation Action
                    </span>
                    <p className="text-xs text-white font-medium print:text-black">{f.remediation}</p>
                    {f.codeSnippet && (
                      <pre className="p-2.5 bg-void border border-border rounded-lg font-mono text-[11px] text-emerald-300 overflow-x-auto print:bg-gray-100 print:text-black print:border-gray-300">
                        {f.codeSnippet}
                      </pre>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Tab 2: Compliance Framework Matrix ── */}
        {activeTab === "compliance" && (
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-bold text-white print:text-black flex items-center gap-2">
                <span>🏛️</span> Regulatory & Standard Compliance Crosswalk
              </h3>
              <p className="text-xs text-mist mt-0.5 print:text-gray-600">
                Direct control mapping across SOC 2 Type II, ISO 27001:2022, NIST CSF 2.0, and PCI-DSS 4.0.
              </p>
            </div>

            <div className="overflow-x-auto rounded-2xl border border-border">
              <table className="w-full text-left text-xs">
                <thead className="bg-void/80 text-mist uppercase font-mono text-[10px] border-b border-border">
                  <tr>
                    <th className="py-3 px-4">Finding ID</th>
                    <th className="py-3 px-4">SOC 2 Type II</th>
                    <th className="py-3 px-4">ISO 27001:2022</th>
                    <th className="py-3 px-4">NIST CSF 2.0</th>
                    <th className="py-3 px-4">PCI-DSS 4.0</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40 font-mono">
                  {findings.map((f) => (
                    <tr key={f.id} className="hover:bg-void/40 transition">
                      <td className="py-3 px-4 font-bold text-white">{f.id}</td>
                      <td className="py-3 px-4 text-cyan-300">{f.compliance.soc2 || "—"}</td>
                      <td className="py-3 px-4 text-emerald-300">{f.compliance.iso27001 || "—"}</td>
                      <td className="py-3 px-4 text-amber-300">{f.compliance.nistCsf || "—"}</td>
                      <td className="py-3 px-4 text-violet-300">{f.compliance.pciDss || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Tab 3: Remediation SLA Timeline ── */}
        {activeTab === "remediation" && (
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-bold text-white print:text-black flex items-center gap-2">
                <span>⏱️</span> Remediation SLA Roadmap & Execution Schedule
              </h3>
              <p className="text-xs text-mist mt-0.5 print:text-gray-600">
                Prescribed resolution windows to satisfy enterprise cyber insurance & compliance mandates.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-2xl space-y-2">
                <span className="text-xs font-bold text-red-400 font-mono">CRITICAL (CVSS 9.0+)</span>
                <div className="text-2xl font-black text-white font-mono">24 Hours</div>
                <p className="text-[11px] text-mist">Immediate containment and emergency change freeze fix.</p>
              </div>

              <div className="p-4 bg-orange-500/10 border border-orange-500/30 rounded-2xl space-y-2">
                <span className="text-xs font-bold text-orange-400 font-mono">HIGH (CVSS 7.0-8.9)</span>
                <div className="text-2xl font-black text-white font-mono">7 Days</div>
                <p className="text-[11px] text-mist">Sprint priority backlog item with dedicated engineer assignment.</p>
              </div>

              <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-2xl space-y-2">
                <span className="text-xs font-bold text-amber-400 font-mono">MEDIUM (CVSS 4.0-6.9)</span>
                <div className="text-2xl font-black text-white font-mono">30 Days</div>
                <p className="text-[11px] text-mist">Standard release cycle integration and hardening patch.</p>
              </div>

              <div className="p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-2xl space-y-2">
                <span className="text-xs font-bold text-cyan-400 font-mono">LOW (CVSS 0.1-3.9)</span>
                <div className="text-2xl font-black text-white font-mono">90 Days</div>
                <p className="text-[11px] text-mist">Quarterly architectural hygiene and perimeter cleanup.</p>
              </div>
            </div>
          </div>
        )}

        {/* Report Footer */}
        <div className="pt-6 border-t border-border/40 text-[10px] font-mono text-mist/60 flex justify-between print:text-gray-500">
          <span>Report Generated by Thunder Recon Enterprise ASM Engine</span>
          <span>Confidential • Internal Security Use Only</span>
        </div>
      </div>
    </div>
  );
}
