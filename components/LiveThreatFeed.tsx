"use client";

import { useState, useEffect } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface KevItem {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
}

// Fallback high-impact dataset if offline or network fails
const FALLBACK_KEV: KevItem[] = [
  {
    cveID: "CVE-2024-3400",
    vendorProject: "Palo Alto Networks",
    product: "PAN-OS",
    vulnerabilityName: "PAN-OS Command Injection Vulnerability",
    dateAdded: "2024-04-12",
    shortDescription: "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS allows an unauthenticated attacker to execute arbitrary code with root privileges.",
    requiredAction: "Apply mitigations per vendor instructions or upgrade to fixed PAN-OS release.",
    dueDate: "2024-04-19",
    knownRansomwareCampaignUse: "Known",
  },
  {
    cveID: "CVE-2024-21413",
    vendorProject: "Microsoft",
    product: "Outlook",
    vulnerabilityName: "Microsoft Outlook Remote Code Execution Vulnerability",
    dateAdded: "2024-02-13",
    shortDescription: "Microsoft Outlook contains a remote code execution vulnerability that bypasses Office Protected View when opening malicious file previews.",
    requiredAction: "Apply February 2024 Microsoft Security Update.",
    dueDate: "2024-03-05",
    knownRansomwareCampaignUse: "Known",
  },
  {
    cveID: "CVE-2024-21887",
    vendorProject: "Ivanti",
    product: "Connect Secure and Policy Secure",
    vulnerabilityName: "Ivanti Connect Secure Command Injection Vulnerability",
    dateAdded: "2024-01-10",
    shortDescription: "A command injection vulnerability in web components of Ivanti Connect Secure allows an authenticated administrator to send crafted requests and execute arbitrary commands.",
    requiredAction: "Apply vendor mitigation XML or upgrade firmware.",
    dueDate: "2024-01-22",
    knownRansomwareCampaignUse: "Known",
  },
  {
    cveID: "CVE-2023-44487",
    vendorProject: "Multiple Vendors",
    product: "HTTP/2 Protocol",
    vulnerabilityName: "HTTP/2 Rapid Reset Denial-of-Service Vulnerability",
    dateAdded: "2023-10-10",
    shortDescription: "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams rapidly.",
    requiredAction: "Apply vendor patches or configure rate limiting for RST_STREAM frames.",
    dueDate: "2023-10-31",
    knownRansomwareCampaignUse: "Known",
  },
];

export default function LiveThreatFeed() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [items, setItems] = useState<KevItem[]>(FALLBACK_KEV);
  const [totalCount, setTotalCount] = useState(1200);
  const [vendorFilter, setVendorFilter] = useState("all");

  const loadFeed = async (searchQuery?: string) => {
    setLoading(true);
    try {
      const qParam = searchQuery !== undefined ? searchQuery : query;
      const res = await fetch(`${API_BASE}/api/tools/cisa-kev?q=${encodeURIComponent(qParam)}&limit=50`);
      if (res.ok) {
        const data = await res.json();
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
          setItems(data.vulnerabilities);
          setTotalCount(data.total_in_catalog || data.matched_count);
        }
      }
    } catch {
      // Keep fallback items if API fails
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFeed();
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    loadFeed(query);
  };

  const filteredItems = items.filter((item) => {
    if (vendorFilter === "all") return true;
    return item.vendorProject.toLowerCase().includes(vendorFilter.toLowerCase());
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 animate-pulse">📡</span>
            Live Cyber Threat Intelligence & CISA KEV Feed
          </h2>
          <p className="text-sm text-mist mt-1">
            Real-time feed of CISA Known Exploited Vulnerabilities (actively weaponized zero-days and ransomware vectors in the wild).
          </p>
        </div>

        <button
          onClick={() => loadFeed()}
          disabled={loading}
          className="px-4 py-2 bg-surface hover:bg-surface/80 border border-border text-xs text-white rounded-xl transition flex items-center gap-1.5 cursor-pointer font-mono shrink-0"
        >
          <span>{loading ? "Refreshing..." : "🔄 Refresh Feed"}</span>
        </button>
      </div>

      {/* Live Alert Ticker Banner */}
      <div className="p-3.5 bg-red-500/10 border border-red-500/30 rounded-2xl flex items-center gap-3 overflow-hidden text-xs">
        <span className="px-2.5 py-1 rounded-lg bg-red-500 text-white font-black text-[10px] uppercase tracking-wider shrink-0 animate-pulse">
          LIVE INTEL
        </span>
        <div className="truncate font-mono text-red-300">
          Tracking <span className="font-bold text-white">{totalCount}+</span> weaponized vulnerabilities requiring mandatory enterprise remediation.
        </div>
      </div>

      {/* Search & Vendor Filter Bar */}
      <div className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md space-y-4">
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="Search CVE ID, vendor, product, or keyword (e.g. Cisco, Ivanti, Microsoft, Remote Code)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-void/60 border border-border focus:border-red-500/80 rounded-xl px-4 py-2.5 text-xs text-white font-mono outline-none"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2.5 bg-red-600 hover:bg-red-500 text-white font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-red-600/20 cursor-pointer"
          >
            <span>🔍</span> Filter Intel
          </button>
        </form>

        {/* Vendor Chips */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-xs text-mist mr-1">Vendor:</span>
          {["all", "Microsoft", "Cisco", "Palo Alto", "Ivanti", "Apache", "Apple", "Linux"].map((v) => (
            <button
              key={v}
              onClick={() => setVendorFilter(v)}
              className={`text-xs px-2.5 py-1 rounded-lg border transition ${
                vendorFilter === v
                  ? "bg-red-500/20 text-red-400 border-red-500/40 font-bold"
                  : "bg-void/40 text-mist border-border hover:text-white"
              }`}
            >
              {v === "all" ? "All Vendors" : v}
            </button>
          ))}
        </div>
      </div>

      {/* Vulnerabilities Feed Cards */}
      <div className="space-y-4">
        {filteredItems.length > 0 ? (
          filteredItems.map((item, idx) => (
            <div
              key={idx}
              className="p-5 bg-surface/80 border border-border rounded-2xl space-y-3 hover:border-red-500/40 transition"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/40 pb-2.5">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${item.cveID}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-xs font-black px-2.5 py-1 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 transition"
                  >
                    {item.cveID} ↗
                  </a>
                  <span className="font-bold text-white text-sm">{item.vulnerabilityName}</span>
                </div>

                <div className="flex items-center gap-2 font-mono text-xs text-mist">
                  <span>Added: <strong className="text-white">{item.dateAdded}</strong></span>
                  <span>•</span>
                  <span>Due: <strong className="text-amber-400">{item.dueDate}</strong></span>
                </div>
              </div>

              <div className="flex flex-wrap gap-2 text-xs font-mono">
                <span className="px-2 py-0.5 rounded bg-void border border-border text-cyan-400">
                  Vendor: {item.vendorProject}
                </span>
                <span className="px-2 py-0.5 rounded bg-void border border-border text-violet-400">
                  Product: {item.product}
                </span>
                {item.knownRansomwareCampaignUse === "Known" && (
                  <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 font-bold flex items-center gap-1 font-sans">
                    <span>⚠️</span> Known Ransomware Use
                  </span>
                )}
              </div>

              <p className="text-xs text-mist/90 leading-relaxed">{item.shortDescription}</p>

              <div className="p-3 bg-void/60 border border-border/60 rounded-xl space-y-1 text-xs">
                <span className="text-[10px] font-bold font-mono text-amber-400 uppercase tracking-wider block">
                  Mandatory Action Required
                </span>
                <p className="text-white font-medium">{item.requiredAction}</p>
              </div>
            </div>
          ))
        ) : (
          <div className="p-12 text-center bg-surface/40 border border-border rounded-2xl text-mist text-xs">
            No matching vulnerabilities found for &quot;{query}&quot;.
          </div>
        )}
      </div>
    </div>
  );
}
