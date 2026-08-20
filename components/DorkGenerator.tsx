"use client";

import { useState } from "react";

interface Dork {
  title: string;
  category: "Exposed Files" | "Admin & Auth" | "API Keys & Secrets" | "Database & Backups" | "IoT & Infra";
  engine: "Google" | "Shodan" | "GitHub" | "Censys";
  queryTemplate: (target: string) => string;
  description: string;
}

const DORKS: Dork[] = [
  // Google: Exposed Files
  {
    title: "Exposed Environment & Config Files",
    category: "Exposed Files",
    engine: "Google",
    queryTemplate: (t) => `site:${t} ext:env OR ext:yml OR ext:yaml OR ext:ini OR ext:conf "DB_PASSWORD"`,
    description: "Searches for indexed .env or configuration files containing database credentials.",
  },
  {
    title: "Exposed Log Files",
    category: "Exposed Files",
    engine: "Google",
    queryTemplate: (t) => `site:${t} ext:log "error" OR "password" OR "exception"`,
    description: "Finds application and server logs that may leak system paths or sensitive user data.",
  },
  {
    title: "Public PDF & Excel Documents",
    category: "Exposed Files",
    engine: "Google",
    queryTemplate: (t) => `site:${t} filetype:pdf OR filetype:xlsx OR filetype:docx "confidential" OR "internal use"`,
    description: "Uncovers indexed documents tagged with confidential or internal distribution notices.",
  },
  {
    title: "Directory Listing / Index of /",
    category: "Exposed Files",
    engine: "Google",
    queryTemplate: (t) => `site:${t} intitle:"index of /" OR intitle:"Index of /"`,
    description: "Identifies web servers with enabled directory browsing revealing file structures.",
  },

  // Google: Admin & Auth
  {
    title: "Exposed Admin & Dashboard Portals",
    category: "Admin & Auth",
    engine: "Google",
    queryTemplate: (t) => `site:${t} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:cpanel`,
    description: "Finds hidden or forgotten administrative login panels on subdomains.",
  },
  {
    title: "Swagger & OpenAPI Documentation",
    category: "Admin & Auth",
    engine: "Google",
    queryTemplate: (t) => `site:${t} inurl:swagger OR inurl:api-docs OR inurl:"/v2/api-docs" OR inurl:graphql`,
    description: "Discovers interactive API documentation that might expose unauthenticated endpoints.",
  },

  // Google: Database & Backups
  {
    title: "Database Dumps & SQL Files",
    category: "Database & Backups",
    engine: "Google",
    queryTemplate: (t) => `site:${t} ext:sql OR ext:dump OR ext:tar OR ext:zip "backup"`,
    description: "Locates public database export dumps or tarball backups on the webroot.",
  },
  {
    title: "Git Repository Exposure",
    category: "Database & Backups",
    engine: "Google",
    queryTemplate: (t) => `site:${t} inurl:/.git/ OR inurl:/.gitignore OR inurl:/HEAD`,
    description: "Detects web servers inadvertently serving the .git folder containing full source code history.",
  },

  // GitHub: API Keys & Secrets
  {
    title: "Leaked AWS Keys in Public Code",
    category: "API Keys & Secrets",
    engine: "GitHub",
    queryTemplate: (t) => `"${t}" "AKIA" OR "aws_secret_access_key"`,
    description: "Searches GitHub public repositories for hardcoded AWS IAM access keys.",
  },
  {
    title: "Leaked JWT Secrets or Private Keys",
    category: "API Keys & Secrets",
    engine: "GitHub",
    queryTemplate: (t) => `"${t}" "-----BEGIN RSA PRIVATE KEY-----" OR "JWT_SECRET"`,
    description: "Finds exposed cryptographic private keys or JWT signing tokens committed to GitHub.",
  },
  {
    title: "Stripe & Payment Gateway Keys",
    category: "API Keys & Secrets",
    engine: "GitHub",
    queryTemplate: (t) => `"${t}" "sk_live_" OR "pk_live_"`,
    description: "Scans for live Stripe API secret keys in public commits.",
  },

  // Shodan: IoT & Infrastructure
  {
    title: "Open Remote Desktop & VNC Services",
    category: "IoT & Infra",
    engine: "Shodan",
    queryTemplate: (t) => `hostname:"${t}" port:3389,5900`,
    description: "Locates exposed RDP or VNC graphical remote access ports indexed on Shodan.",
  },
  {
    title: "Exposed Redis / MongoDB / Elasticsearch",
    category: "IoT & Infra",
    engine: "Shodan",
    queryTemplate: (t) => `hostname:"${t}" port:6379,27017,9200`,
    description: "Finds unauthenticated NoSQL or search databases reachable over the public internet.",
  },
];

export default function DorkGenerator() {
  const [target, setTarget] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [selectedEngine, setSelectedEngine] = useState<string>("all");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const cleanTarget = target.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "example.com";

  const filteredDorks = DORKS.filter((d) => {
    if (selectedCategory !== "all" && d.category !== selectedCategory) return false;
    if (selectedEngine !== "all" && d.engine !== selectedEngine) return false;
    return true;
  });

  const copyQuery = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getSearchUrl = (engine: Dork["engine"], query: string) => {
    if (engine === "Google") return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
    if (engine === "GitHub") return `https://github.com/search?q=${encodeURIComponent(query)}&type=code`;
    if (engine === "Shodan") return `https://www.shodan.io/search?query=${encodeURIComponent(query)}`;
    return `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(query)}`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">🎯</span>
            OSINT Dork & Search Query Generator
          </h2>
          <p className="text-sm text-mist mt-1">
            Generate crafted Google Dorks, Shodan queries, and GitHub secret-hunting expressions tailored to your target.
          </p>
        </div>
      </div>

      {/* Target Input */}
      <div className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md">
        <label className="text-xs font-semibold text-mist uppercase tracking-wider block mb-2">Target Domain / Brand</label>
        <input
          type="text"
          placeholder="e.g. uber.com or paypal.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="w-full bg-void/60 border border-border/80 focus:border-amber-500/80 rounded-xl px-4 py-3 text-sm text-white placeholder-mist/40 outline-none transition font-mono"
        />
      </div>

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-surface/60 border border-border/60 rounded-xl">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-mist">Engine:</span>
          {["all", "Google", "GitHub", "Shodan"].map((eng) => (
            <button
              key={eng}
              onClick={() => setSelectedEngine(eng)}
              className={`text-xs px-2.5 py-1 rounded-lg border transition ${
                selectedEngine === eng
                  ? "bg-amber-500/20 text-amber-400 border-amber-500/40 font-bold"
                  : "bg-void/40 text-mist border-border hover:text-white"
              }`}
            >
              {eng === "all" ? "All Engines" : eng}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-void border border-border rounded-lg px-2.5 py-1 text-xs text-mist outline-none"
          >
            <option value="all">All Categories</option>
            <option value="Exposed Files">Exposed Files</option>
            <option value="Admin & Auth">Admin & Auth</option>
            <option value="API Keys & Secrets">API Keys & Secrets</option>
            <option value="Database & Backups">Database & Backups</option>
            <option value="IoT & Infra">IoT & Infra</option>
          </select>
        </div>
      </div>

      {/* Dork Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredDorks.map((d, i) => {
          const generated = d.queryTemplate(cleanTarget);
          const searchUrl = getSearchUrl(d.engine, generated);

          return (
            <div key={i} className="bg-surface/80 border border-border rounded-2xl p-5 space-y-3 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-bold text-white text-sm">{d.title}</span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-bold border ${
                      d.engine === "Google"
                        ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
                        : d.engine === "GitHub"
                        ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                        : "bg-red-500/10 text-red-400 border-red-500/20"
                    }`}
                  >
                    {d.engine}
                  </span>
                </div>
                <p className="text-xs text-mist">{d.description}</p>
              </div>

              {/* Code snippet */}
              <div className="p-3 bg-void/80 border border-border rounded-xl font-mono text-xs text-amber-300 break-all select-all">
                {generated}
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-1 gap-2">
                <button
                  type="button"
                  onClick={() => copyQuery(generated, i)}
                  className="text-xs px-3 py-1.5 rounded-lg bg-void hover:bg-void/80 border border-border text-mist hover:text-white transition flex items-center gap-1.5 cursor-pointer"
                >
                  <span>{copiedIndex === i ? "✓ Copied" : "📋 Copy Query"}</span>
                </button>

                <a
                  href={searchUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs px-3 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/30 text-amber-400 font-medium transition flex items-center gap-1"
                >
                  <span>Search on {d.engine}</span>
                  <span>↗</span>
                </a>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
