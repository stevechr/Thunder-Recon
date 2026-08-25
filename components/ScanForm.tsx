"use client";

import { useState } from "react";
import { AuthUser } from "./AuthProviders";

interface Props {
  onScan: (
    domain: string,
    authorized: boolean,
    includePorts: boolean,
    includeBreaches: boolean,
    email: string,
    sessionToken?: string
  ) => void;
  loading: boolean;
  user?: AuthUser | null;
  onUserChange?: (user: AuthUser | null) => void;
  onRequestAuth?: (targetDomain: string) => void;
}

export default function ScanForm({ onScan, loading, user }: Props) {
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(true);
  const [includePorts, setIncludePorts] = useState(true);
  const [includeBreaches, setIncludeBreaches] = useState(true);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    // Scan directly — 100% free with no email verification or login required
    const targetEmail = user?.email || "anonymous@thunder-recon.local";
    onScan(domain.trim(), authorized, includePorts, includeBreaches, targetEmail, user?.session_token);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl space-y-4">
      {/* Scan Input Bar */}
      <div className="flex flex-col sm:flex-row items-center gap-2 bg-panel border border-panelBorder rounded-xl px-4 py-3 focus-within:border-cyan-signal transition-colors shadow-lg">
        <div className="flex items-center gap-2 flex-1 w-full">
          <span className="text-cyan-signal font-mono">$</span>
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Target domain (e.g. example.com)"
            className="flex-1 bg-transparent outline-none text-mist placeholder-mist/50 font-mono text-sm md:text-base"
            style={{ color: "#E8EDF2" }}
          />
        </div>

        <button
          type="submit"
          disabled={loading || !domain.trim()}
          className="w-full sm:w-auto btn-cyber-primary disabled:opacity-30 disabled:cursor-not-allowed whitespace-nowrap shadow-md"
        >
          {loading ? "Scanning…" : "Run Free Scan →"}
        </button>
      </div>

      {/* Options & Authorization */}
      <div className="flex flex-wrap items-center justify-between gap-4 text-xs text-mist pt-0.5">
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="accent-cyan-signal w-4 h-4"
          />
          Free Scan • Authorization Confirmed
        </label>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includePorts}
              onChange={(e) => setIncludePorts(e.target.checked)}
              className="accent-cyan-signal w-4 h-4"
            />
            Port scan
          </label>
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeBreaches}
              onChange={(e) => setIncludeBreaches(e.target.checked)}
              className="accent-cyan-signal w-4 h-4"
            />
            Breach Intelligence
          </label>
        </div>
      </div>
    </form>
  );
}
