"use client";

import { useState } from "react";

interface Props {
  onScan: (domain: string, authorized: boolean, includePorts: boolean, includeBreaches: boolean) => void;
  loading: boolean;
}

export default function ScanForm({ onScan, loading }: Props) {
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [includePorts, setIncludePorts] = useState(true);
  const [includeBreaches, setIncludeBreaches] = useState(true);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim() || !authorized) return;
    onScan(domain.trim(), authorized, includePorts, includeBreaches);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl">
      <div className="flex items-center gap-2 bg-panel border border-panelBorder rounded-lg px-4 py-3 focus-within:border-cyan-signal transition-colors">
        <span className="text-cyan-signal">$</span>
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          className="flex-1 bg-transparent outline-none text-mist placeholder-mist/50 font-mono text-sm md:text-base"
          style={{ color: "#E8EDF2" }}
        />
        <button
          type="submit"
          disabled={loading || !domain.trim() || !authorized}
          className="px-5 py-2 rounded-md bg-cyan-signal text-void font-display font-medium text-sm disabled:opacity-30 disabled:cursor-not-allowed hover:brightness-110 transition"
        >
          {loading ? "Scanning…" : "Run scan"}
        </button>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-4 mt-4 text-xs text-mist">
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="accent-cyan-signal w-4 h-4"
          />
          I own this domain or am authorized to test it
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
            Data Breach Intelligence
          </label>
        </div>
      </div>
    </form>
  );
}
