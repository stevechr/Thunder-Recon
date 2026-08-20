"use client";

import { useState } from "react";
import { AuthUser, ProviderButtonsBar, ProviderType } from "./AuthProviders";

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
  user: AuthUser | null;
  onUserChange: (user: AuthUser | null) => void;
  onRequestAuth: (targetDomain: string, provider?: ProviderType) => void;
}

export default function ScanForm({ onScan, loading, user, onUserChange, onRequestAuth }: Props) {
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [includePorts, setIncludePorts] = useState(true);
  const [includeBreaches, setIncludeBreaches] = useState(true);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim() || !authorized) return;

    if (!user) {
      onRequestAuth(domain.trim(), "google");
      return;
    }

    onScan(domain.trim(), authorized, includePorts, includeBreaches, user.email, user.session_token);
  };

  const handleSelectProvider = (provider: ProviderType) => {
    onRequestAuth(domain.trim() || "target domain", provider);
  };

  const handleSignOut = () => {
    try {
      localStorage.removeItem("thunder_recon_auth_user");
      localStorage.removeItem("thunder_recon_google_user");
    } catch (e) {}
    onUserChange(null);
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
          disabled={loading || !domain.trim() || !authorized}
          className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-cyan-signal text-void font-display font-semibold text-sm disabled:opacity-30 disabled:cursor-not-allowed hover:brightness-110 transition whitespace-nowrap shadow-md"
        >
          {loading ? "Scanning…" : "Run scan"}
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

      {/* Provider Icons & Account Verification under scan options */}
      <div className="pt-1">
        <ProviderButtonsBar
          user={user}
          onSelectProvider={handleSelectProvider}
          onSignOut={handleSignOut}
        />
      </div>
    </form>
  );
}
