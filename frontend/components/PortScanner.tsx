"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface OpenPort {
  port: number;
  service: string;
  state: string;
  banner: string | null;
}

interface PortScanData {
  target: string;
  ip: string;
  open_ports_count: number;
  open_ports: OpenPort[];
}

const PORT_PRESETS: { label: string; ports: number[] }[] = [
  { label: "Standard Top 17", ports: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017] },
  { label: "Web Ports", ports: [80, 81, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000] },
  { label: "Database Ports", ports: [1433, 1521, 3306, 5432, 6379, 9200, 27017, 28017] },
  { label: "Remote Admin & SSH", ports: [22, 23, 3389, 5900, 5901, 8080, 10000] },
  { label: "Mail & Transfer", ports: [20, 21, 25, 69, 110, 143, 465, 587, 993, 995] },
];

export default function PortScanner() {
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [customPorts, setCustomPorts] = useState("");
  const [selectedPreset, setSelectedPreset] = useState<string>("Standard Top 17");
  const [result, setResult] = useState<PortScanData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sessionToken = (() => {
    try {
      const u = localStorage.getItem("thunder_recon_auth_user");
      return u ? JSON.parse(u)?.session_token : null;
    } catch {
      return null;
    }
  })();

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanTarget = target.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!cleanTarget) return;
    if (!authorized) {
      setError("You must confirm you own or are authorized to test this target.");
      return;
    }

    let portsToScan: number[] | null = null;
    if (customPorts.trim()) {
      portsToScan = customPorts
        .split(",")
        .map((p) => parseInt(p.trim()))
        .filter((p) => !isNaN(p) && p > 0 && p <= 65535);
    } else {
      const preset = PORT_PRESETS.find((p) => p.label === selectedPreset);
      if (preset) portsToScan = preset.ports;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/tools/ports`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          target: cleanTarget,
          ports: portsToScan,
          authorized: true,
          session_token: sessionToken,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Port scan failed (HTTP ${res.status})`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to complete port scan.");
    } finally {
      setLoading(false);
    }
  };

  const getPortRiskBadge = (port: number) => {
    if ([21, 23, 445, 3389].includes(port)) {
      return "bg-red-500/20 text-red-400 border-red-500/30";
    }
    if ([3306, 5432, 6379, 27017].includes(port)) {
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    }
    return "bg-cyan-500/20 text-cyan-400 border-cyan-500/30";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-orange-500/10 border border-orange-500/20 text-orange-400">🔌</span>
            Port Scanner & Service Fingerprinter
          </h2>
          <p className="text-sm text-mist mt-1">
            Perform TCP connect banner grabbing and open port discovery across critical infrastructure services.
          </p>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="e.g. 192.168.1.1 or scanme.nmap.org"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full bg-void/60 border border-border/80 focus:border-orange-500/80 rounded-xl px-4 py-3 text-sm text-white placeholder-mist/40 outline-none transition font-mono"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !target.trim() || !authorized}
            className="px-6 py-3 bg-orange-600 hover:bg-orange-500 disabled:opacity-50 text-white font-medium text-sm rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-orange-600/20 cursor-pointer disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                Scanning TCP Ports...
              </>
            ) : (
              <>
                <span>⚡</span> Scan Target Ports
              </>
            )}
          </button>
        </div>

        {/* Port Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-xs text-mist">Preset:</span>
          {PORT_PRESETS.map((p) => (
            <button
              type="button"
              key={p.label}
              onClick={() => {
                setSelectedPreset(p.label);
                setCustomPorts("");
              }}
              className={`text-xs px-2.5 py-1 rounded-lg border transition ${
                selectedPreset === p.label && !customPorts
                  ? "bg-orange-500/20 text-orange-400 border-orange-500/40 font-semibold"
                  : "bg-void/40 text-mist border-border hover:text-white"
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Custom Port Range */}
        <div className="flex items-center gap-2 pt-1">
          <span className="text-xs text-mist">Custom Ports:</span>
          <input
            type="text"
            placeholder="e.g. 80, 443, 8080, 9000 (optional)"
            value={customPorts}
            onChange={(e) => setCustomPorts(e.target.value)}
            className="bg-void/60 border border-border rounded-lg px-3 py-1.5 text-xs text-white placeholder-mist/40 outline-none w-64 font-mono"
          />
        </div>

        {/* Authorization checkbox */}
        <label className="flex items-start gap-2.5 cursor-pointer text-xs text-mist select-none pt-2 border-t border-border/40">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-0.5 rounded border-border bg-void/80 text-orange-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
          />
          <span>
            I confirm that I own or have explicit legal authorization to scan TCP ports on this target.
          </span>
        </label>
      </form>

      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm flex items-center gap-3">
          <span>⚠️</span> {error}
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* Summary Card */}
          <div className="p-5 bg-surface/80 border border-border rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <span className="text-xs uppercase text-mist font-semibold">Target Resolved</span>
              <div className="text-xl font-bold text-white font-mono flex items-center gap-2 mt-0.5">
                <span>{result.target}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-void border border-border text-cyan-400">
                  {result.ip}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="p-3 bg-void/60 border border-border rounded-xl text-center min-w-[140px]">
                <div className="text-[10px] text-mist uppercase">Open Ports</div>
                <div className={`text-2xl font-bold font-mono ${result.open_ports_count > 0 ? "text-emerald-400" : "text-mist"}`}>
                  {result.open_ports_count}
                </div>
              </div>
            </div>
          </div>

          {/* Open Ports Table */}
          {result.open_ports.length > 0 ? (
            <div className="bg-surface/80 border border-border rounded-2xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-void/70 border-b border-border text-mist uppercase text-[10px] tracking-wider font-sans">
                    <tr>
                      <th className="py-3 px-4">Port</th>
                      <th className="py-3 px-4">Service</th>
                      <th className="py-3 px-4">State</th>
                      <th className="py-3 px-4">Banner / Response</th>
                      <th className="py-3 px-4 text-right">Risk Tag</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40">
                    {result.open_ports.map((p, idx) => (
                      <tr key={idx} className="hover:bg-void/30 transition">
                        <td className="py-3 px-4 text-orange-400 font-bold">{p.port}</td>
                        <td className="py-3 px-4 text-white font-semibold font-sans">{p.service}</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                            OPEN
                          </span>
                        </td>
                        <td className="py-3 px-4 text-mist truncate max-w-xs">
                          {p.banner ? p.banner : <span className="text-mist/40 italic">No banner returned</span>}
                        </td>
                        <td className="py-3 px-4 text-right font-sans">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getPortRiskBadge(p.port)}`}>
                            {[21, 23, 445, 3389].includes(p.port) ? "HIGH RISK" : [3306, 5432, 6379, 27017].includes(p.port) ? "DB EXPOSURE" : "STANDARD"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center bg-surface/40 border border-border/40 rounded-2xl text-mist text-xs">
              No open TCP ports detected among the scanned list. Target might be firewalled or filtering connection probes.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
