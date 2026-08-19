"use client";

import { useState } from "react";
import ScanForm from "@/components/ScanForm";
import ResultsDashboard from "@/components/ResultsDashboard";
import BreachChecker from "@/components/BreachChecker";
import { runScan, ScanResult } from "@/lib/api";

export default function Home() {
  const [activeMode, setActiveMode] = useState<"domain" | "pwned">("domain");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (
    domain: string,
    authorized: boolean,
    includePorts: boolean,
    includeBreaches: boolean
  ) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await runScan(domain, authorized, includePorts, includeBreaches);
      setResult(data);
    } catch (e: any) {
      setError(e.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen scan-grid flex flex-col items-center px-6 py-12">
      {/* Hero */}
      <div className="relative flex flex-col items-center text-center mb-8">
        <div className="relative w-24 h-24 mb-6">
          <div className="absolute inset-0 rounded-full border border-panelBorder" />
          <div className="absolute inset-3 rounded-full border border-panelBorder" />
          <div className="absolute inset-0 animate-sweep origin-center">
            <div
              className="absolute top-1/2 left-1/2 w-1/2 h-[1px]"
              style={{
                background: "linear-gradient(90deg, #4FD1C5, transparent)",
                transformOrigin: "0% 50%",
              }}
            />
          </div>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-signal animate-blink shadow-lg shadow-cyan-signal/50" />
          </div>
        </div>
        <h1 className="font-display text-4xl md:text-5xl font-extrabold tracking-tight" style={{ color: "#E8EDF2" }}>
          Thunder Recon
        </h1>
        <p className="text-mist mt-3 max-w-lg text-sm md:text-base leading-relaxed">
          Am I Pwned breach engine & deep security reconnaissance — check domains, emails, and target assets for data breaches, leaks, exposure, and vulnerabilities.
        </p>

        {/* Mode Selector */}
        <div className="flex bg-panel border border-panelBorder p-1.5 rounded-xl mt-6 gap-2">
          <button
            onClick={() => setActiveMode("domain")}
            className={`px-5 py-2 rounded-lg font-display text-xs md:text-sm font-semibold transition ${
              activeMode === "domain"
                ? "bg-cyan-signal text-void shadow-md"
                : "text-mist hover:text-white"
            }`}
          >
            🛡️ Domain Recon & Breaches
          </button>
          <button
            onClick={() => setActiveMode("pwned")}
            className={`px-5 py-2 rounded-lg font-display text-xs md:text-sm font-semibold transition ${
              activeMode === "pwned"
                ? "bg-cyan-signal text-void shadow-md"
                : "text-mist hover:text-white"
            }`}
          >
            ⚡ Am I Pwned? Search
          </button>
        </div>
      </div>

      {activeMode === "domain" ? (
        <div className="w-full flex flex-col items-center">
          <ScanForm onScan={handleScan} loading={loading} />

          {error && (
            <div className="mt-6 text-crimson-risk text-sm border border-crimson-risk/30 bg-crimson-risk/10 rounded-md px-4 py-2">
              {error}
            </div>
          )}

          {loading && (
            <div className="mt-10 font-mono text-sm text-cyan-signal animate-blink">
              resolving target & querying breach intelligence datasets...
            </div>
          )}

          {result && (
            <div className="mt-10 w-full flex justify-center">
              <ResultsDashboard result={result} />
            </div>
          )}
        </div>
      ) : (
        <div className="w-full flex justify-center mt-2">
          <BreachChecker />
        </div>
      )}
    </main>
  );
}
