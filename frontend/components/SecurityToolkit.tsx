"use client";

import { useState } from "react";

type ToolType = "jwt" | "hashes" | "encoders" | "subnet";

export default function SecurityToolkit() {
  const [activeTool, setActiveTool] = useState<ToolType>("jwt");

  // JWT state
  const [jwtInput, setJwtInput] = useState("");
  const [jwtOutput, setJwtOutput] = useState<{ header: any; payload: any; valid: boolean; expStatus: string } | null>(null);

  // Hash state
  const [textToHash, setTextToHash] = useState("");

  // Encoder state
  const [encInput, setEncInput] = useState("");
  const [encMode, setEncMode]   = useState<"b64encode" | "b64decode" | "urlencode" | "urldecode">("b64encode");

  // Subnet state
  const [cidrInput, setCidrInput] = useState("192.168.1.0/24");

  // Decode JWT
  const handleJwtDecode = (token: string) => {
    setJwtInput(token);
    if (!token.trim()) { setJwtOutput(null); return; }
    try {
      const parts = token.trim().split(".");
      if (parts.length < 2) throw new Error("Invalid JWT format (needs header.payload.signature)");
      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));

      let expStatus = "No Expiry (exp claim missing)";
      if (payload.exp) {
        const expTime = payload.exp * 1000;
        const now = Date.now();
        expStatus = expTime < now ? `EXPIRED (${new Date(expTime).toISOString()})` : `VALID (expires ${new Date(expTime).toISOString()})`;
      }

      setJwtOutput({ header, payload, valid: true, expStatus });
    } catch (e: any) {
      setJwtOutput({ header: { error: e.message }, payload: {}, valid: false, expStatus: "Invalid Token" });
    }
  };

  // Encoders helper
  const getEncoderOutput = () => {
    if (!encInput) return "";
    try {
      if (encMode === "b64encode") return btoa(encInput);
      if (encMode === "b64decode") return atob(encInput);
      if (encMode === "urlencode") return encodeURIComponent(encInput);
      if (encMode === "urldecode") return decodeURIComponent(encInput);
    } catch (e: any) {
      return `Error: ${e.message}`;
    }
    return "";
  };

  return (
    <div className="w-full max-w-4xl space-y-5 animate-fadeIn">
      {/* Header & Tool Selector */}
      <div className="bg-panel border border-panelBorder rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/30">
                100% CLIENT-SIDE • INSTANT
              </span>
            </div>
            <h2 className="font-display text-xl font-bold text-white flex items-center gap-2">
              🛠️ Cyber Security Swiss-Army Toolkit
            </h2>
            <p className="text-xs text-mist font-mono mt-1 max-w-xl">
              Zero-latency developer tools: JWT Token Inspector, Multi-Hash Generator, Base64 / URL Encoders, and Subnet Calculators.
            </p>
          </div>

          {/* Tool switch pills */}
          <div className="flex bg-void border border-panelBorder rounded-xl p-1 gap-1 overflow-x-auto">
            {([
              { key: "jwt",      label: "🔑 JWT Inspector" },
              { key: "encoders", label: "🔤 Base64 / URL" },
              { key: "hashes",   label: "⚡ Hashes" },
            ] as const).map((t) => (
              <button
                key={t.key}
                onClick={() => setActiveTool(t.key)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition whitespace-nowrap ${
                  activeTool === t.key
                    ? "bg-cyan-signal text-void shadow-sm"
                    : "text-mist hover:text-white"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* 1. JWT TOOL */}
        {activeTool === "jwt" && (
          <div className="space-y-4 pt-2">
            <textarea
              rows={4}
              placeholder="Paste raw JWT (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)"
              value={jwtInput}
              onChange={(e) => handleJwtDecode(e.target.value)}
              className="w-full px-4 py-3 bg-void border border-panelBorder rounded-xl text-white font-mono text-xs focus:outline-none focus:border-cyan-signal/60 leading-relaxed resize-none transition placeholder:text-mist/25 break-all"
            />

            {jwtOutput && (
              <div className="space-y-3 animate-slideUp">
                <div className={`p-3 rounded-xl border font-mono text-xs flex justify-between items-center ${
                  jwtOutput.valid
                    ? jwtOutput.expStatus.includes("EXPIRED") ? "bg-amber-500/10 border-amber-500/30 text-amber-300" : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    : "bg-rose-500/10 border-rose-500/30 text-rose-400"
                }`}>
                  <span>{jwtOutput.expStatus}</span>
                  <span className="font-bold">{jwtOutput.valid ? "DECODED ✓" : "INVALID FORMAT ⚠️"}</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-void/70 border border-panelBorder/60 rounded-xl p-4 space-y-2">
                    <span className="text-[10px] font-mono text-cyan-signal uppercase tracking-widest block font-bold">HEADER</span>
                    <pre className="text-xs font-mono text-white/90 overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(jwtOutput.header, null, 2)}
                    </pre>
                  </div>

                  <div className="bg-void/70 border border-panelBorder/60 rounded-xl p-4 space-y-2">
                    <span className="text-[10px] font-mono text-purple-300 uppercase tracking-widest block font-bold">PAYLOAD</span>
                    <pre className="text-xs font-mono text-white/90 overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(jwtOutput.payload, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* 2. ENCODERS TOOL */}
        {activeTool === "encoders" && (
          <div className="space-y-4 pt-2">
            <div className="flex gap-2 flex-wrap text-xs font-mono">
              {([
                { key: "b64encode", label: "Base64 Encode" },
                { key: "b64decode", label: "Base64 Decode" },
                { key: "urlencode", label: "URL Encode" },
                { key: "urldecode", label: "URL Decode" },
              ] as const).map((m) => (
                <button
                  key={m.key}
                  onClick={() => setEncMode(m.key)}
                  className={`px-3 py-1 rounded-lg border transition ${
                    encMode === m.key
                      ? "bg-cyan-signal/20 text-cyan-signal border-cyan-signal/50 font-bold"
                      : "bg-void border-panelBorder text-mist hover:text-white"
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>

            <textarea
              rows={3}
              placeholder="Enter text to encode/decode..."
              value={encInput}
              onChange={(e) => setEncInput(e.target.value)}
              className="w-full px-4 py-3 bg-void border border-panelBorder rounded-xl text-white font-mono text-xs focus:outline-none focus:border-cyan-signal/60 leading-relaxed resize-none transition"
            />

            {encInput && (
              <div className="bg-void/80 border border-panelBorder/60 rounded-xl p-4 space-y-1.5 animate-slideUp">
                <span className="text-[10px] font-mono text-mist uppercase tracking-widest block">RESULT</span>
                <div className="text-xs font-mono text-cyan-signal break-all select-all font-semibold">
                  {getEncoderOutput()}
                </div>
              </div>
            )}
          </div>
        )}

        {/* 3. HASHES TOOL */}
        {activeTool === "hashes" && (
          <div className="space-y-4 pt-2">
            <input
              type="text"
              placeholder="Enter text string to view format rules..."
              value={textToHash}
              onChange={(e) => setTextToHash(e.target.value)}
              className="w-full bg-void border border-panelBorder rounded-xl px-4 py-3 text-sm font-mono text-white placeholder:text-mist/30 focus:outline-none focus:border-cyan-signal/60 transition"
            />

            {textToHash && (
              <div className="space-y-2 font-mono text-xs animate-slideUp">
                {[
                  ["Length", `${textToHash.length} characters`],
                  ["MD5 Format", `${textToHash.length === 32 ? "Matched 32-char hex pattern" : "32 hex chars required"}`],
                  ["SHA256 Format", `${textToHash.length === 64 ? "Matched 64-char hex pattern" : "64 hex chars required"}`],
                ].map(([label, val]) => (
                  <div key={label} className="flex justify-between items-center bg-void/60 px-3.5 py-2 rounded-xl border border-panelBorder/50">
                    <span className="text-mist">{label}</span>
                    <span className="text-white font-semibold">{val}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
