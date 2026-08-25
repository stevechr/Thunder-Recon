"use client";

import React, { useState, useEffect, useRef } from "react";

// Real-World Global Telemetry Sensor Hubs
const GLOBAL_SENSOR_HUBS = [
  { id: "us-west", name: "San Francisco (US-West)", lat: 37.7749, lng: -122.4194, flag: "🇺🇸", color: "#00f0ff" },
  { id: "us-east", name: "New York (US-East)", lat: 40.7128, lng: -74.0060, flag: "🇺🇸", color: "#00f0ff" },
  { id: "uk-lon", name: "London (EU-West)", lat: 51.5074, lng: -0.1278, flag: "🇬🇧", color: "#3b82f6" },
  { id: "de-fra", name: "Frankfurt (EU-Central)", lat: 50.1109, lng: 8.6821, flag: "🇩🇪", color: "#6366f1" },
  { id: "jp-tyo", name: "Tokyo (AP-North)", lat: 35.6762, lng: 139.6503, flag: "🇯🇵", color: "#10b981" },
  { id: "sg-sin", name: "Singapore (AP-South)", lat: 1.3521, lng: 103.8198, flag: "🇸🇬", color: "#f59e0b" },
  { id: "au-syd", name: "Sydney (OC-East)", lat: -33.8688, lng: 151.2093, flag: "🇦🇺", color: "#8b5cf6" },
  { id: "br-sao", name: "São Paulo (SA-East)", lat: -23.5505, lng: -46.6333, flag: "🇧🇷", color: "#ec4899" },
  { id: "in-bom", name: "Mumbai (AP-West)", lat: 19.0760, lng: 72.8777, flag: "🇮🇳", color: "#14b8a6" },
  { id: "za-jnb", name: "Johannesburg (AF-South)", lat: -26.2041, lng: 28.0473, flag: "🇿🇦", color: "#eab308" }
];

// Attack types for visual telemetry
const ATTACK_TYPES = [
  { name: "DDoS Amplification", color: "#ff2a55", port: 53, threat: "CRITICAL" },
  { name: "SQL Injection", color: "#f97316", port: 443, threat: "HIGH" },
  { name: "SSH Brute-Force", color: "#00f0ff", port: 22, threat: "ELEVATED" },
  { name: "RCE Exploit", color: "#d946ef", port: 8080, threat: "HIGH" },
  { name: "Ransomware C2", color: "#ef4444", port: 4444, threat: "CRITICAL" },
  { name: "Port Scan", color: "#a855f7", port: 0, threat: "LOW" },
];

interface LiveAttackMapProps {
  isFullscreenBg?: boolean;
}

export default function LiveAttackMap({ isFullscreenBg = false }: LiveAttackMapProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Simulation State
  const [activeVectorsCount, setActiveVectorsCount] = useState(0);
  const [feed, setFeed] = useState<any[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [simSpeed, setSimSpeed] = useState(400); // ms per attack
  const [stats, setStats] = useState({ bandwidth: 0, packets: 0 });
  const [showGrid, setShowGrid] = useState(true);

  // Refs for animation loop
  const arcsRef = useRef<any[]>([]);
  const impactsRef = useRef<any[]>([]);
  const animIdRef = useRef<number | null>(null);
  const isPausedRef = useRef(isPaused);
  const activeFilterRef = useRef(activeFilter);
  const showGridRef = useRef(showGrid);

  useEffect(() => { isPausedRef.current = isPaused; }, [isPaused]);
  useEffect(() => { activeFilterRef.current = activeFilter; }, [activeFilter]);
  useEffect(() => { showGridRef.current = showGrid; }, [showGrid]);

  // DEFCON calculation
  const getDefconLevel = () => {
    if (activeVectorsCount > 10) return { level: 1, label: "MAXIMUM READINESS", color: "text-rose-500" };
    if (activeVectorsCount > 5) return { level: 2, label: "HIGH ALERT", color: "text-orange-500" };
    if (activeVectorsCount > 2) return { level: 3, label: "ELEVATED RISK", color: "text-yellow-400" };
    return { level: 4, label: "NORMAL SURVEILLANCE", color: "text-emerald-400" };
  };

  // Convert lat/lng to 2D canvas pixel coordinates
  const projectCoords = (lat: number, lng: number, width: number, height: number) => {
    const x = ((lng + 180) / 360) * width;
    const latRad = (lat * Math.PI) / 180;
    const mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
    const y = height / 2 - (mercN / (2 * Math.PI)) * height * 1.05;
    return { x, y: Math.max(20, Math.min(height - 20, y)) };
  };

  // Synthetic attack generation
  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(() => {
      const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
      if (activeFilterRef.current && type.name !== activeFilterRef.current) return;

      const srcIdx = Math.floor(Math.random() * GLOBAL_SENSOR_HUBS.length);
      let dstIdx = Math.floor(Math.random() * GLOBAL_SENSOR_HUBS.length);
      while (dstIdx === srcIdx) {
        dstIdx = Math.floor(Math.random() * GLOBAL_SENSOR_HUBS.length);
      }

      const source = GLOBAL_SENSOR_HUBS[srcIdx];
      const target = GLOBAL_SENSOR_HUBS[dstIdx];
      const payloadMb = Math.floor(Math.random() * 500) + 12;

      const newArc = {
        id: Math.random().toString(36).substring(7),
        source,
        target,
        type: type.name,
        color: type.color,
        port: type.port,
        threat: type.threat,
        payload: payloadMb,
        progress: 0,
        speed: 0.015 + Math.random() * 0.012,
        curveOffset: (Math.random() - 0.5) * 80,
      };

      arcsRef.current.push(newArc);
      setActiveVectorsCount(arcsRef.current.length);

      // Add to live log
      setFeed((prev) => [
        {
          id: newArc.id,
          time: new Date().toLocaleTimeString(),
          source: source.name,
          sourceFlag: source.flag,
          target: target.name,
          targetFlag: target.flag,
          type: type.name,
          color: type.color,
          payload: payloadMb,
          port: type.port,
          threat: type.threat,
        },
        ...prev.slice(0, 40),
      ]);

      // Telemetry stats
      setStats((s) => ({
        bandwidth: Math.min(25000, s.bandwidth + payloadMb * 2.4),
        packets: s.packets + Math.floor(payloadMb * 180),
      }));
    }, simSpeed);

    return () => clearInterval(interval);
  }, [isPaused, simSpeed]);

  // Bandwidth decay
  useEffect(() => {
    const decay = setInterval(() => {
      setStats((s) => ({
        bandwidth: Math.max(120, Math.floor(s.bandwidth * 0.94)),
        packets: Math.max(400, Math.floor(s.packets * 0.95)),
      }));
    }, 1000);
    return () => clearInterval(decay);
  }, []);

  // Main Canvas Render Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = (canvas.width = canvas.parentElement?.clientWidth || 800);
    let height = (canvas.height = canvas.parentElement?.clientHeight || 600);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      const dpr = window.devicePixelRatio || 1;
      width = canvas.parentElement.clientWidth;
      height = canvas.parentElement.clientHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.scale(dpr, dpr);
    };

    handleResize();
    window.addEventListener("resize", handleResize);

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // 1. Draw Tactical Matrix Grid
      if (showGridRef.current) {
        ctx.save();
        ctx.strokeStyle = "rgba(0, 245, 212, 0.05)";
        ctx.lineWidth = 1;

        // Longitude grid lines
        for (let x = 0; x <= width; x += width / 12) {
          ctx.beginPath();
          ctx.moveTo(x, 0);
          ctx.lineTo(x, height);
          ctx.stroke();
        }

        // Latitude grid lines
        for (let y = 0; y <= height; y += height / 8) {
          ctx.beginPath();
          ctx.moveTo(0, y);
          ctx.lineTo(width, y);
          ctx.stroke();
        }

        // Equator highlight
        ctx.strokeStyle = "rgba(0, 245, 212, 0.12)";
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(0, height / 2);
        ctx.lineTo(width, height / 2);
        ctx.stroke();
        ctx.setLineDash([]);

        ctx.restore();
      }

      // 2. Draw Sensor Nodes & Pulse Beacons
      GLOBAL_SENSOR_HUBS.forEach((hub) => {
        const pt = projectCoords(hub.lat, hub.lng, width, height);

        // Radar node base
        ctx.save();
        ctx.fillStyle = hub.color;
        ctx.shadowColor = hub.color;
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 4, 0, Math.PI * 2);
        ctx.fill();

        // Node pulse wave
        const waveR = 4 + (Date.now() / 40) % 18;
        const waveOp = Math.max(0, 1 - waveR / 22);
        ctx.strokeStyle = hub.color;
        ctx.globalAlpha = waveOp;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, waveR, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = 1.0;

        // Hub Text Label
        ctx.font = "600 9px monospace";
        ctx.fillStyle = "#ffffff";
        ctx.fillText(`${hub.flag} ${hub.id.toUpperCase()}`, pt.x + 8, pt.y + 3);
        ctx.restore();
      });

      // 3. Draw Active Ballistic Trajectory Arcs
      const arcs = arcsRef.current;
      for (let i = arcs.length - 1; i >= 0; i--) {
        const arc = arcs[i];
        if (!isPausedRef.current) {
          arc.progress += arc.speed;
        }

        const p1 = projectCoords(arc.source.lat, arc.source.lng, width, height);
        const p2 = projectCoords(arc.target.lat, arc.target.lng, width, height);

        const midX = (p1.x + p2.x) / 2;
        const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
        const midY = (p1.y + p2.y) / 2 - Math.min(dist * 0.35, 120) + arc.curveOffset;

        // Trajectory dashed curve
        ctx.save();
        ctx.strokeStyle = arc.color;
        ctx.lineWidth = 1.5;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.quadraticCurveTo(midX, midY, p2.x, p2.y);
        ctx.stroke();
        ctx.setLineDash([]);

        // Active traveling missile head
        const t = Math.min(arc.progress, 1);
        const headX = (1 - t) * (1 - t) * p1.x + 2 * (1 - t) * t * midX + t * t * p2.x;
        const headY = (1 - t) * (1 - t) * p1.y + 2 * (1 - t) * t * midY + t * t * p2.y;

        ctx.fillStyle = "#ffffff";
        ctx.shadowColor = arc.color;
        ctx.shadowBlur = 12;
        ctx.beginPath();
        ctx.arc(headX, headY, 3.5, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = arc.color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(headX, headY, 6, 0, Math.PI * 2);
        ctx.stroke();

        // Label on flight path
        if (t > 0.25 && t < 0.75) {
          const lbl = `${arc.type} (${arc.payload}MB)`;
          ctx.font = "bold 9px monospace";
          const tw = ctx.measureText(lbl).width;
          ctx.fillStyle = "rgba(4, 8, 16, 0.9)";
          ctx.fillRect(headX - tw / 2 - 4, headY - 18, tw + 8, 13);
          ctx.strokeStyle = arc.color;
          ctx.lineWidth = 0.8;
          ctx.strokeRect(headX - tw / 2 - 4, headY - 18, tw + 8, 13);
          ctx.fillStyle = "#ffffff";
          ctx.fillText(lbl, headX - tw / 2, headY - 8);
        }
        ctx.restore();

        // Target Impact
        if (arc.progress >= 1) {
          impactsRef.current.push({
            x: p2.x,
            y: p2.y,
            r: 2,
            op: 1,
            color: arc.color,
          });
          arcs.splice(i, 1);
          setActiveVectorsCount(arcs.length);
        }
      }

      // 4. Draw Expanding Impact Shockwaves
      const impacts = impactsRef.current;
      for (let j = impacts.length - 1; j >= 0; j--) {
        const imp = impacts[j];
        imp.r += 1.6;
        imp.op -= 0.04;

        ctx.save();
        ctx.strokeStyle = imp.color;
        ctx.lineWidth = 2;
        ctx.globalAlpha = Math.max(0, imp.op);
        ctx.beginPath();
        ctx.arc(imp.x, imp.y, imp.r, 0, Math.PI * 2);
        ctx.stroke();
        ctx.restore();

        if (imp.op <= 0) {
          impacts.splice(j, 1);
        }
      }

      animIdRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener("resize", handleResize);
      if (animIdRef.current) cancelAnimationFrame(animIdRef.current);
    };
  }, []);

  const defcon = getDefconLevel();

  return (
    <div
      ref={containerRef}
      className={`w-full flex flex-col lg:flex-row relative font-mono shadow-2xl ${
        isFullscreenBg
          ? "h-full bg-[#02050A]"
          : "gap-4 h-[75vh] min-h-[580px] border border-cyan-500/20 rounded-2xl bg-[#030712] overflow-hidden"
      }`}
    >
      {/* ── Main 2D Tactical Attack Grid Canvas ── */}
      <div className="flex-1 w-full h-full relative cursor-crosshair overflow-hidden bg-[radial-gradient(ellipse_at_center,rgba(0,245,212,0.06)_0%,rgba(3,7,18,0.95)_75%)]">
        
        {/* Top HUD Telemetry Overlay */}
        <div className="absolute top-4 left-4 right-4 z-10 pointer-events-none flex justify-between items-start gap-4">
          <div className="space-y-2">
            <h2 className="text-sm font-bold text-white flex items-center gap-2 tracking-widest bg-black/60 px-3 py-1.5 rounded-lg backdrop-blur-md border border-cyan-500/30 shadow-lg">
              <span className={`w-2.5 h-2.5 rounded-full ${defcon.color.replace("text-", "bg-")} ${!isPaused ? "animate-ping" : ""}`} />
              TACTICAL THREAT RADAR
            </h2>
            <div className="bg-black/60 p-2.5 rounded-lg backdrop-blur-md border border-white/10 space-y-1 shadow-md">
              <p className="text-[11px] text-slate-300">
                Active Vectors: <span className="text-cyan-400 font-bold">{activeVectorsCount}</span>
              </p>
              <p className="text-[11px] text-slate-300">
                DEFCON: <span className={`${defcon.color} font-bold`}>{defcon.level} ({defcon.label})</span>
              </p>
            </div>
          </div>

          <div className="bg-black/60 p-3 rounded-lg backdrop-blur-md border border-white/10 text-right space-y-1 hidden sm:block shadow-md">
            <p className="text-[10px] text-slate-400 uppercase tracking-wider">Global Traffic Impact</p>
            <p className="text-lg text-cyan-400 font-bold">{(stats.bandwidth / 1024).toFixed(2)} GB/s</p>
            <p className="text-[10px] text-slate-400">{stats.packets.toLocaleString()} Pkt/s intercepted</p>
          </div>
        </div>

        {/* Bottom Interactive Controls Overlay */}
        <div className="absolute bottom-4 left-4 right-4 z-10 flex flex-col sm:flex-row gap-3 justify-between items-end pointer-events-auto">
          
          {/* Attack Vector Filter Pills */}
          <div className="flex flex-wrap gap-1.5 max-w-lg bg-black/70 p-2 rounded-xl border border-white/10 backdrop-blur-md shadow-lg">
            <button
              onClick={() => setActiveFilter(null)}
              className={`px-2.5 py-1 rounded text-[10px] font-bold border transition-all ${
                !activeFilter
                  ? "border-cyan-400 text-cyan-300 bg-cyan-500/20 shadow-[0_0_10px_rgba(0,245,212,0.3)]"
                  : "border-white/10 text-slate-400 hover:bg-white/10"
              }`}
            >
              ALL
            </button>
            {ATTACK_TYPES.map((t) => (
              <button
                key={t.name}
                onClick={() => setActiveFilter(t.name)}
                className="px-2.5 py-1 rounded text-[10px] border transition-all flex items-center gap-1.5"
                style={{
                  borderColor: activeFilter === t.name ? t.color : "rgba(255,255,255,0.12)",
                  backgroundColor: activeFilter === t.name ? `${t.color}25` : "transparent",
                  color: activeFilter === t.name ? "#fff" : "rgba(255,255,255,0.7)",
                }}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: t.color }} />
                {t.name}
              </button>
            ))}
          </div>

          {/* Controls: Play/Pause, Speed, Grid Toggle */}
          <div className="flex items-center gap-3 bg-black/70 p-2 rounded-xl border border-white/10 backdrop-blur-md shadow-lg">
            <button
              onClick={() => setShowGrid(!showGrid)}
              className={`text-xs font-bold px-2.5 py-1.5 rounded transition-all border ${
                showGrid ? "border-cyan-400/50 bg-cyan-500/15 text-cyan-300" : "border-white/10 bg-white/5 text-slate-400"
              }`}
              title="Toggle Tactical Coordinate Grid"
            >
              🌐 GRID: {showGrid ? "ON" : "OFF"}
            </button>
          </div>
        </div>

        {/* HTML5 Tactical Canvas */}
        <canvas ref={canvasRef} className="w-full h-full block" />
      </div>

      {/* ── Right-Side Real-Time Threat Log Stream ── */}
      <div className="w-full lg:w-96 h-64 lg:h-full bg-black/80 border-t lg:border-t-0 lg:border-l border-white/10 flex flex-col font-mono text-[10px] overflow-hidden backdrop-blur-xl shrink-0 z-10">
        <div className="p-3 border-b border-white/10 bg-white/[0.02] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-white font-bold tracking-wider text-xs">LIVE ATTACK STREAM</span>
            <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 text-[8px] border border-rose-500/30 font-bold animate-pulse">
              LIVE
            </span>
          </div>
          <button
            onClick={() => setFeed([])}
            className="text-[9px] text-slate-400 hover:text-white px-2 py-0.5 rounded bg-white/5 border border-white/10 transition"
          >
            Clear
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1.5 scrollbar-thin">
          {feed.length === 0 ? (
            <div className="text-center text-slate-500 mt-10 text-[11px]">Awaiting telemetry stream...</div>
          ) : (
            feed.map((item) => (
              <div
                key={item.id}
                className="p-2 rounded-lg bg-white/[0.03] border border-white/5 hover:border-white/20 transition flex flex-col gap-1"
              >
                <div className="flex justify-between items-center">
                  <span className="text-slate-400 text-[9px]">{item.time}</span>
                  <span
                    className="font-bold px-1.5 py-0.2 rounded text-[8.5px]"
                    style={{
                      color: item.color,
                      backgroundColor: `${item.color}15`,
                      border: `1px solid ${item.color}30`,
                    }}
                  >
                    {item.type}
                  </span>
                </div>
                <div className="text-slate-200 text-[10px] flex items-center gap-1">
                  <span>{item.sourceFlag} {item.source}</span>
                  <span className="text-cyan-400 font-bold">➔</span>
                  <span>{item.targetFlag} {item.target}</span>
                </div>
                <div className="flex justify-between text-[9px] text-slate-400">
                  <span>Payload: <b className="text-white">{item.payload} MB</b></span>
                  <span>Port: <b className="text-slate-300">{item.port}</b></span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
