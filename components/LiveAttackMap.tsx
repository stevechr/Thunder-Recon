"use client";

import React, { useState, useEffect, useRef, useMemo } from "react";
import dynamic from "next/dynamic";
import * as THREE from "three";

// Dynamically import Globe because it relies on window/document (WebGL)
const Globe = dynamic(() => import("react-globe.gl"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex flex-col items-center justify-center font-mono text-cyan-signal text-xs animate-pulse bg-void">
      <div className="w-8 h-8 rounded-full border-2 border-t-cyan-signal border-r-cyan-signal border-b-transparent border-l-transparent animate-spin mb-4" />
      Initializing WebGL Cyber Globe...
    </div>
  ),
});

// Helper to generate random coordinates (biased slightly towards major tech hubs for realism)
const randCoords = () => {
  const hubs = [
    { lat: 37.77, lng: -122.41 }, // SF
    { lat: 40.71, lng: -74.00 }, // NY
    { lat: 51.50, lng: -0.12 }, // London
    { lat: 55.75, lng: 37.61 }, // Moscow
    { lat: 39.90, lng: 116.40 }, // Beijing
    { lat: 35.68, lng: 139.69 }, // Tokyo
    { lat: -23.55, lng: -46.63 }, // Sao Paulo
  ];
  if (Math.random() > 0.6) {
    const hub = hubs[Math.floor(Math.random() * hubs.length)];
    return {
      lat: hub.lat + (Math.random() - 0.5) * 10,
      lng: hub.lng + (Math.random() - 0.5) * 10,
    };
  }
  return {
    lat: (Math.random() - 0.5) * 160,
    lng: (Math.random() - 0.5) * 360,
  };
};

// Attack types for visual flair
const ATTACK_TYPES = [
  { name: "DDoS Amplification", color: "#ff2a2a", port: 53, threat: "CRITICAL" },
  { name: "SQL Injection", color: "#ff8c00", port: 443, threat: "HIGH" },
  { name: "SSH Brute-Force", color: "#00ffff", port: 22, threat: "ELEVATED" },
  { name: "RCE Exploit", color: "#ff00ff", port: 8080, threat: "HIGH" },
  { name: "Ransomware C2", color: "#ff0044", port: 4444, threat: "CRITICAL" },
  { name: "Port Scan", color: "#a855f7", port: 0, threat: "LOW" },
];

export default function LiveAttackMap({ isFullscreenBg = false }: { isFullscreenBg?: boolean }) {
  const globeEl = useRef<any>(null);
  
  // Simulation State
  const [arcsData, setArcsData] = useState<any[]>([]);
  const [ringsData, setRingsData] = useState<any[]>([]);
  const [feed, setFeed] = useState<any[]>([]);
  
  // Interactive Controls State
  const [isPaused, setIsPaused] = useState(false);
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [simSpeed, setSimSpeed] = useState(400); // ms per attack
  const [stats, setStats] = useState({ bandwidth: 0, packets: 0 });

  // Auto-rotate globe initially
  useEffect(() => {
    if (globeEl.current) {
      globeEl.current.controls().autoRotate = true;
      globeEl.current.controls().autoRotateSpeed = 0.5;
      globeEl.current.pointOfView({ altitude: 2.5 });
    }
  }, [globeEl.current]);

  // Handle auto-rotation pausing
  useEffect(() => {
    if (globeEl.current) {
      globeEl.current.controls().autoRotate = !isPaused;
    }
  }, [isPaused]);

  // Synthetic attack stream
  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(() => {
      const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
      
      // If a filter is active and doesn't match, skip rendering but keep clock ticking
      if (activeFilter && type.name !== activeFilter) return;

      const source = randCoords();
      const target = randCoords();
      const payloadMb = Math.floor(Math.random() * 500) + 10;
      
      const newAttack = {
        id: Math.random().toString(36).substring(7),
        startLat: source.lat,
        startLng: source.lng,
        endLat: target.lat,
        endLng: target.lng,
        color: type.color,
        type: type.name,
        port: type.port,
        threat: type.threat,
        payload: payloadMb,
        timestamp: new Date().toISOString().split("T")[1].split(".")[0],
      };

      // Add to arcs
      setArcsData((prev) => [...prev.slice(-60), newAttack]);
      
      // Add source ring (small, instant)
      setRingsData((prev) => [...prev.slice(-40), { ...newAttack, isSource: true }]);

      // Add impact ripple (large, delayed to simulate arc travel)
      setTimeout(() => {
        setRingsData((prev) => [...prev.slice(-40), { ...newAttack, isSource: false }]);
      }, 1000);

      // Add to terminal feed
      setFeed((prev) => [newAttack, ...prev.slice(0, 99)]);
      
      // Update HUD stats
      setStats((prev) => ({
        bandwidth: prev.bandwidth + payloadMb,
        packets: prev.packets + Math.floor(Math.random() * 10000),
      }));

    }, simSpeed);

    return () => clearInterval(interval);
  }, [isPaused, activeFilter, simSpeed]);

  // Camera Fly-To function
  const focusOnTarget = (lat: number, lng: number) => {
    setIsPaused(true);
    if (globeEl.current) {
      globeEl.current.pointOfView({ lat, lng, altitude: 0.8 }, 1500); // 1.5s animation
    }
  };

  const getDefconLevel = () => {
    if (simSpeed < 200) return { level: 1, color: "text-red-500", label: "CRITICAL WARFARE" };
    if (simSpeed <= 400) return { level: 2, color: "text-orange-500", label: "HIGH ALERT" };
    if (simSpeed <= 800) return { level: 3, color: "text-yellow-500", label: "ELEVATED" };
    return { level: 4, color: "text-green-500", label: "NORMAL" };
  };

  const defcon = getDefconLevel();

  return (
    <div className={`w-full flex flex-col lg:flex-row relative font-mono shadow-2xl shadow-cyan-900/10 ${
      isFullscreenBg 
        ? "h-full bg-black" 
        : "gap-4 h-[75vh] min-h-[600px] border border-panelBorder/40 rounded-2xl bg-[#000005] overflow-hidden"
    }`}>
      
      {/* 3D WebGL Globe */}
      <div className="flex-1 w-full h-full relative cursor-move">
        
        {/* Advanced HUD Top Overlay */}
        <div className="absolute top-4 left-4 right-4 z-10 pointer-events-none flex justify-between items-start">
          <div className="space-y-2">
            <h2 className="text-sm font-bold text-white flex items-center gap-2 tracking-widest bg-black/50 p-2 rounded backdrop-blur-md border border-white/10">
              <span className={`w-2 h-2 rounded-full ${defcon.color.replace('text', 'bg')} ${!isPaused ? 'animate-pulse' : ''}`} />
              THREAT RADAR
            </h2>
            <div className="bg-black/50 p-2 rounded backdrop-blur-md border border-white/10 space-y-1">
              <p className="text-[10px] text-mist/80">Active Vectors: <span className="text-white font-bold">{arcsData.length}</span></p>
              <p className="text-[10px] text-mist/80">DEFCON: <span className={`${defcon.color} font-bold`}>{defcon.level} ({defcon.label})</span></p>
            </div>
          </div>

          <div className="bg-black/50 p-3 rounded backdrop-blur-md border border-white/10 text-right space-y-1 hidden sm:block">
            <p className="text-[10px] text-mist/60 uppercase tracking-wider">Global Traffic Impact</p>
            <p className="text-lg text-cyan-signal font-bold">{(stats.bandwidth / 1024).toFixed(2)} GB/s</p>
            <p className="text-[10px] text-white/50">{stats.packets.toLocaleString()} Pkt/s intercepted</p>
          </div>
        </div>

        {/* Interactive Controls Overlay (Bottom) */}
        <div className="absolute bottom-4 left-4 right-4 z-10 flex flex-col sm:flex-row gap-4 justify-between items-end pointer-events-auto">
          
          {/* Legend / Filters */}
          <div className="flex flex-wrap gap-2 max-w-lg bg-black/60 p-2 rounded-lg border border-white/10 backdrop-blur-md">
            <button 
              onClick={() => setActiveFilter(null)}
              className={`px-2 py-1 rounded text-[10px] border transition-all ${!activeFilter ? 'border-white text-white bg-white/20' : 'border-white/10 text-mist hover:bg-white/10'}`}
            >
              ALL
            </button>
            {ATTACK_TYPES.map((t) => (
              <button
                key={t.name}
                onClick={() => setActiveFilter(t.name)}
                className={`px-2 py-1 rounded text-[10px] border transition-all flex items-center gap-1.5`}
                style={{ 
                  borderColor: activeFilter === t.name ? t.color : 'rgba(255,255,255,0.1)',
                  backgroundColor: activeFilter === t.name ? `${t.color}20` : 'transparent',
                  color: activeFilter === t.name ? '#fff' : 'rgba(255,255,255,0.6)'
                }}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: t.color }} />
                {t.name}
              </button>
            ))}
          </div>

          {/* Playback & Speed Controls */}
          <div className="flex items-center gap-4 bg-black/60 p-2 rounded-lg border border-white/10 backdrop-blur-md">
            <button
              onClick={() => setIsPaused(!isPaused)}
              className="text-xs font-bold text-white bg-white/10 hover:bg-white/20 px-3 py-1.5 rounded transition-all flex items-center gap-2"
            >
              {isPaused ? "▶ RESUME" : "⏸ PAUSE"}
            </button>
            <div className="flex items-center gap-2 text-[10px] text-mist">
              <span>SPEED:</span>
              <input 
                type="range" 
                min="50" 
                max="1000" 
                step="50" 
                value={1050 - simSpeed} // invert for intuitive UI (higher = faster)
                onChange={(e) => setSimSpeed(1050 - parseInt(e.target.value))}
                className="w-24 accent-cyan-signal"
              />
            </div>
          </div>

        </div>

        <Globe
          ref={globeEl}
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
          bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
          backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
          
          // Arcs (Pew Pew)
          arcsData={arcsData}
          arcStartLat={(d: any) => d.startLat}
          arcStartLng={(d: any) => d.startLng}
          arcEndLat={(d: any) => d.endLat}
          arcEndLng={(d: any) => d.endLng}
          arcColor={(d: any) => ['rgba(255, 255, 255, 0.8)', d.color]} // Gradient: White origin to Colored impact
          arcDashLength={0.4}
          arcDashGap={0.2}
          arcDashAnimateTime={1200}
          arcAltitudeAutoScale={0.3}
          arcLabel={(d: any) => `
            <div style="background: rgba(0,0,0,0.8); border: 1px solid ${d.color}; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 10px;">
              <strong style="color: ${d.color}">${d.type}</strong><br/>
              Payload: ${d.payload} MB<br/>
              Target Port: ${d.port}
            </div>
          `}
          
          // Impact & Source Rings
          ringsData={ringsData}
          ringLat={(d: any) => d.isSource ? d.startLat : d.endLat}
          ringLng={(d: any) => d.isSource ? d.startLng : d.endLng}
          ringColor={(d: any) => d.color}
          ringMaxRadius={(d: any) => d.isSource ? 1.5 : 5} // Source rings are small, impact rings are large
          ringPropagationSpeed={(d: any) => d.isSource ? 1 : 3}
          ringRepeatPeriod={0}
        />
      </div>

      {/* Interactive Terminal Log */}
      <div className="w-full lg:w-96 h-64 lg:h-full bg-black/80 border-t lg:border-t-0 lg:border-l border-white/10 flex flex-col font-mono text-[10px] overflow-hidden backdrop-blur-xl relative z-10">
        <div className="p-3 border-b border-white/10 bg-white/[0.02] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-white font-bold tracking-wider">THREAT LOG</span>
            <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-[8px] border border-red-500/30">LIVE</span>
          </div>
          {isPaused && <span className="text-yellow-500 text-[9px] animate-pulse">PAUSED</span>}
        </div>
        
        <div className="flex-1 overflow-y-auto p-2 space-y-1.5 scrollbar-thin scrollbar-thumb-white/20">
          {feed.map((f) => (
            <div 
              key={f.id} 
              onClick={() => focusOnTarget(f.endLat, f.endLng)}
              className="flex flex-col gap-1 p-2 rounded bg-white/[0.03] border border-white/[0.05] hover:bg-white/[0.08] hover:border-white/20 transition-all cursor-pointer group"
              title="Click to track target on globe"
            >
              <div className="flex items-center justify-between opacity-80">
                <span className="text-mist">{f.timestamp}</span>
                <span className="text-[8px] px-1 rounded border" style={{ borderColor: f.color, color: f.color }}>{f.threat}</span>
              </div>
              <div className="flex items-center justify-between">
                <span style={{ color: f.color }} className="font-bold text-[11px] group-hover:underline">{f.type}</span>
                <span className="text-mist/60">{f.payload} MB</span>
              </div>
              <div className="flex items-center justify-between mt-1 text-[9px]">
                <span className="text-white/40 truncate flex-1">
                  {f.startLat.toFixed(1)}, {f.startLng.toFixed(1)}
                </span>
                <span className="text-white/20 mx-2">→</span>
                <span className="text-white/70 truncate flex-1 text-right">
                  {f.endLat.toFixed(1)}, {f.endLng.toFixed(1)} <span className="text-white/40">:{f.port}</span>
                </span>
              </div>
            </div>
          ))}
          {feed.length === 0 && (
            <div className="text-center text-mist/30 mt-10">Awaiting telemetry...</div>
          )}
        </div>
      </div>
    </div>
  );
}
