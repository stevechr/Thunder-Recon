"use client";

import React, { useState, useEffect, useRef } from "react";
import dynamic from "next/dynamic";

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

// Helper to generate random coordinates
const randCoords = () => ({
  lat: (Math.random() - 0.5) * 160,
  lng: (Math.random() - 0.5) * 360,
});

// Attack types for visual flair
const ATTACK_TYPES = [
  { name: "DDoS Amplification", color: "#ff2a2a", intensity: 1.5, port: 53 },
  { name: "SQL Injection", color: "#ff8c00", intensity: 1.0, port: 443 },
  { name: "SSH Brute-Force", color: "#00ffff", intensity: 0.8, port: 22 },
  { name: "RCE Exploit", color: "#ff00ff", intensity: 1.2, port: 8080 },
  { name: "Ransomware C2", color: "#ff0044", intensity: 2.0, port: 4444 },
];

export default function LiveAttackMap() {
  const globeEl = useRef<any>(null);
  const [arcsData, setArcsData] = useState<any[]>([]);
  const [ringsData, setRingsData] = useState<any[]>([]);
  const [feed, setFeed] = useState<any[]>([]);

  // Auto-rotate globe
  useEffect(() => {
    if (globeEl.current) {
      globeEl.current.controls().autoRotate = true;
      globeEl.current.controls().autoRotateSpeed = 0.8;
      globeEl.current.pointOfView({ altitude: 2.5 });
    }
  }, [globeEl.current]);

  // Synthetic attack stream
  useEffect(() => {
    const interval = setInterval(() => {
      const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
      const source = randCoords();
      const target = randCoords();
      
      const newAttack = {
        id: Math.random().toString(36).substring(7),
        startLat: source.lat,
        startLng: source.lng,
        endLat: target.lat,
        endLng: target.lng,
        color: type.color,
        type: type.name,
        port: type.port,
        timestamp: new Date().toISOString().split("T")[1].split(".")[0], // HH:MM:SS
      };

      // Add to arcs
      setArcsData((prev) => [...prev.slice(-40), newAttack]);
      
      // Add impact ripple (ring) slightly delayed
      setTimeout(() => {
        setRingsData((prev) => [...prev.slice(-20), newAttack]);
      }, 1000);

      // Add to terminal feed
      setFeed((prev) => [newAttack, ...prev.slice(0, 49)]);
    }, 400); // 1 attack every 400ms

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="w-full flex flex-col lg:flex-row gap-4 h-[75vh] min-h-[600px] border border-panelBorder/40 rounded-2xl bg-void/50 overflow-hidden relative">
      
      {/* HUD Overlay */}
      <div className="absolute top-4 left-4 z-10 pointer-events-none">
        <h2 className="text-sm font-bold font-mono text-white flex items-center gap-2 tracking-widest">
          <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          GLOBAL THREAT RADAR
        </h2>
        <p className="text-[10px] text-mist/60 font-mono mt-1">
          Tracking {arcsData.length} active live vectors
        </p>
      </div>

      {/* 3D WebGL Globe */}
      <div className="flex-1 w-full h-full relative cursor-move bg-[#000005]">
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
          arcColor={(d: any) => [d.color, d.color]}
          arcDashLength={0.4}
          arcDashGap={0.2}
          arcDashAnimateTime={1200}
          arcAltitudeAutoScale={0.3}
          
          // Impact Rings
          ringsData={ringsData}
          ringLat={(d: any) => d.endLat}
          ringLng={(d: any) => d.endLng}
          ringColor={(d: any) => d.color}
          ringMaxRadius={5}
          ringPropagationSpeed={3}
          ringRepeatPeriod={0}
        />
      </div>

      {/* Live Terminal Log */}
      <div className="w-full lg:w-80 h-48 lg:h-full bg-black/80 border-t lg:border-t-0 lg:border-l border-panelBorder/40 flex flex-col font-mono text-[10px] overflow-hidden">
        <div className="p-3 border-b border-panelBorder/40 bg-white/[0.02] flex items-center justify-between">
          <span className="text-mist font-bold">LIVE INCIDENT FEED</span>
          <span className="text-cyan-signal text-[9px] animate-pulse">STREAMING</span>
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1 scrollbar-thin scrollbar-thumb-panelBorder">
          {feed.map((f) => (
            <div key={f.id} className="flex flex-col gap-0.5 p-1.5 rounded bg-white/[0.02] border border-white/[0.05] hover:bg-white/[0.05] transition">
              <div className="flex items-center justify-between opacity-70">
                <span className="text-mist">{f.timestamp}</span>
                <span style={{ color: f.color }} className="font-bold">{f.type}</span>
              </div>
              <div className="flex items-center justify-between mt-0.5">
                <span className="text-white/40 truncate w-24">
                  {f.startLat.toFixed(2)}, {f.startLng.toFixed(2)}
                </span>
                <span className="text-mist/30">→</span>
                <span className="text-white/80 truncate w-24 text-right">
                  {f.endLat.toFixed(2)}, {f.endLng.toFixed(2)} :<span className="text-orange-400">{f.port}</span>
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
