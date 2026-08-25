"use client";

import React, { useEffect, useRef, useState } from "react";

interface RealCountry {
  id: string;
  name: string;
  code: string;
  flag: string;
  lat: number;
  lng: number;
  color: string;
  traffic: string;
  status: string;
  activeAttacks: number;
}

const COUNTRIES: RealCountry[] = [
  { id: "usa", name: "United States", code: "USA", flag: "🇺🇸", lat: 37.0902, lng: -95.7129, color: "#38BDF8", traffic: "184 Gbps", status: "Shield Active", activeAttacks: 1420 },
  { id: "can", name: "Canada", code: "CAN", flag: "🇨🇦", lat: 56.1304, lng: -106.3468, color: "#38BDF8", traffic: "42 Gbps", status: "Guarded", activeAttacks: 210 },
  { id: "bra", name: "Brazil", code: "BRA", flag: "🇧🇷", lat: -14.235, lng: -51.9253, color: "#F43F5E", traffic: "96 Gbps", status: "Attack Origin", activeAttacks: 680 },
  { id: "gbr", name: "United Kingdom", code: "GBR", flag: "🇬🇧", lat: 55.3781, lng: -3.436, color: "#00F5D4", traffic: "128 Gbps", status: "SOC Defense", activeAttacks: 940 },
  { id: "deu", name: "Germany", code: "DEU", flag: "🇩🇪", lat: 51.1657, lng: 10.4515, color: "#00F5D4", traffic: "115 Gbps", status: "Scrubbing Active", activeAttacks: 830 },
  { id: "fra", name: "France", code: "FRA", flag: "🇫🇷", lat: 46.2276, lng: 2.2137, color: "#00F5D4", traffic: "89 Gbps", status: "Guarded", activeAttacks: 510 },
  { id: "ukr", name: "Ukraine", code: "UKR", flag: "🇺🇦", lat: 48.3794, lng: 31.1656, color: "#FFB703", traffic: "94 Gbps", status: "Critical Target", activeAttacks: 1890 },
  { id: "rus", name: "Russia", code: "RUS", flag: "🇷🇺", lat: 61.524, lng: 105.3188, color: "#F43F5E", traffic: "210 Gbps", status: "Threat Swarm C2", activeAttacks: 2450 },
  { id: "chn", name: "China", code: "CHN", flag: "🇨🇳", lat: 35.8617, lng: 104.1954, color: "#F43F5E", traffic: "260 Gbps", status: "C2 Swarm Detected", activeAttacks: 3100 },
  { id: "ind", name: "India", code: "IND", flag: "🇮🇳", lat: 20.5937, lng: 78.9629, color: "#FFB703", traffic: "145 Gbps", status: "DDoS Mitigation", activeAttacks: 1120 },
  { id: "jpn", name: "Japan", code: "JPN", flag: "🇯🇵", lat: 36.2048, lng: 138.2529, color: "#38BDF8", traffic: "88 Gbps", status: "Hardened", activeAttacks: 430 },
  { id: "kor", name: "South Korea", code: "KOR", flag: "🇰🇷", lat: 35.9078, lng: 127.7669, color: "#38BDF8", traffic: "74 Gbps", status: "Defended", activeAttacks: 380 },
  { id: "sgp", name: "Singapore", code: "SGP", flag: "🇸🇬", lat: 1.3521, lng: 103.8198, color: "#00F5D4", traffic: "112 Gbps", status: "Secure Gateway", activeAttacks: 720 },
  { id: "aus", name: "Australia", code: "AUS", flag: "🇦🇺", lat: -25.2744, lng: 133.7751, color: "#38BDF8", traffic: "65 Gbps", status: "Protected", activeAttacks: 290 },
  { id: "zaf", name: "South Africa", code: "ZAF", flag: "🇿🇦", lat: -30.5595, lng: 22.9375, color: "#F43F5E", traffic: "44 Gbps", status: "Botnet Surge", activeAttacks: 340 },
  { id: "are", name: "UAE", code: "ARE", flag: "🇦🇪", lat: 23.4241, lng: 53.8478, color: "#00F5D4", traffic: "58 Gbps", status: "Shield Active", activeAttacks: 410 },
  { id: "nld", name: "Netherlands", code: "NLD", flag: "🇳🇱", lat: 52.1326, lng: 5.2913, color: "#00F5D4", traffic: "140 Gbps", status: "IXP Hub Defended", activeAttacks: 980 },
];

const ATTACK_VECTORS = [
  { name: "Volumetric UDP/DNS Amp", color: "#F43F5E", minBw: 80, maxBw: 185 },
  { name: "Mirai C2 IoT Swarm", color: "#FFB703", minBw: 30, maxBw: 75 },
  { name: "HTTP/2 Rapid Reset Exploit", color: "#00F5D4", minBw: 45, maxBw: 110 },
  { name: "SYN Flood Exfiltration", color: "#A855F7", minBw: 20, maxBw: 55 },
];

export default function RealWorldThreatMap() {
  const mapContainerRef = useRef<HTMLDivElement | null>(null);
  const mapInstanceRef = useRef<any>(null);
  const arcsLayerRef = useRef<any>(null);
  const [activeTileLayer, setActiveTileLayer] = useState<"dark" | "satellite">("dark");
  const [selectedCountry, setSelectedCountry] = useState<RealCountry | null>(null);
  const [recentVectors, setRecentVectors] = useState<Array<{ id: number; text: string; color: string }>>([
    { id: 1, text: "🇨🇳 China ➔ 🇺🇸 United States • UDP Amp (142 Gbps)", color: "#F43F5E" },
    { id: 2, text: "🇷🇺 Russia ➔ 🇺🇦 Ukraine • Mirai C2 Swarm (68 Gbps)", color: "#FFB703" },
    { id: 3, text: "🇧🇷 Brazil ➔ 🇬🇧 United Kingdom • HTTP/2 Reset", color: "#00F5D4" },
  ]);

  useEffect(() => {
    let isMounted = true;

    const initMap = async () => {
      if (typeof window === "undefined" || !mapContainerRef.current) return;

      const L = (await import("leaflet")).default;

      // Prevent re-initialization
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }

      // Initialize real interactive Leaflet map
      const map = L.map(mapContainerRef.current, {
        center: [25, 10],
        zoom: 2,
        minZoom: 2,
        maxZoom: 9,
        zoomControl: false,
        attributionControl: false,
        worldCopyJump: true,
      });

      mapInstanceRef.current = map;

      // Add Zoom Control at bottom right
      L.control.zoom({ position: "bottomright" }).addTo(map);

      // Base Tile Layer: CartoDB Dark Matter
      const darkTiles = L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          subdomains: "abcd",
          maxZoom: 19,
        }
      );

      const satelliteTiles = L.tileLayer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
        {
          maxZoom: 18,
        }
      );

      if (activeTileLayer === "dark") {
        darkTiles.addTo(map);
      } else {
        satelliteTiles.addTo(map);
      }

      // Layer group for dynamic attack trajectories
      const arcsLayer = L.layerGroup().addTo(map);
      arcsLayerRef.current = arcsLayer;

      // Add Sovereign Country Pulse Markers
      COUNTRIES.forEach((c) => {
        const customIcon = L.divIcon({
          className: "custom-country-pin",
          html: `
            <div style="position: relative; display: flex; align-items: center; cursor: pointer;">
              <!-- Pulse Wave -->
              <div style="
                position: absolute;
                top: -6px;
                left: -6px;
                width: 24px;
                height: 24px;
                border-radius: 50%;
                border: 1.5px solid ${c.color};
                opacity: 0.7;
                animation: ping 2.5s cubic-bezier(0, 0, 0.2, 1) infinite;
              "></div>

              <!-- Core Dot -->
              <div style="
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background: ${c.color};
                box-shadow: 0 0 12px ${c.color};
                border: 2px solid #ffffff;
                z-index: 10;
              "></div>

              <!-- Country Tag -->
              <div style="
                margin-left: 8px;
                background: rgba(6, 12, 24, 0.90);
                border: 1px solid rgba(255, 255, 255, 0.15);
                padding: 2px 7px;
                border-radius: 6px;
                white-space: nowrap;
                font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
                font-size: 11px;
                font-weight: 600;
                color: #F8FAFC;
                box-shadow: 0 4px 12px rgba(0,0,0,0.5);
                display: flex;
                align-items: center;
                gap: 4px;
              ">
                <span>${c.flag}</span>
                <span>${c.name}</span>
              </div>
            </div>
          `,
          iconSize: [120, 24],
          iconAnchor: [6, 12],
        });

        const marker = L.marker([c.lat, c.lng], { icon: customIcon }).addTo(map);

        marker.on("click", () => {
          setSelectedCountry(c);
          map.flyTo([c.lat, c.lng], Math.max(map.getZoom(), 4), { duration: 1 });
        });
      });
    };

    initMap();

    return () => {
      isMounted = false;
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [activeTileLayer]);

  // Periodic Ballistic Attack Trajectory Arcs on Leaflet
  useEffect(() => {
    const interval = setInterval(async () => {
      if (!mapInstanceRef.current || !arcsLayerRef.current) return;
      const L = (await import("leaflet")).default;

      const sIdx = Math.floor(Math.random() * COUNTRIES.length);
      let tIdx = Math.floor(Math.random() * COUNTRIES.length);
      while (tIdx === sIdx) tIdx = Math.floor(Math.random() * COUNTRIES.length);

      const src = COUNTRIES[sIdx];
      const tgt = COUNTRIES[tIdx];
      const type = ATTACK_VECTORS[Math.floor(Math.random() * ATTACK_VECTORS.length)];
      const bw = `${Math.floor(type.minBw + Math.random() * (type.maxBw - type.minBw))} Gbps`;

      // Generate curved geodesic coordinates (quadratic Bezier in geo-space)
      const latMid = (src.lat + tgt.lat) / 2 + (tgt.lng > src.lng ? 15 : -15);
      const lngMid = (src.lng + tgt.lng) / 2;

      const curvePoints: [number, number][] = [];
      const steps = 25;
      for (let i = 0; i <= steps; i++) {
        const t = i / steps;
        const lat = (1 - t) * (1 - t) * src.lat + 2 * (1 - t) * t * latMid + t * t * tgt.lat;
        const lng = (1 - t) * (1 - t) * src.lng + 2 * (1 - t) * t * lngMid + t * t * tgt.lng;
        curvePoints.push([lat, lng]);
      }

      // Draw trajectory polyline
      const polyline = L.polyline(curvePoints, {
        color: type.color,
        weight: 2,
        opacity: 0.65,
        dashArray: "6, 6",
      }).addTo(arcsLayerRef.current);

      // Add pulsing impact circle on target
      const impactCircle = L.circleMarker([tgt.lat, tgt.lng], {
        radius: 12,
        color: type.color,
        fillColor: type.color,
        fillOpacity: 0.3,
        weight: 1.5,
      }).addTo(arcsLayerRef.current);

      // Auto-remove arc after flight completes
      setTimeout(() => {
        if (arcsLayerRef.current) {
          arcsLayerRef.current.removeLayer(polyline);
          arcsLayerRef.current.removeLayer(impactCircle);
        }
      }, 3500);

      // Update ticker
      setRecentVectors((prev) => [
        {
          id: Date.now() + Math.random(),
          text: `${src.flag} ${src.name} ➔ ${tgt.flag} ${tgt.name} • ${type.name} (${bw})`,
          color: type.color,
        },
        ...prev.slice(0, 2),
      ]);
    }, 2400);

    return () => clearInterval(interval);
  }, []);

  const handleResetView = () => {
    if (mapInstanceRef.current) {
      mapInstanceRef.current.flyTo([25, 10], 2, { duration: 1.2 });
      setSelectedCountry(null);
    }
  };

  return (
    <div className="w-full relative rounded-2xl bg-[#030712] border border-white/15 overflow-hidden shadow-2xl h-[380px] sm:h-[480px] lg:h-[520px]">
      
      {/* Actual Real-World Leaflet Map Container */}
      <div ref={mapContainerRef} className="w-full h-full z-0" />

      {/* Layer Switcher & Reset Control (Top Left) */}
      <div className="absolute top-2.5 left-2.5 z-[1000] flex items-center gap-1 bg-[#060D1E]/90 backdrop-blur-md p-1 rounded-xl border border-white/15 shadow-xl">
        <button
          onClick={() => setActiveTileLayer("dark")}
          className={`px-2.5 py-1 text-[11px] sm:text-xs font-semibold rounded-lg transition-all ${
            activeTileLayer === "dark"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/40"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          🌐 Dark Carto
        </button>
        <button
          onClick={() => setActiveTileLayer("satellite")}
          className={`px-2.5 py-1 text-[11px] sm:text-xs font-semibold rounded-lg transition-all ${
            activeTileLayer === "satellite"
              ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/40"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          🛰️ Satellite
        </button>
        <button
          onClick={handleResetView}
          className="px-2 py-1 text-[11px] sm:text-xs font-medium rounded-lg text-slate-400 hover:text-white bg-white/5 hover:bg-white/10"
          title="Reset Global View"
        >
          ↺ Reset
        </button>
      </div>

      {/* Live Ballistic Stream Ticker (Top Right) */}
      <div className="absolute top-2.5 right-2.5 z-[1000] max-w-[220px] sm:max-w-xs hidden sm:block bg-[#060D1E]/90 backdrop-blur-md p-2.5 sm:p-3 rounded-xl border border-white/15 text-[10px] font-mono space-y-1.5 shadow-xl">
        <div className="text-slate-400 font-bold tracking-wider text-[9px] uppercase border-b border-white/10 pb-1 flex items-center justify-between">
          <span>LIVE BALLISTIC STREAM</span>
          <span className="text-rose-400 animate-pulse font-semibold">● ACTIVE</span>
        </div>
        {recentVectors.slice(0, 3).map((vec) => (
          <div key={vec.id} className="text-slate-300 truncate text-[10px]" style={{ borderLeft: `2px solid ${vec.color}`, paddingLeft: "6px" }}>
            {vec.text}
          </div>
        ))}
      </div>

      {/* Selected Country Tactical Inspector Modal (Bottom Left / Full Width on Mobile) */}
      {selectedCountry && (
        <div className="absolute bottom-2.5 left-2.5 right-2.5 sm:right-auto sm:max-w-md z-[1000] bg-[#060D1D]/95 backdrop-blur-md px-3.5 py-2.5 rounded-xl border border-cyan-400/40 text-xs font-mono flex items-center justify-between gap-3 shadow-2xl animate-fadeIn">
          <div>
            <span className="text-white font-bold text-xs sm:text-sm flex items-center gap-1.5">
              <span className="text-base sm:text-lg">{selectedCountry.flag}</span>
              <span>{selectedCountry.name} ({selectedCountry.code})</span>
            </span>
            <div className="text-[10px] sm:text-[11px] text-slate-400 mt-0.5 flex flex-wrap items-center gap-x-2.5 gap-y-0.5">
              <span>Status: <strong className="text-cyan-300">{selectedCountry.status}</strong></span>
              <span>Flow: <strong className="text-rose-400">{selectedCountry.traffic}</strong></span>
              <span>Attacks: <strong className="text-amber-400">{selectedCountry.activeAttacks.toLocaleString()}/min</strong></span>
            </div>
          </div>
          <button
            onClick={() => setSelectedCountry(null)}
            className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-white/10 shrink-0"
          >
            ✕
          </button>
        </div>
      )}

      {/* Bottom Map Legend (Bottom Right) */}
      <div className="absolute bottom-2.5 right-14 z-[1000] hidden md:flex items-center gap-3 bg-[#060D1E]/90 backdrop-blur-md px-3 py-1.5 rounded-xl border border-white/15 text-[10px] font-mono text-slate-300 shadow-xl">
        <span className="flex items-center gap-1 text-rose-400">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-500" /> UDP/DDoS
        </span>
        <span className="flex items-center gap-1 text-amber-400">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" /> Mirai Botnet
        </span>
        <span className="flex items-center gap-1 text-cyan-300">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" /> HTTP/2 Reset
        </span>
        <span className="flex items-center gap-1 text-purple-400">
          <span className="w-1.5 h-1.5 rounded-full bg-purple-500" /> SYN Flood
        </span>
      </div>

    </div>
  );
}
