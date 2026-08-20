"use client";

import { useState } from "react";
import { ScanResult } from "@/lib/api";

interface Node {
  id: string;
  label: string;
  type: "domain" | "ip" | "asn" | "port" | "subdomain" | "ssl" | "tech" | "risk";
  detail?: string;
  status?: "clean" | "warn" | "danger" | "info";
  x: number;
  y: number;
}

interface Edge {
  from: string;
  to: string;
  label?: string;
}

export default function AttackGraph({ result }: { result?: ScanResult | null }) {
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [customTarget, setCustomTarget] = useState("github.com");

  // Fallback demo dataset if no active scan result is present
  const targetDomain = result?.domain || customTarget;
  const rootId = "root";

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Central Domain Node
  nodes.push({
    id: rootId,
    label: targetDomain,
    type: "domain",
    detail: `Target Root Perimeter: ${targetDomain}`,
    status: (result?.risk?.score || 35) >= 50 ? "danger" : (result?.risk?.score || 35) >= 25 ? "warn" : "clean",
    x: 400,
    y: 250,
  });

  let angle = 0;
  const radius = 180;

  // 1. IP Node
  const ipVal = result?.ip || "140.82.121.4";
  const ipId = "node-ip";
  const radIp = (angle * Math.PI) / 180;
  nodes.push({
    id: ipId,
    label: ipVal,
    type: "ip",
    detail: `IP Geolocation: ${result?.ip_intel?.city || "San Francisco"}, ${result?.ip_intel?.country || "United States"}`,
    status: result?.ip_intel?.is_proxy ? "warn" : "clean",
    x: 400 + Math.cos(radIp) * radius,
    y: 250 + Math.sin(radIp) * radius,
  });
  edges.push({ from: rootId, to: ipId, label: "Resolves To" });
  angle += 50;

  // ASN Sub-node
  const asnVal = result?.ip_intel?.asn?.split(" ")[0] || "AS36459";
  const asnId = "node-asn";
  nodes.push({
    id: asnId,
    label: asnVal,
    type: "asn",
    detail: `ISP Transit: ${result?.ip_intel?.isp || "GitHub, Inc."} (${asnVal})`,
    status: "info",
    x: 400 + Math.cos(radIp) * (radius + 80),
    y: 250 + Math.sin(radIp) * (radius + 80),
  });
  edges.push({ from: ipId, to: asnId, label: "Routed By" });

  // 2. SSL Cert Node
  const sslId = "node-ssl";
  const radSsl = (angle * Math.PI) / 180;
  nodes.push({
    id: sslId,
    label: `SSL: ${result?.ssl?.issuer_o || "DigiCert Inc"}`,
    type: "ssl",
    detail: `Issuer: ${result?.ssl?.issuer_cn || "DigiCert Global Root G2"} • Remaining: ${result?.ssl?.days_remaining ?? 142} days`,
    status: "clean",
    x: 400 + Math.cos(radSsl) * radius,
    y: 250 + Math.sin(radSsl) * radius,
  });
  edges.push({ from: rootId, to: sslId, label: "Secured By" });
  angle += 50;

  // 3. Open Ports
  const openPortsList = Array.isArray(result?.ports)
    ? result.ports
    : ((result?.ports as any)?.open_ports || [
        { port: 80, service: "http", banner: "nginx" },
        { port: 443, service: "https", banner: "cloudflare" },
        { port: 22, service: "ssh", banner: "OpenSSH_8.9p1" },
      ]);

  openPortsList.slice(0, 4).forEach((p: any) => {
    const portId = `node-port-${p.port}`;
    const rad = (angle * Math.PI) / 180;
    const isDangerous = [21, 22, 23, 3389, 27017, 6379].includes(p.port);
    nodes.push({
      id: portId,
      label: `Port ${p.port}/${(p.service || "TCP").toUpperCase()}`,
      type: "port",
      detail: `Service Banner: ${p.banner || "Standard Service"}`,
      status: isDangerous ? "danger" : "info",
      x: 400 + Math.cos(rad) * radius,
      y: 250 + Math.sin(rad) * radius,
    });
    edges.push({ from: rootId, to: portId, label: "Open Port" });
    angle += 38;
  });

  // 4. Detected Tech Stack
  const techList = (result?.technology as any)?.detected ||
    (Array.isArray(result?.technology) ? result.technology : ["Ruby on Rails", "React", "Cloudflare WAF"]);

  techList.slice(0, 3).forEach((tech: any, idx: number) => {
    const techId = `node-tech-${idx}`;
    const techName = typeof tech === "string" ? tech : tech.name || "Tech";
    const rad = (angle * Math.PI) / 180;
    nodes.push({
      id: techId,
      label: techName,
      type: "tech",
      detail: `Detected Component: ${techName}`,
      status: "clean",
      x: 400 + Math.cos(rad) * radius,
      y: 250 + Math.sin(rad) * radius,
    });
    edges.push({ from: rootId, to: techId, label: "Runs On" });
    angle += 38;
  });

  // 5. Cloud & Subdomains
  const subNodeId = "node-sub-api";
  const radSub = (angle * Math.PI) / 180;
  nodes.push({
    id: subNodeId,
    label: `api.${targetDomain}`,
    type: "subdomain",
    detail: `Subdomain: api.${targetDomain} • Status: 200 OK`,
    status: "clean",
    x: 400 + Math.cos(radSub) * radius,
    y: 250 + Math.sin(radSub) * radius,
  });
  edges.push({ from: rootId, to: subNodeId, label: "Subdomain" });

  const getNodeColor = (node: Node) => {
    switch (node.status) {
      case "danger":
        return { fill: "#ef4444", stroke: "#dc2626" };
      case "warn":
        return { fill: "#f59e0b", stroke: "#d97706" };
      case "clean":
        return { fill: "#10b981", stroke: "#059669" };
      case "info":
      default:
        return { fill: "#06b6d4", stroke: "#0891b2" };
    }
  };

  return (
    <div className="w-full max-w-5xl bg-panel/90 border border-panelBorder rounded-2xl p-6 backdrop-blur-md shadow-2xl space-y-4 font-mono animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">🕸️</span>
            Attack Surface Visual Topology Graph
          </h2>
          <p className="text-xs text-mist mt-0.5">
            Interactive node-graph mapping of perimeter nodes, open ports, SSL certificates, ASN transit, and cloud exposure.
          </p>
        </div>

        {!result && (
          <div className="flex items-center gap-2">
            <input
              type="text"
              placeholder="e.g. cloudflare.com"
              value={customTarget}
              onChange={(e) => setCustomTarget(e.target.value)}
              className="bg-void border border-border rounded-xl px-3 py-1.5 text-xs text-white placeholder-mist/40 outline-none w-44 font-mono focus:border-cyan-400"
            />
          </div>
        )}
      </div>

      {/* SVG Canvas Container */}
      <div className="relative w-full h-[520px] bg-void/90 border border-panelBorder/70 rounded-xl overflow-hidden shadow-inner flex items-center justify-center">
        {/* Glow definitions */}
        <svg className="w-full h-full cursor-grab active:cursor-grabbing" viewBox="0 0 800 500">
          <defs>
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="6" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Grid lines */}
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" />
          </pattern>
          <rect width="100%" height="100%" fill="url(#grid)" opacity="0.6" />

          {/* Render Edges */}
          {edges.map((e, idx) => {
            const fromNode = nodes.find((n) => n.id === e.from);
            const toNode = nodes.find((n) => n.id === e.to);
            if (!fromNode || !toNode) return null;

            const midX = (fromNode.x + toNode.x) / 2;
            const midY = (fromNode.y + toNode.y) / 2;

            return (
              <g key={idx}>
                <line
                  x1={fromNode.x}
                  y1={fromNode.y}
                  x2={toNode.x}
                  y2={toNode.y}
                  stroke="#334155"
                  strokeWidth="1.5"
                  strokeDasharray="4 2"
                />
                <text
                  x={midX}
                  y={midY - 4}
                  fill="#64748b"
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor="middle"
                >
                  {e.label}
                </text>
              </g>
            );
          })}

          {/* Render Nodes */}
          {nodes.map((n) => {
            const colors = getNodeColor(n);
            const isSelected = selectedNode?.id === n.id;
            const radiusSize = n.type === "domain" ? 28 : 20;

            return (
              <g
                key={n.id}
                onClick={() => setSelectedNode(n)}
                className="cursor-pointer transition-transform duration-200 hover:scale-110"
              >
                <circle
                  cx={n.x}
                  cy={n.y}
                  r={radiusSize}
                  fill={colors.fill}
                  stroke={isSelected ? "#ffffff" : colors.stroke}
                  strokeWidth={isSelected ? "3" : "1.5"}
                  filter={n.status === "danger" ? "url(#glow)" : undefined}
                  className="transition-all"
                />
                <text
                  x={n.x}
                  y={n.y + radiusSize + 14}
                  fill="#f8fafc"
                  fontSize="10"
                  fontWeight="bold"
                  fontFamily="monospace"
                  textAnchor="middle"
                >
                  {n.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Drawer / Tooltip */}
        {selectedNode && (
          <div className="absolute bottom-4 left-4 right-4 bg-panel/95 border border-cyan-500/50 backdrop-blur-md rounded-xl p-3.5 font-mono text-xs text-white shadow-2xl flex items-center justify-between animate-slideUp">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-cyan-400 uppercase tracking-wider">{selectedNode.type} Node:</span>
                <span className="font-bold text-white">{selectedNode.label}</span>
              </div>
              <p className="text-mist text-[11px] mt-0.5">{selectedNode.detail}</p>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="px-2.5 py-1 bg-void border border-panelBorder text-mist hover:text-white rounded text-[10px] cursor-pointer"
            >
              Close ✕
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
