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

export default function AttackGraph({ result }: { result: ScanResult }) {
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  // Generate node positions in an interactive radial layout
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Central Domain Node
  const rootId = "root";
  nodes.push({
    id: rootId,
    label: result.domain,
    type: "domain",
    detail: `Target Domain scanned by ${result.email || "User"}`,
    status: result.risk.score >= 50 ? "danger" : result.risk.score >= 25 ? "warn" : "clean",
    x: 400,
    y: 250,
  });

  let angle = 0;
  const radius = 180;

  // 1. IP Node
  if (result.ip) {
    const ipId = "node-ip";
    const rad = (angle * Math.PI) / 180;
    nodes.push({
      id: ipId,
      label: result.ip,
      type: "ip",
      detail: `IP Geolocation: ${result.ip_intel.city || "Unknown"}, ${result.ip_intel.country || "Unknown"}`,
      status: result.ip_intel.is_proxy ? "warn" : "clean",
      x: 400 + Math.cos(rad) * radius,
      y: 250 + Math.sin(rad) * radius,
    });
    edges.push({ from: rootId, to: ipId, label: "Resolves To" });
    angle += 45;

    // ASN Sub-node
    if (result.ip_intel.asn) {
      const asnId = "node-asn";
      nodes.push({
        id: asnId,
        label: result.ip_intel.asn.split(" ")[0] || "ASN",
        type: "asn",
        detail: `ISP: ${result.ip_intel.isp || "Unknown"} (${result.ip_intel.asn})`,
        status: "info",
        x: 400 + Math.cos(rad) * (radius + 80),
        y: 250 + Math.sin(rad) * (radius + 80),
      });
      edges.push({ from: ipId, to: asnId, label: "Routed By" });
    }
  }

  // 2. SSL Cert Node
  if (result.ssl && result.ssl.subject_cn) {
    const sslId = "node-ssl";
    const rad = (angle * Math.PI) / 180;
    nodes.push({
      id: sslId,
      label: `SSL: ${result.ssl.issuer_o || "Valid Cert"}`,
      type: "ssl",
      detail: `Issuer: ${result.ssl.issuer_cn || "TLS Issuer"} • Days Left: ${result.ssl.days_remaining ?? "N/A"}`,
      status: (result.ssl.days_remaining ?? 99) < 14 ? "warn" : "clean",
      x: 400 + Math.cos(rad) * radius,
      y: 250 + Math.sin(rad) * radius,
    });
    edges.push({ from: rootId, to: sslId, label: "Secured By" });
    angle += 45;
  }

  // 3. Open Ports
  const openPortsList = Array.isArray(result.ports) ? result.ports : ((result.ports as any)?.open_ports || []);
  if (openPortsList.length > 0) {
    openPortsList.slice(0, 4).forEach((p: any) => {
      const portId = `node-port-${p.port}`;
      const rad = (angle * Math.PI) / 180;
      const isDangerous = [21, 22, 23, 3389, 27017, 6379].includes(p.port);
      nodes.push({
        id: portId,
        label: `Port ${p.port}/${(p.service || "TCP").toUpperCase()}`,
        type: "port",
        detail: `Service Banner: ${p.banner || "No Banner"}`,
        status: isDangerous ? "danger" : "info",
        x: 400 + Math.cos(rad) * radius,
        y: 250 + Math.sin(rad) * radius,
      });
      edges.push({ from: rootId, to: portId, label: "Open Port" });
      angle += 35;
    });
  }

  // 4. Detected Tech Stack
  const techList = (result.technology as any)?.detected || (Array.isArray(result.technology) ? result.technology : []);
  if (Array.isArray(techList) && techList.length > 0) {
    techList.slice(0, 3).forEach((tech: any, idx: number) => {
      const techId = `node-tech-${idx}`;
      const rad = (angle * Math.PI) / 180;
      nodes.push({
        id: techId,
        label: tech.name,
        type: "tech",
        detail: `Category: ${tech.category} (Confidence: ${tech.confidence}%)`,
        status: "info",
        x: 400 + Math.cos(rad) * radius,
        y: 250 + Math.sin(rad) * radius,
      });
      edges.push({ from: rootId, to: techId, label: "Stack Tech" });
      angle += 40;
    });
  }

  // 5. Risk Score Node
  const riskId = "node-risk";
  const rad = (angle * Math.PI) / 180;
  nodes.push({
    id: riskId,
    label: `Risk: ${result.risk.score}/100`,
    type: "risk",
    detail: `Threat Level: ${result.risk.rating} • ${result.risk.findings.length} Anomalies Flagged`,
    status: result.risk.score >= 50 ? "danger" : result.risk.score >= 25 ? "warn" : "clean",
    x: 400 + Math.cos(rad) * radius,
    y: 250 + Math.sin(rad) * radius,
  });
  edges.push({ from: rootId, to: riskId, label: "Threat Level" });

  const getNodeColor = (n: Node) => {
    if (n.status === "danger") return { fill: "#f43f5e", stroke: "#fb7185", text: "#ffffff" };
    if (n.status === "warn") return { fill: "#f59e0b", stroke: "#fbbf24", text: "#ffffff" };
    if (n.type === "domain") return { fill: "#06b6d4", stroke: "#22d3ee", text: "#ffffff" };
    if (n.type === "ip") return { fill: "#8b5cf6", stroke: "#a78bfa", text: "#ffffff" };
    if (n.type === "ssl") return { fill: "#10b981", stroke: "#34d399", text: "#ffffff" };
    if (n.type === "port") return { fill: "#ec4899", stroke: "#f472b6", text: "#ffffff" };
    return { fill: "#334155", stroke: "#64748b", text: "#e2e8f0" };
  };

  return (
    <div className="bg-panel border border-panelBorder rounded-2xl p-5 shadow-xl space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-signal border border-cyan-500/30">
            INTERACTIVE GRAPH TOPOLOGY
          </span>
          <h3 className="font-display text-lg font-bold text-white mt-1">
            🕸️ Attack Surface Node Map
          </h3>
        </div>
        <div className="flex gap-3 text-[11px] font-mono text-mist">
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-cyan-signal inline-block" /> Domain</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block" /> IP / ASN</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> SSL</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" /> Open Ports</span>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full overflow-hidden bg-void/90 border border-panelBorder rounded-xl p-2 min-h-[380px] flex items-center justify-center">
        <svg viewBox="0 0 800 500" className="w-full h-full max-h-[460px] select-none">
          <defs>
            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

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
            const radiusSize = n.type === "domain" ? 28 : 22;

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
          <div className="absolute bottom-4 left-4 right-4 bg-panel/95 border border-cyan-signal/50 backdrop-blur-md rounded-xl p-3.5 font-mono text-xs text-white shadow-2xl flex items-center justify-between animate-slideUp">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-cyan-signal uppercase tracking-wider">{selectedNode.type} Node:</span>
                <span className="font-bold text-white">{selectedNode.label}</span>
              </div>
              <p className="text-mist text-[11px] mt-0.5">{selectedNode.detail}</p>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="px-2.5 py-1 bg-void border border-panelBorder text-mist hover:text-white rounded text-[10px]"
            >
              Close ✕
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
