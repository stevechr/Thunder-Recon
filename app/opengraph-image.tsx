import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Thunder Recon — Advanced OSINT & Cyber Threat Intelligence Platform";
export const size = {
  width: 1200,
  height: 630,
};
export const contentType = "image/png";

export default async function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          height: "100%",
          width: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-start",
          justifyContent: "space-between",
          backgroundColor: "#060911",
          backgroundImage:
            "radial-gradient(circle at 25% 25%, rgba(0, 245, 212, 0.15), transparent 45%), radial-gradient(circle at 75% 75%, rgba(56, 189, 248, 0.15), transparent 45%)",
          padding: "60px 70px",
          fontFamily: "sans-serif",
          color: "white",
          border: "2px solid rgba(0, 245, 212, 0.3)",
        }}
      >
        {/* Top Badge */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
            backgroundColor: "rgba(255, 255, 255, 0.05)",
            border: "1px solid rgba(0, 245, 212, 0.3)",
            padding: "8px 18px",
            borderRadius: "9999px",
          }}
        >
          <div
            style={{
              width: "12px",
              height: "12px",
              borderRadius: "50%",
              backgroundColor: "#00F5D4",
              boxShadow: "0 0 12px #00F5D4",
            }}
          />
          <span style={{ fontSize: "16px", fontWeight: "600", color: "#00F5D4", letterSpacing: "1px" }}>
            THUNDER RECON • GLOBAL THREAT INTELLIGENCE
          </span>
        </div>

        {/* Center Main Title */}
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <h1
            style={{
              fontSize: "64px",
              fontWeight: "800",
              margin: 0,
              lineHeight: 1.1,
              letterSpacing: "-1px",
              color: "#FFFFFF",
            }}
          >
            Surface Intelligence &amp;
            <br />
            <span
              style={{
                background: "linear-gradient(90deg, #00F5D4, #38BDF8, #818CF8)",
                backgroundClip: "text",
                color: "transparent",
              }}
            >
              Cyber Threat Forensics
            </span>
          </h1>
          <p style={{ fontSize: "22px", color: "#94A3B8", margin: 0, maxWidth: "900px" }}>
            Free all-in-one OSINT surface discovery, DNSSEC validator, live global attack radar, and automated defense posture scoring.
          </p>
        </div>

        {/* Bottom Feature Tags */}
        <div style={{ display: "flex", gap: "14px", width: "100%" }}>
          {["🛡️ Passive OSINT", "🔐 DNSSEC & TLS 1.3", "🌐 22 Country Radar", "⚠️ CISA KEV Feed", "📊 Posture Scorecards"].map(
            (tag) => (
              <div
                key={tag}
                style={{
                  padding: "10px 18px",
                  borderRadius: "12px",
                  backgroundColor: "rgba(255, 255, 255, 0.04)",
                  border: "1px solid rgba(255, 255, 255, 0.1)",
                  fontSize: "15px",
                  fontWeight: "600",
                  color: "#E2E8F0",
                }}
              >
                {tag}
              </div>
            )
          )}
        </div>
      </div>
    ),
    {
      ...size,
    }
  );
}
