import { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Thunder Recon — Cyber Threat Intelligence",
    short_name: "ThunderRecon",
    description: "Free OSINT surface reconnaissance, DNSSEC cryptographic auditing, and live cyber threat telemetry platform.",
    start_url: "/",
    display: "standalone",
    background_color: "#060911",
    theme_color: "#00F5D4",
    icons: [
      {
        src: "/favicon.ico",
        sizes: "any",
        type: "image/x-icon",
      },
    ],
  };
}
