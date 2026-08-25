import { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = "https://thunder-recon.vercel.app";
  const now = new Date().toISOString();

  const engines = [
    "",
    "?mode=domain",
    "?mode=scorecard",
    "?mode=subdomains",
    "?mode=dns",
    "?mode=ssl",
    "?mode=headers",
    "?mode=whois",
    "?mode=ip",
    "?mode=sandbox",
    "?mode=pwned",
    "?mode=cve",
    "?mode=email",
    "?mode=attack_map",
    "?mode=topology",
    "?mode=toolkit",
    "?mode=report",
  ];

  return engines.map((route, index) => ({
    url: `${baseUrl}/${route}`,
    lastModified: now,
    changeFrequency: index === 0 ? "hourly" : "daily",
    priority: index === 0 ? 1.0 : 0.85,
  }));
}
