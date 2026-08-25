import { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = "https://thunder-recon.vercel.app";
  const now = new Date().toISOString();

  const engines = [
    { path: "", priority: 1.0, changeFrequency: "hourly" as const },
    { path: "?mode=domain", priority: 0.95, changeFrequency: "daily" as const },
    { path: "?mode=scorecard", priority: 0.95, changeFrequency: "daily" as const },
    { path: "?mode=subdomains", priority: 0.9, changeFrequency: "daily" as const },
    { path: "?mode=dns", priority: 0.9, changeFrequency: "daily" as const },
    { path: "?mode=ssl", priority: 0.9, changeFrequency: "daily" as const },
    { path: "?mode=headers", priority: 0.9, changeFrequency: "daily" as const },
    { path: "?mode=whois", priority: 0.9, changeFrequency: "daily" as const },
    { path: "?mode=ip", priority: 0.9, changeFrequency: "daily" as const },
    { path: "?mode=sandbox", priority: 0.85, changeFrequency: "daily" as const },
    { path: "?mode=pwned", priority: 0.85, changeFrequency: "daily" as const },
    { path: "?mode=cve", priority: 0.9, changeFrequency: "hourly" as const },
    { path: "?mode=email", priority: 0.85, changeFrequency: "daily" as const },
    { path: "?mode=attack_map", priority: 0.95, changeFrequency: "hourly" as const },
    { path: "?mode=topology", priority: 0.85, changeFrequency: "daily" as const },
    { path: "?mode=toolkit", priority: 0.85, changeFrequency: "weekly" as const },
    { path: "?mode=report", priority: 0.85, changeFrequency: "weekly" as const },
    { path: "?mode=robots", priority: 0.85, changeFrequency: "daily" as const },
    { path: "?mode=dork", priority: 0.85, changeFrequency: "weekly" as const },
    { path: "?mode=waf", priority: 0.85, changeFrequency: "daily" as const },
    { path: "?mode=bucket", priority: 0.85, changeFrequency: "daily" as const },
    { path: "?mode=ports", priority: 0.85, changeFrequency: "daily" as const },
    { path: "?mode=mail_headers", priority: 0.8, changeFrequency: "weekly" as const },
    { path: "?mode=mitre", priority: 0.8, changeFrequency: "weekly" as const },
  ];

  return engines.map((engine) => ({
    url: engine.path ? `${baseUrl}/${engine.path}` : baseUrl,
    lastModified: now,
    changeFrequency: engine.changeFrequency,
    priority: engine.priority,
  }));
}
