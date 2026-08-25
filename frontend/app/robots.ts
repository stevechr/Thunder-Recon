import { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: ["/api/", "/_next/"],
      },
      {
        userAgent: "Googlebot",
        allow: "/",
        disallow: ["/api/"],
      },
      {
        userAgent: "Bingbot",
        allow: "/",
        disallow: ["/api/"],
      },
      {
        userAgent: "Applebot",
        allow: "/",
        disallow: ["/api/"],
      },
    ],
    sitemap: "https://thunder-recon.vercel.app/sitemap.xml",
    host: "https://thunder-recon.vercel.app",
  };
}
