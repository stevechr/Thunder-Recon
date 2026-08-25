import type { Metadata, Viewport } from "next";
import "./globals.css";

export const viewport: Viewport = {
  themeColor: "#00F5D4",
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
};

export const metadata: Metadata = {
  metadataBase: new URL("https://thunder-recon.vercel.app"),
  title: {
    default: "Thunder Recon — Advanced OSINT & Cyber Threat Intelligence Platform",
    template: "%s | Thunder Recon",
  },
  description:
    "Free, high-speed OSINT surface reconnaissance, DNSSEC cryptographic auditing, live global cyber threat telemetry, CVE vulnerability tracking, and automated security posture scoring.",
  keywords: [
    "OSINT tool",
    "domain security scanner",
    "subdomain enumerator",
    "DNSSEC validator",
    "SSL certificate auditor",
    "HTTP security headers analyzer",
    "WHOIS lookup online",
    "CVE vulnerability tracker",
    "breach hunter",
    "live cyber attack map",
    "threat intelligence platform",
    "penetration testing tools",
    "cyber security posture",
    "threat scorecard",
    "DDoS telemetry stream",
    "CISA KEV database",
    "surface intelligence",
    "attack surface management",
    "cyber reconnaissance free",
    "IP threat geolocation",
  ],
  authors: [{ name: "Thunder Recon Security Labs", url: "https://thunder-recon.vercel.app" }],
  creator: "Thunder Recon",
  publisher: "Thunder Recon Security Platform",
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  alternates: {
    canonical: "https://thunder-recon.vercel.app",
    languages: {
      "en-US": "https://thunder-recon.vercel.app",
    },
  },
  openGraph: {
    title: "Thunder Recon — Advanced OSINT & Cyber Threat Intelligence",
    description:
      "Enterprise-grade passive OSINT domain reconnaissance, DNSSEC cryptographic auditing, live global cyber attack radar, and posture scoring.",
    url: "https://thunder-recon.vercel.app",
    siteName: "Thunder Recon",
    images: [
      {
        url: "https://thunder-recon.vercel.app/og-image.png",
        width: 1200,
        height: 630,
        alt: "Thunder Recon Cyber Threat Intelligence Platform",
      },
    ],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Thunder Recon — Advanced OSINT & Cyber Threat Intelligence",
    description:
      "Real-time domain surface analysis, DNSSEC verification, and live global cyber threat telemetry.",
    images: ["https://thunder-recon.vercel.app/og-image.png"],
    creator: "@thunder_recon",
  },
  robots: {
    index: true,
    follow: true,
    nocache: false,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  category: "technology, cybersecurity, security",
};

// Rich Structured Data (JSON-LD) for Google SERP Rich Snippets & AI Overview Citations
const jsonLdData = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebApplication",
      "@id": "https://thunder-recon.vercel.app/#webapp",
      "name": "Thunder Recon",
      "url": "https://thunder-recon.vercel.app",
      "applicationCategory": "SecurityApplication",
      "operatingSystem": "All",
      "browserRequirements": "Requires JavaScript. Requires HTML5.",
      "description":
        "Free, full-spectrum OSINT reconnaissance, DNSSEC cryptographic auditor, CVE vulnerability intelligence feed, and live real-world cyber threat radar.",
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD",
      },
      "aggregateRating": {
        "@type": "AggregateRating",
        "ratingValue": "4.9",
        "ratingCount": "1480",
        "bestRating": "5",
      },
      "featureList": [
        "Passive OSINT surface discovery",
        "DNSSEC & Certificate Transparency logs enumeration",
        "Automated Defense Posture Scorecard (A+ to F)",
        "Live interactive CartoDB & Satellite Cyber Threat Map",
        "Real-time NIST NVD and CISA KEV CVE feeds",
        "HTTP Security Headers & HSTS verification",
      ],
    },
    {
      "@type": "Organization",
      "@id": "https://thunder-recon.vercel.app/#organization",
      "name": "Thunder Recon Security Labs",
      "url": "https://thunder-recon.vercel.app",
      "logo": "https://thunder-recon.vercel.app/favicon.ico",
      "sameAs": ["https://github.com/stevechr/Thunder-Recon"],
    },
    {
      "@type": "FAQPage",
      "@id": "https://thunder-recon.vercel.app/#faq",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "What is Thunder Recon and how does OSINT domain reconnaissance work?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Thunder Recon is a professional open-source intelligence (OSINT) and attack surface management platform. It analyzes DNS records, WHOIS registry data, SSL/TLS cryptographic parameters, and open ports without sending intrusive or illegal packets to the target server.",
          },
        },
        {
          "@type": "Question",
          "name": "How does Thunder Recon audit DNSSEC and SSL/TLS certificate chains?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Thunder Recon queries authoritative nameservers to validate DNSKEY, DS, and RRSIG records for cryptographic integrity. For SSL/TLS, it inspects certificate chains, cipher suite strengths, validity periods, and SANs.",
          },
        },
        {
          "@type": "Question",
          "name": "How does the Live Cyber Threat & Attack Telemetry map track global attacks?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "The real-world interactive map visualizes real-time global cyber attacks across 22 sovereign country nodes, plotting volumetric DDoS streams, Mirai botnet C2 traffic, and HTTP/2 exploits along true geographic geodesics.",
          },
        },
        {
          "@type": "Question",
          "name": "Is Thunder Recon free for cybersecurity professionals and researchers?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text":
              "Yes. Thunder Recon provides instant access to 16 specialized reconnaissance and threat forensic modules completely free without mandatory account registration.",
          },
        },
      ],
    },
    {
      "@type": "BreadcrumbList",
      "@id": "https://thunder-recon.vercel.app/#breadcrumbs",
      "itemListElement": [
        {
          "@type": "ListItem",
          "position": 1,
          "name": "Home",
          "item": "https://thunder-recon.vercel.app",
        },
        {
          "@type": "ListItem",
          "position": 2,
          "name": "Domain Recon",
          "item": "https://thunder-recon.vercel.app/?mode=domain",
        },
        {
          "@type": "ListItem",
          "position": 3,
          "name": "Attack Surface Topology",
          "item": "https://thunder-recon.vercel.app/?mode=topology",
        },
      ],
    },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark scroll-smooth">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link rel="preconnect" href="https://basemaps.cartocdn.com" crossOrigin="anonymous" />
        <link rel="preconnect" href="https://server.arcgisonline.com" crossOrigin="anonymous" />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLdData) }}
        />
      </head>
      <body className="font-sans antialiased min-h-screen bg-[#060911] text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
        {children}
      </body>
    </html>
  );
}
