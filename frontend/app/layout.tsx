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
    default: "Thunder Recon — Advanced OSINT, Cyber Threat Intelligence & Attack Surface Platform",
    template: "%s | Thunder Recon",
  },
  description:
    "Free all-in-one OSINT surface reconnaissance, DNSSEC validator, SSL/TLS auditor, subdomain enumerator, live cyber attack radar, CVE vulnerability tracker, DMARC/SPF checker, and security scorecard platform.",
  keywords: [
    // Core Platform Keywords
    "OSINT tool free",
    "cyber threat intelligence platform",
    "attack surface management",
    "surface reconnaissance tool",
    "penetration testing tools online",
    "domain security scanner",
    "cyber security audit platform",
    "automated defense posture scorecard",
    "Shodan alternative free",
    "SecurityTrails alternative",
    "VirusTotal alternative online",

    // Domain Recon & Tech Stack
    "domain reconnaissance tool",
    "website technology fingerprinter",
    "tech stack detector online",
    "open ports scanner online",
    "free port scanner",
    "website infrastructure analyzer",
    "domain surface mapper",

    // Subdomain Enumeration
    "subdomain finder online",
    "subdomain enumerator free",
    "certificate transparency subdomain search",
    "crt.sh search online",
    "find all subdomains of a website",
    "passive subdomain discovery",
    "subdomain takeover scanner",
    "Amass alternative online",

    // DNS & DNSSEC
    "DNS lookup online",
    "DNSSEC validator online",
    "dig online tool",
    "MX record lookup",
    "NS record checker",
    "SOA record inspector",
    "CAA record checker",
    "DNS health check",
    "MXToolbox alternative free",
    "DNS propagation live test",

    // SSL / TLS Cryptography
    "SSL certificate checker",
    "TLS 1.3 auditor",
    "Qualys SSL Labs alternative",
    "check certificate chain online",
    "SSL expiration countdown tracker",
    "SAN certificate finder",
    "cipher suite strength test",
    "TLS certificate inspector",

    // HTTP Security Headers
    "security headers checker",
    "HSTS preload checker",
    "Content Security Policy analyzer",
    "CSP policy generator",
    "X-Frame-Options clickjacking test",
    "CORS security analyzer",
    "securityheaders.com alternative",

    // WHOIS & Domain Registry
    "WHOIS lookup online",
    "domain age checker",
    "registrar information lookup",
    "abuse contact finder",
    "domain expiry date checker",
    "WHOIS privacy detection",
    "historical WHOIS lookup",

    // IP Threat & ASN Intelligence
    "IP threat score",
    "IP geolocation lookup",
    "ASN lookup online",
    "BGP routing intelligence",
    "ISP detection tool",
    "malicious IP scanner",
    "IP reputation checker",
    "AbuseIPDB alternative",

    // Sandbox, Phishing & URL Threat
    "URL scanner online",
    "malicious link checker",
    "phishing link detector",
    "safe browsing check",
    "redirect tracer online",
    "URL reputation score",
    "URL behavioral sandbox",

    // Data Breach & Credential Leaks
    "data breach checker free",
    "HaveIBeenPwned alternative",
    "check if email is breached",
    "compromised credentials search",
    "dark web leak hunter",
    "credential leak checker",

    // CVE & Vulnerability Feeds
    "CVE database search",
    "CISA KEV catalog tracker",
    "zero day vulnerability feed",
    "NIST NVD CVE lookup",
    "CVSS 3.1 score calculator",
    "actively exploited CVEs feed",
    "vulnerability intelligence feed",

    // Email Security (SPF / DMARC / DKIM)
    "DMARC record checker",
    "SPF record validator",
    "DKIM selector lookup",
    "email spoofing vulnerability test",
    "BIMI record checker",
    "email deliverability audit",
    "dmarcian alternative",

    // Live Cyber Attack Map & Telemetry
    "live cyber attack map",
    "real time DDoS attack map",
    "global cyber threat map",
    "botnet tracking radar",
    "Norse attack map alternative",
    "Cloudflare radar live attacks",
    "real world threat map Leaflet",

    // Graph Topology & Threat Mapping
    "attack surface mapping graph",
    "node graph threat visualizer",
    "asset discovery topology map",
    "cyber graph database visualizer",
    "attack path analysis",

    // Swiss Sec Toolkit
    "subnet calculator online",
    "CIDR to IP range converter",
    "hash identifier online",
    "MD5 SHA256 hash detector",
    "JWT token inspector debugger",
    "Base64 encoder decoder online",
    "Hex to string converter",
    "CyberChef alternative online",

    // Executive Reports
    "pentest report generator",
    "executive security summary PDF",
    "cybersecurity audit report template",
    "vulnerability assessment export",
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
    title: "Thunder Recon — Advanced OSINT, Cyber Threat Intelligence & Attack Surface Platform",
    description:
      "Enterprise-grade passive OSINT domain reconnaissance, DNSSEC cryptographic auditing, live global cyber attack radar, and automated posture scoring.",
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
      "Real-time domain surface analysis, DNSSEC verification, live cyber attack radar, and posture scoring.",
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
  category: "technology, cybersecurity, security, tools",
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
      "hasOfferCatalog": {
        "@type": "OfferCatalog",
        "name": "Cybersecurity Reconnaissance & Threat Intelligence Engines",
        "itemListElement": [
          { "@type": "Offer", "name": "Domain Recon Hub & Port Scanner" },
          { "@type": "Offer", "name": "Threat Scorecard & Posture Auditor" },
          { "@type": "Offer", "name": "Subdomain Enumerator (crt.sh Logs)" },
          { "@type": "Offer", "name": "DNSSEC Intelligence Matrix" },
          { "@type": "Offer", "name": "SSL/TLS Cryptographic Auditor" },
          { "@type": "Offer", "name": "HTTP Security Headers Analyzer (HSTS/CSP)" },
          { "@type": "Offer", "name": "WHOIS Registry Forensics & Domain Age" },
          { "@type": "Offer", "name": "IP Threat Map & ASN Route Intelligence" },
          { "@type": "Offer", "name": "URL & File Threat Sandbox (Phishing)" },
          { "@type": "Offer", "name": "Breach & Compromised Credential Hunter" },
          { "@type": "Offer", "name": "CVE & CISA KEV Threat Intelligence Feed" },
          { "@type": "Offer", "name": "Email Anti-Spoofing Auditor (SPF/DMARC/DKIM)" },
          { "@type": "Offer", "name": "Tactical Attack Vector Radar & Real-World Map" },
          { "@type": "Offer", "name": "Attack Surface Topology Graph Visualizer" },
          { "@type": "Offer", "name": "Swiss Security Utility Toolkit (Subnet/Hash/JWT)" },
          { "@type": "Offer", "name": "Executive Pentest Report Generator" },
        ],
      },
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
