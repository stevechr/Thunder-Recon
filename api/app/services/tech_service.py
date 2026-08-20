"""
Web Technology Stack & Fingerprinting Service.
Detects CMS, web server, analytics, JavaScript frameworks, CDN/WAF, and UI libraries.
"""

import requests
import re
from urllib.parse import urlparse

TECH_PATTERNS = [
    # CMS / Frameworks
    {"name": "WordPress", "category": "CMS", "pattern": r"wp-content|wp-includes|wordpress", "icon": "📝"},
    {"name": "Next.js", "category": "Frontend Framework", "pattern": r"_next/static|__NEXT_DATA__", "icon": "⚛️"},
    {"name": "React", "category": "JavaScript Library", "pattern": r"react\.production|react-dom|data-reactroot", "icon": "⚛️"},
    {"name": "Vue.js", "category": "JavaScript Library", "pattern": r"vue\.js|vue\.min\.js|data-v-", "icon": "🟢"},
    {"name": "Shopify", "category": "E-Commerce", "pattern": r"cdn\.shopify\.com|Shopify\.theme", "icon": "🛍️"},
    {"name": "Tailwind CSS", "category": "CSS Framework", "pattern": r"tailwindcss|tailwind", "icon": "🎨"},
    {"name": "Bootstrap", "category": "CSS Framework", "pattern": r"bootstrap\.min\.css|bootstrap\.bundle", "icon": "🎨"},

    # Servers & CDN / WAF
    {"name": "Cloudflare", "category": "CDN & WAF", "pattern": r"cf-ray|cloudflare|__cfduid", "icon": "☁️"},
    {"name": "AWS CloudFront", "category": "CDN", "pattern": r"cloudfront\.net|x-amz-cf-id", "icon": "☁️"},
    {"name": "Akamai", "category": "CDN", "pattern": r"akamai|akamaihd\.net", "icon": "☁️"},
    {"name": "Nginx", "category": "Web Server", "pattern": r"nginx", "icon": "⚙️"},
    {"name": "Apache", "category": "Web Server", "pattern": r"apache", "icon": "⚙️"},

    # Analytics & Utilities
    {"name": "Google Analytics", "category": "Analytics", "pattern": r"google-analytics\.com|gtag|googletagmanager", "icon": "📊"},
    {"name": "Font Awesome", "category": "Icon Library", "pattern": r"fontawesome|font-awesome", "icon": "🔤"},
    {"name": "jQuery", "category": "JavaScript Library", "pattern": r"jquery\.min\.js|jquery-\d", "icon": "📜"},
]

def detect_tech_stack(url: str) -> dict:
    raw_url = url.strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    try:
        resp = requests.get(
            raw_url,
            timeout=7,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThunderRecon-TechDetect/3.0"}
        )
        html_content = resp.text[:150000] # First 150KB
        headers_str = " ".join([f"{k}:{v}" for k, v in resp.headers.items()]).lower()
        cookies_str = " ".join([f"{c.name}={c.value}" for c in resp.cookies]).lower()
        combined_text = (html_content + " " + headers_str + " " + cookies_str).lower()
    except Exception as e:
        raise ValueError(f"Failed to fetch target URL for fingerprinting: {str(e)}")

    detected_tech = []
    detected_names = set()

    for item in TECH_PATTERNS:
        if re.search(item["pattern"], combined_text, re.IGNORECASE):
            if item["name"] not in detected_names:
                detected_names.add(item["name"])
                detected_tech.append({
                    "name": item["name"],
                    "category": item["category"],
                    "icon": item["icon"],
                })

    return {
        "url": raw_url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "total_detected": len(detected_tech),
        "technologies": detected_tech,
    }
