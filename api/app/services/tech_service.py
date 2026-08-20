"""
Lightweight web technology + security header detection.
Uses response headers and simple body signatures — no third-party API key
required. Swap in a Wappalyzer-based detector later for deeper fingerprinting.
"""
import re
import requests

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

CMS_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r'name="generator" content="WordPress'],
    "Joomla": [r"/media/jui/", r'name="generator" content="Joomla'],
    "Drupal": [r"sites/default/files", r'name="generator" content="Drupal'],
    "Shopify": [r"cdn\.shopify\.com"],
    "Wix": [r"static\.wixstatic\.com"],
    "Squarespace": [r"static1\.squarespace\.com"],
}


def analyze(domain: str) -> dict:
    result = {
        "server": None,
        "powered_by": None,
        "cms": [],
        "cdn": None,
        "security_headers": {},
        "status_code": None,
        "error": None,
    }
    for scheme in ("https://", "http://"):
        try:
            resp = requests.get(
                f"{scheme}{domain}",
                timeout=6,
                headers={"User-Agent": "ThunderRecon/1.0 (authorized-scan)"},
                allow_redirects=True,
            )
            result["status_code"] = resp.status_code
            headers = resp.headers

            result["server"] = headers.get("Server")
            result["powered_by"] = headers.get("X-Powered-By")

            for h in SECURITY_HEADERS:
                result["security_headers"][h] = headers.get(h) is not None

            if "cf-ray" in headers or "cloudflare" in headers.get("Server", "").lower():
                result["cdn"] = "Cloudflare"
            elif "x-amz-cf-id" in headers:
                result["cdn"] = "Amazon CloudFront"
            elif "x-akamai" in str(headers).lower():
                result["cdn"] = "Akamai"

            body_sample = resp.text[:20000]
            for cms, patterns in CMS_SIGNATURES.items():
                if any(re.search(p, body_sample, re.IGNORECASE) for p in patterns):
                    result["cms"].append(cms)

            return result
        except requests.RequestException:
            continue

    result["error"] = "Could not reach host over HTTPS or HTTP"
    return result
