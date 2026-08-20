"""
HTTP Security Headers & Security Scorecard Service.
Audits CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, etc.
"""

import requests
from urllib.parse import urlparse

SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "description": "Enforces HTTPS connections and prevents SSL stripping attacks (HSTS).",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
        "score_weight": 20,
    },
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "description": "Restricts sources from which scripts, styles, and images can load to mitigate XSS.",
        "recommendation": "default-src 'self'; script-src 'self'; object-src 'none';",
        "score_weight": 25,
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "description": "Protects against Clickjacking by controlling whether the site can be embedded in iframes.",
        "recommendation": "DENY or SAMEORIGIN",
        "score_weight": 15,
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "description": "Prevents browsers from MIME-sniffing response content types.",
        "recommendation": "nosniff",
        "score_weight": 15,
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "description": "Controls how much referrer information is sent with requests.",
        "recommendation": "strict-origin-when-cross-origin",
        "score_weight": 10,
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "description": "Restricts browser features (camera, microphone, geolocation) accessible to the page.",
        "recommendation": "geolocation=(), camera=(), microphone=()",
        "score_weight": 10,
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "key": "cross-origin-opener-policy",
        "description": "Ensures a top-level document does not share a browsing context group with cross-origin documents.",
        "recommendation": "same-origin",
        "score_weight": 5,
    },
]

def audit_security_headers(target_url: str) -> dict:
    raw_target = target_url.strip()
    if not raw_target.startswith("http://") and not raw_target.startswith("https://"):
        raw_target = "https://" + raw_target

    headers = {}
    status_code = 0
    final_url = raw_target
    server_header = None
    powered_by_header = None

    try:
        resp = requests.get(
            raw_target,
            timeout=7,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThunderRecon-HeaderAuditor/3.0"}
        )
        status_code = resp.status_code
        final_url = resp.url
        headers = {k.lower(): v for k, v in resp.headers.items()}
        server_header = headers.get("server")
        powered_by_header = headers.get("x-powered-by")
    except Exception as e:
        raise ValueError(f"Failed to connect to target URL: {str(e)}")

    results = []
    earned_score = 0
    total_max_score = sum(h["score_weight"] for h in SECURITY_HEADERS)

    for h in SECURITY_HEADERS:
        val = headers.get(h["key"])
        present = val is not None
        if present:
            earned_score += h["score_weight"]

        results.append({
            "header": h["name"],
            "key": h["key"],
            "present": present,
            "value": val or "MISSING",
            "description": h["description"],
            "recommendation": h["recommendation"],
            "weight": h["score_weight"],
        })

    score_percentage = int((earned_score / total_max_score) * 100)

    if score_percentage >= 90:
        grade = "A+"
    elif score_percentage >= 75:
        grade = "A"
    elif score_percentage >= 60:
        grade = "B"
    elif score_percentage >= 40:
        grade = "C"
    elif score_percentage >= 20:
        grade = "D"
    else:
        grade = "F"

    # Information Leakage Warnings
    info_leaks = []
    if server_header:
        info_leaks.append({"header": "Server", "value": server_header, "risk": "Exposes web server implementation details."})
    if powered_by_header:
        info_leaks.append({"header": "X-Powered-By", "value": powered_by_header, "risk": "Exposes backend framework/language details (e.g. PHP/Express)."})

    return {
        "raw_target": raw_target,
        "final_url": final_url,
        "status_code": status_code,
        "score_percentage": score_percentage,
        "grade": grade,
        "headers_audited": results,
        "info_leaks": info_leaks,
        "raw_headers": headers,
    }
