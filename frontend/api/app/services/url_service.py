"""
URL Analyzer & Threat Intelligence Service (VirusTotal style).
Inspects URLs for:
- Protocol, domain, path, and parameter decomposition
- Redirect chain & HTTP hop sequence tracking
- Server response status, headers, and content-type
- Phishing, credential harvesting & malware heuristic analysis
- Multi-AV reputation & VirusTotal URL link
"""

import requests
import socket
import base64
from urllib.parse import urlparse, parse_qs
from app.services import virustotal_service

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "wallet", "password", "credential", "auth", "confirm", "billing", "recover"
]


def analyze_url(raw_url: str) -> dict:
    raw_url = raw_url.strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    domain = parsed.netloc.split(":")[0].lower()
    path = parsed.path or "/"
    query_params = parse_qs(parsed.query)

    # 1. Resolve domain IP
    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        pass

    # 2. Trace Redirect Hops & Response Telemetry
    redirect_chain = []
    final_url = raw_url
    status_code = None
    headers = {}
    content_type = "unknown"
    server = "unknown"
    is_accessible = False
    html_preview = ""

    try:
        session = requests.Session()
        resp = session.get(
            raw_url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 ThunderRecon-URL/2.0"},
        )
        is_accessible = True
        status_code = resp.status_code
        final_url = resp.url
        headers = {k.lower(): v for k, v in resp.headers.items()}
        content_type = headers.get("content-type", "unknown")
        server = headers.get("server", "unknown")
        html_preview = resp.text[:1000]

        # Populate redirect history
        if resp.history:
            for idx, r in enumerate(resp.history):
                redirect_chain.append({
                    "hop": idx + 1,
                    "url": r.url,
                    "status_code": r.status_code,
                    "location": r.headers.get("location", ""),
                })
        redirect_chain.append({
            "hop": len(redirect_chain) + 1,
            "url": resp.url,
            "status_code": resp.status_code,
            "location": "Destination",
        })
    except Exception as e:
        redirect_chain.append({
            "hop": 1,
            "url": raw_url,
            "status_code": 0,
            "location": f"Connection Failed: {str(e)[:100]}",
        })

    # 3. Phishing & Malicious Heuristic Checks
    heuristics = []
    risk_score = 0

    # Suspicious keywords in path/params
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in path.lower() or any(kw in str(v).lower() for v in query_params.values())]
    if matched_keywords and not any(trusted in domain for trusted in ["google.com", "microsoft.com", "apple.com", "github.com", "amazon.com"]):
        heuristics.append({
            "type": "Credential Keyword Ingestion",
            "details": f"Path contains sensitive keywords: {', '.join(matched_keywords)}",
            "severity": "Medium",
        })
        risk_score += 20

    # IP address in URL hostname
    if domain.replace(".", "").isdigit():
        heuristics.append({
            "type": "Direct IP Hostname",
            "details": "URL host is a direct IP address rather than a registered domain name.",
            "severity": "High",
        })
        risk_score += 35

    # Multiple subdomains (e.g. login.secure.bank.com.xyz)
    if domain.count(".") >= 4:
        heuristics.append({
            "type": "Excessive Subdomain Depth",
            "details": f"Unusual subdomain hierarchy depth ({domain.count('.')} levels).",
            "severity": "Medium",
        })
        risk_score += 15

    # 4. Multi-AV & VirusTotal Engine Evaluation
    vt_intel = virustotal_service.get_virustotal_report(domain, ip)

    # Base64 URL identifier for VirusTotal GUI lookup
    url_id = base64.urlsafe_b64encode(raw_url.encode()).decode().strip("=")
    vt_url_link = f"https://www.virustotal.com/gui/url/{url_id}"

    mal_count = vt_intel.get("malicious_count", 0)
    risk_rating = "Safe / Low Risk"
    if risk_score >= 50 or mal_count >= 2:
        risk_rating = "High Risk / Malicious"
    elif risk_score >= 25 or mal_count == 1:
        risk_rating = "Suspicious / Review"

    return {
        "raw_url": raw_url,
        "final_url": final_url,
        "scheme": parsed.scheme,
        "domain": domain,
        "path": path,
        "query_params": query_params,
        "ip": ip,
        "status_code": status_code,
        "content_type": content_type,
        "server": server,
        "is_accessible": is_accessible,
        "redirect_hops_count": len(redirect_chain),
        "redirect_chain": redirect_chain,
        "heuristics": heuristics,
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "virustotal": {
            **vt_intel,
            "vt_url_link": vt_url_link,
        },
    }
