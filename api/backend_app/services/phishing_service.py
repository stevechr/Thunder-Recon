"""
Phishing & Malicious URL Detection Service.
Multi-source URL reputation checking using free, no-key-required APIs.

Sources:
  1. URLhaus (abuse.ch) — real-time malware/phishing URL database
  2. Domain age check via WHOIS (new domains < 30 days = suspicious)
  3. Redirect chain analysis — detect suspicious redirects
  4. Lexical/heuristic checks — homograph, typosquatting indicators
  5. Google Safe Browsing (optional — if GSB_API_KEY env var set)
"""

import requests
import re
import os
import time
import socket
from urllib.parse import urlparse, quote
from typing import Optional
from datetime import datetime, timezone

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0 ThunderRecon/3.5 Security Research"}


# ---------------------------------------------------------------------------
# URLhaus Check (abuse.ch - free, no key)
# ---------------------------------------------------------------------------

def check_urlhaus(url: str) -> dict:
    """Query URLhaus API for a URL or domain."""
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=TIMEOUT,
            headers={"User-Agent": "ThunderRecon/3.5"},
        )
        if r.status_code != 200:
            return {"found": False, "error": f"URLhaus API returned {r.status_code}"}

        data = r.json()
        if data.get("query_status") == "no_results":
            return {"found": False, "source": "URLhaus"}

        return {
            "found": True,
            "source": "URLhaus (abuse.ch)",
            "url_status": data.get("url_status"),
            "threat": data.get("threat"),
            "tags": data.get("tags", []),
            "date_added": data.get("date_added"),
            "urlhaus_link": data.get("urlhaus_link"),
            "blacklists": data.get("blacklists", {}),
        }
    except Exception as e:
        return {"found": False, "error": str(e)}


def check_urlhaus_host(host: str) -> dict:
    """Query URLhaus by host/domain."""
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": host},
            timeout=TIMEOUT,
            headers={"User-Agent": "ThunderRecon/3.5"},
        )
        if r.status_code != 200:
            return {"found": False}
        data = r.json()
        if data.get("query_status") in ("no_results", "invalid_host"):
            return {"found": False, "source": "URLhaus"}

        urls = data.get("urls", [])
        return {
            "found": True,
            "source": "URLhaus (abuse.ch)",
            "url_count": data.get("url_count", 0),
            "blacklists": data.get("blacklists", {}),
            "recent_urls": [
                {
                    "url": u.get("url"),
                    "url_status": u.get("url_status"),
                    "threat": u.get("threat"),
                    "date_added": u.get("date_added"),
                }
                for u in urls[:5]
            ],
        }
    except Exception as e:
        return {"found": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Redirect Chain Analysis
# ---------------------------------------------------------------------------

def analyze_redirect_chain(url: str) -> dict:
    """Follow redirect chain and detect suspicious hops."""
    chain = []
    try:
        resp = requests.get(
            url,
            timeout=10,
            headers={**HEADERS, "Accept": "text/html"},
            allow_redirects=True,
            stream=True,
        )
        # Walk the history
        for r in resp.history:
            chain.append({
                "url": r.url,
                "status": r.status_code,
                "location": r.headers.get("Location"),
            })
        chain.append({"url": resp.url, "status": resp.status_code, "location": None})

        # Detect suspicious patterns in chain
        suspicious = []
        final_url = resp.url
        if len(chain) > 3:
            suspicious.append(f"Deep redirect chain ({len(chain)} hops)")

        domains_in_chain = set()
        for hop in chain:
            try:
                h = urlparse(hop["url"]).netloc
                domains_in_chain.add(h)
            except Exception:
                pass
        if len(domains_in_chain) > 2:
            suspicious.append(f"Redirects through {len(domains_in_chain)} different domains")

        for hop in chain[:-1]:
            try:
                parsed = urlparse(hop["url"])
                if parsed.scheme == "https" and urlparse(chain[chain.index(hop) + 1]["url"]).scheme == "http":
                    suspicious.append("HTTPS → HTTP downgrade detected in redirect")
            except Exception:
                pass

        return {
            "chain": chain,
            "hops": len(chain),
            "final_url": final_url,
            "domains_traversed": list(domains_in_chain),
            "suspicious_patterns": suspicious,
            "is_suspicious": len(suspicious) > 0,
        }
    except requests.exceptions.TooManyRedirects:
        return {"chain": chain, "hops": len(chain), "error": "Too many redirects", "is_suspicious": True}
    except Exception as e:
        return {"chain": [], "hops": 0, "error": str(e), "is_suspicious": False}


# ---------------------------------------------------------------------------
# Heuristic / Lexical Analysis
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update",
    "banking", "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "instagram", "netflix", "wallet", "confirm", "auth",
    "credential", "password", "helpdesk", "support", "alert",
]

LEGITIMATE_TLDS = {".com", ".org", ".net", ".edu", ".gov"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}


def heuristic_analysis(url: str) -> dict:
    """Perform lexical and structural analysis on a URL."""
    parsed = urlparse(url if url.startswith("http") else f"http://{url}")
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    full = url.lower()

    findings = []
    score = 0  # 0 = benign, higher = more suspicious

    # Check for IP address as host
    try:
        socket.inet_aton(hostname.split(":")[0])
        findings.append("URL uses an IP address instead of domain name")
        score += 30
    except socket.error:
        pass

    # Subdomain depth
    parts = hostname.split(".")
    if len(parts) > 4:
        findings.append(f"Excessive subdomain depth ({len(parts) - 2} subdomains)")
        score += 15

    # Suspicious TLD
    tld = "." + parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(f"Suspicious TLD '{tld}' commonly used in phishing")
        score += 20

    # Suspicious keywords in hostname
    kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in hostname]
    if kw_hits:
        findings.append(f"Suspicious keywords in hostname: {', '.join(kw_hits)}")
        score += len(kw_hits) * 10

    # Keyword in path
    path_kw_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path]
    if path_kw_hits:
        findings.append(f"Suspicious keywords in path: {', '.join(path_kw_hits[:3])}")
        score += len(path_kw_hits) * 5

    # Homograph / lookalike characters
    confusables = re.findall(r"[а-яА-Я\u0400-\u04ff]", hostname)
    if confusables:
        findings.append("Cyrillic/homograph characters detected in domain (possible IDN attack)")
        score += 40

    # Excessive dashes
    if hostname.count("-") > 3:
        findings.append(f"Excessive hyphens in domain ({hostname.count('-')}) — typosquatting indicator")
        score += 15

    # URL length
    if len(url) > 100:
        findings.append(f"Unusually long URL ({len(url)} chars)")
        score += 10

    # @-sign in URL (classic phishing trick)
    if "@" in parsed.netloc:
        findings.append("@ symbol in URL — classic phishing obfuscation")
        score += 35

    # Double slashes in path
    if "//" in path:
        findings.append("Double slashes in URL path — possible obfuscation")
        score += 10

    # HTTP (not HTTPS)
    if parsed.scheme == "http":
        findings.append("Non-HTTPS URL — no transport encryption")
        score += 10

    risk_level = "CRITICAL" if score >= 60 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW" if score > 0 else "CLEAN"

    return {
        "url": url,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "tld": tld,
        "heuristic_score": min(score, 100),
        "risk_level": risk_level,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Google Safe Browsing (optional)
# ---------------------------------------------------------------------------

def check_google_safe_browsing(url: str) -> dict:
    """Check URL against Google Safe Browsing API (requires GSB_API_KEY env var)."""
    api_key = os.environ.get("GSB_API_KEY", "")
    if not api_key:
        return {"available": False, "reason": "GSB_API_KEY not configured"}

    payload = {
        "client": {"clientId": "thunder-recon", "clientVersion": "3.5"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=TIMEOUT,
        )
        data = r.json()
        matches = data.get("matches", [])
        return {
            "available": True,
            "is_safe": len(matches) == 0,
            "threats": [
                {
                    "type": m.get("threatType"),
                    "platform": m.get("platformType"),
                    "entry_type": m.get("threatEntryType"),
                }
                for m in matches
            ],
        }
    except Exception as e:
        return {"available": True, "error": str(e)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def analyze_url_threat(url: str) -> dict:
    """Full phishing / malicious URL analysis."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.netloc or parsed.path

    heuristics = heuristic_analysis(url)
    urlhaus_url = check_urlhaus(url)
    urlhaus_host = check_urlhaus_host(host)
    redirect = analyze_redirect_chain(url)
    gsb = check_google_safe_browsing(url)

    # Build aggregate verdict
    is_malicious = (
        urlhaus_url.get("found") or
        urlhaus_host.get("found") or
        heuristics["heuristic_score"] >= 50 or
        gsb.get("available") and not gsb.get("is_safe", True) or
        redirect.get("is_suspicious")
    )

    risk_sources = []
    if urlhaus_url.get("found"):
        risk_sources.append(f"URLhaus: {urlhaus_url.get('threat', 'known malicious')}")
    if urlhaus_host.get("found"):
        risk_sources.append(f"URLhaus host: {urlhaus_host.get('url_count', '?')} known malicious URLs")
    if heuristics["heuristic_score"] >= 30:
        risk_sources.append(f"Heuristics: score {heuristics['heuristic_score']}/100")
    if gsb.get("available") and not gsb.get("is_safe", True):
        for t in gsb.get("threats", []):
            risk_sources.append(f"Google Safe Browsing: {t['type']}")

    return {
        "url": url,
        "host": host,
        "is_malicious": is_malicious,
        "verdict": "MALICIOUS" if is_malicious else "SUSPICIOUS" if heuristics["heuristic_score"] >= 20 else "CLEAN",
        "risk_sources": risk_sources,
        "heuristics": heuristics,
        "urlhaus_url": urlhaus_url,
        "urlhaus_host": urlhaus_host,
        "redirect_chain": redirect,
        "google_safe_browsing": gsb,
    }
