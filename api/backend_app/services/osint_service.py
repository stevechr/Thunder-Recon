"""
OSINT Aggregator Service.
Aggregates open-source intelligence from multiple free/no-key sources:
 1. GitHub — public repo search for domain mentions / exposed secrets
 2. Gravatar — email -> avatar/profile presence check
 3. Social presence hints via domain linkage (Google, Twitter, LinkedIn)
 4. Wayback Machine — historical snapshots of a domain
 5. HackerNews — mentions of a domain
 6. DNS-based email/service discovery (MX, TXT for Google Workspace etc.)
"""

import requests
import socket
import dns.resolver
import dns.exception
import hashlib
import re
from typing import Optional
from urllib.parse import quote_plus

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 ThunderRecon/3.5"}


# ---------------------------------------------------------------------------
# Gravatar
# ---------------------------------------------------------------------------

def check_gravatar(email: str) -> dict:
    """Check if an email has a Gravatar profile."""
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{email_hash}.json"
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            entry = data.get("entry", [{}])[0]
            return {
                "found": True,
                "hash": email_hash,
                "display_name": entry.get("displayName"),
                "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}?s=200",
                "profile_url": entry.get("profileUrl"),
                "about_me": entry.get("aboutMe"),
                "accounts": [
                    {"domain": a.get("domain"), "display": a.get("display")}
                    for a in entry.get("accounts", [])
                ],
            }
        return {
            "found": False,
            "hash": email_hash,
            "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}?d=404",
        }
    except Exception:
        return {"found": False, "hash": email_hash, "error": "Could not reach Gravatar"}


# ---------------------------------------------------------------------------
# Wayback Machine
# ---------------------------------------------------------------------------

def check_wayback(domain: str) -> dict:
    """Check Wayback Machine for archived snapshots of a domain."""
    try:
        r = requests.get(
            f"https://archive.org/wayback/available?url={domain}",
            timeout=TIMEOUT,
            headers=HEADERS,
        )
        data = r.json()
        snapshot = data.get("archived_snapshots", {}).get("closest", {})

        # CDX API for total count estimate
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&limit=5&fl=timestamp,original,statuscode&fastLatest=true"
        )
        cdx_r = requests.get(cdx_url, timeout=TIMEOUT, headers=HEADERS)
        recent_pages = []
        if cdx_r.status_code == 200:
            rows = cdx_r.json()
            for row in rows[1:6]:  # Skip header row
                if len(row) >= 3:
                    ts = row[0]
                    recent_pages.append({
                        "timestamp": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}",
                        "url": row[1],
                        "status": row[2],
                        "archive_url": f"https://web.archive.org/web/{ts}/{row[1]}",
                    })

        return {
            "has_snapshots": bool(snapshot.get("available")),
            "closest_snapshot": {
                "available": snapshot.get("available", False),
                "url": snapshot.get("url"),
                "timestamp": snapshot.get("timestamp"),
                "status": snapshot.get("status"),
            } if snapshot else None,
            "recent_pages": recent_pages,
        }
    except Exception as e:
        return {"has_snapshots": False, "error": str(e)}


# ---------------------------------------------------------------------------
# HackerNews Mentions
# ---------------------------------------------------------------------------

def check_hackernews(domain: str) -> dict:
    """Search HackerNews for domain mentions via Algolia API."""
    try:
        r = requests.get(
            f"https://hn.algolia.com/api/v1/search?query={quote_plus(domain)}&tags=story&hitsPerPage=5",
            timeout=TIMEOUT,
            headers=HEADERS,
        )
        data = r.json()
        hits = data.get("hits", [])
        return {
            "total_mentions": data.get("nbHits", 0),
            "recent_stories": [
                {
                    "title": h.get("title"),
                    "url": h.get("url"),
                    "points": h.get("points"),
                    "comments": h.get("num_comments"),
                    "created_at": h.get("created_at"),
                    "hn_url": f"https://news.ycombinator.com/item?id={h.get('objectID')}",
                }
                for h in hits
            ],
        }
    except Exception:
        return {"total_mentions": 0, "recent_stories": []}


# ---------------------------------------------------------------------------
# GitHub Domain Search
# ---------------------------------------------------------------------------

def check_github(domain: str) -> dict:
    """
    Search GitHub code for files mentioning the domain.
    No auth token required for basic search (rate-limited).
    """
    try:
        r = requests.get(
            f"https://api.github.com/search/code?q={quote_plus(domain)}&per_page=5",
            timeout=TIMEOUT,
            headers={
                **HEADERS,
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if r.status_code == 403:
            return {
                "rate_limited": True,
                "message": "GitHub API rate limit reached. Results unavailable without an API token.",
                "results": [],
            }
        if r.status_code != 200:
            return {"results": [], "error": f"GitHub API returned {r.status_code}"}

        data = r.json()
        items = data.get("items", [])
        return {
            "total_results": data.get("total_count", 0),
            "rate_limited": False,
            "results": [
                {
                    "repo": item.get("repository", {}).get("full_name"),
                    "repo_url": item.get("repository", {}).get("html_url"),
                    "file": item.get("name"),
                    "path": item.get("path"),
                    "file_url": item.get("html_url"),
                    "is_public": not item.get("repository", {}).get("private", True),
                }
                for item in items
            ],
        }
    except Exception as e:
        return {"results": [], "error": str(e)}


# ---------------------------------------------------------------------------
# Email-based Service Discovery (DNS TXT)
# ---------------------------------------------------------------------------

def discover_dns_services(domain: str) -> dict:
    """
    Parse TXT and MX records to identify hosted services.
    e.g. Google Workspace, Microsoft 365, Mailchimp, Salesforce, etc.
    """
    SERVICE_FINGERPRINTS = {
        "google": "Google Workspace / Gmail",
        "v=spf1 include:_spf.google.com": "Google Workspace",
        "include:protection.outlook.com": "Microsoft 365 / Exchange Online",
        "include:spf.protection.outlook.com": "Microsoft 365",
        "include:sendgrid.net": "SendGrid Email",
        "include:mailgun.org": "Mailgun",
        "include:amazonses.com": "Amazon SES",
        "include:_spf.mailchimp.com": "Mailchimp",
        "include:mail.zendesk.com": "Zendesk",
        "include:spf.mandrillapp.com": "Mandrill / Mailchimp",
        "zoho": "Zoho Mail",
        "hubspot": "HubSpot",
        "salesforce": "Salesforce",
        "atlassian": "Atlassian / Jira",
        "fastly": "Fastly CDN",
        "stripe": "Stripe",
        "docusign": "DocuSign",
        "asana": "Asana",
        "slack": "Slack",
    }

    txt_records = []
    mx_records = []
    discovered_services = []

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        for rdata in resolver.resolve(domain, "TXT"):
            txt = " ".join(part.decode() if isinstance(part, bytes) else part for part in rdata.strings)
            txt_records.append(txt)

        for rdata in resolver.resolve(domain, "MX"):
            mx_records.append(str(rdata.exchange).rstrip("."))
    except Exception:
        pass

    combined = " ".join(txt_records + mx_records).lower()
    seen = set()
    for fingerprint, service_name in SERVICE_FINGERPRINTS.items():
        if fingerprint.lower() in combined and service_name not in seen:
            discovered_services.append(service_name)
            seen.add(service_name)

    # MX-based service detection
    for mx in mx_records:
        mx_lower = mx.lower()
        if "google.com" in mx_lower and "Google Workspace / Gmail" not in seen:
            discovered_services.append("Google Workspace / Gmail")
            seen.add("Google Workspace / Gmail")
        elif "outlook.com" in mx_lower or "microsoft.com" in mx_lower:
            svc = "Microsoft 365 / Exchange Online"
            if svc not in seen:
                discovered_services.append(svc)
                seen.add(svc)
        elif "amazonses.com" in mx_lower:
            svc = "Amazon SES"
            if svc not in seen:
                discovered_services.append(svc)
                seen.add(svc)
        elif "zoho.com" in mx_lower:
            svc = "Zoho Mail"
            if svc not in seen:
                discovered_services.append(svc)
                seen.add(svc)
        elif "mailgun.org" in mx_lower:
            svc = "Mailgun"
            if svc not in seen:
                discovered_services.append(svc)
                seen.add(svc)

    return {
        "domain": domain,
        "txt_records": txt_records[:10],
        "mx_records": mx_records,
        "discovered_services": discovered_services,
    }


# ---------------------------------------------------------------------------
# Social Presence Hints
# ---------------------------------------------------------------------------

def check_social_presence(domain: str) -> dict:
    """
    Infer likely social media presence from common brand patterns.
    Does lightweight HTTP checks on probable social URLs.
    """
    brand = domain.split(".")[0].lower()
    platforms = [
        {"name": "Twitter/X", "url": f"https://twitter.com/{brand}", "icon": "🐦"},
        {"name": "LinkedIn", "url": f"https://linkedin.com/company/{brand}", "icon": "💼"},
        {"name": "GitHub", "url": f"https://github.com/{brand}", "icon": "🐙"},
        {"name": "Instagram", "url": f"https://instagram.com/{brand}", "icon": "📸"},
        {"name": "Facebook", "url": f"https://facebook.com/{brand}", "icon": "👥"},
        {"name": "YouTube", "url": f"https://youtube.com/@{brand}", "icon": "▶️"},
        {"name": "Reddit", "url": f"https://reddit.com/r/{brand}", "icon": "🔴"},
        {"name": "Medium", "url": f"https://medium.com/@{brand}", "icon": "✍️"},
        {"name": "TikTok", "url": f"https://tiktok.com/@{brand}", "icon": "🎵"},
        {"name": "npm", "url": f"https://npmjs.com/org/{brand}", "icon": "📦"},
        {"name": "PyPI", "url": f"https://pypi.org/user/{brand}", "icon": "🐍"},
        {"name": "Docker Hub", "url": f"https://hub.docker.com/r/{brand}", "icon": "🐳"},
    ]

    results = []
    for p in platforms:
        try:
            r = requests.head(
                p["url"], timeout=4, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 ThunderRecon/3.5"},
            )
            status = r.status_code
            results.append({
                **p,
                "status": status,
                "likely_exists": status < 400,
            })
        except Exception:
            results.append({**p, "status": None, "likely_exists": False})

    return {
        "brand": brand,
        "domain": domain,
        "platforms": results,
        "confirmed_count": sum(1 for r in results if r["likely_exists"]),
    }


# ---------------------------------------------------------------------------
# Main Aggregation
# ---------------------------------------------------------------------------

def run_osint(domain: str, email: Optional[str] = None) -> dict:
    """Aggregate OSINT data for a domain/email target."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    result = {
        "target": domain,
        "email_target": email,
        "wayback": check_wayback(domain),
        "hackernews": check_hackernews(domain),
        "github_exposure": check_github(domain),
        "dns_services": discover_dns_services(domain),
        "social_presence": check_social_presence(domain),
    }

    if email:
        result["gravatar"] = check_gravatar(email)

    return result
