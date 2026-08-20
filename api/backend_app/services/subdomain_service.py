"""
Subdomain Enumeration Engine.

Dual-source discovery:
 1. Passive  — Certificate Transparency logs via crt.sh
 2. Active   — Concurrent DNS brute-force over a curated wordlist
 3. Live/Dead probe — HEAD request per discovered subdomain
 4. Cloud Takeover detection — CNAME pointing to unclaimed services
"""

import socket
import concurrent.futures
import requests
import dns.resolver
import dns.exception
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TIMEOUT = 4

WORDLIST = [
    "www", "mail", "app", "api", "api2", "dev", "staging", "stage", "beta",
    "alpha", "test", "uat", "qa", "preprod", "preview", "demo", "sandbox",
    "admin", "panel", "portal", "dashboard", "console", "mgmt", "management",
    "cpanel", "webmail", "autodiscover", "autoconfig", "mx", "smtp", "imap",
    "pop", "pop3", "ftp", "sftp", "ssh", "vpn", "remote", "rdp",
    "cdn", "media", "static", "assets", "img", "images", "video", "upload",
    "status", "health", "monitor", "grafana", "prometheus", "kibana", "elk",
    "git", "gitlab", "github", "bitbucket", "jira", "confluence", "wiki",
    "jenkins", "ci", "cd", "build", "deploy", "sonar", "nexus",
    "auth", "login", "sso", "oauth", "id", "identity", "accounts", "users",
    "blog", "docs", "help", "support", "kb", "forum", "community",
    "shop", "store", "pay", "billing", "invoice", "checkout", "cart",
    "api-v2", "v1", "v2", "v3", "graphql", "ws", "websocket", "wss",
    "internal", "intranet", "corp", "office", "private", "secure", "vault",
    "analytics", "tracking", "pixel", "metrics", "data",
    "mobile", "m", "ios", "android", "app2",
    "backup", "bak", "old", "legacy", "archive",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "gateway", "proxy", "edge", "lb", "loadbalancer", "nginx",
    "dev2", "test2", "staging2", "prod", "production",
]

# CNAME fingerprints that indicate a potential subdomain takeover
TAKEOVER_CNAMES = {
    "amazonaws.com": "AWS S3 / Elastic Beanstalk",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "heroku.com": "Heroku",
    "herokussl.com": "Heroku SSL",
    "herokudns.com": "Heroku DNS",
    "github.io": "GitHub Pages",
    "githubusercontent.com": "GitHub",
    "pages.dev": "Cloudflare Pages",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "vercel.app": "Vercel",
    "now.sh": "Vercel (now.sh)",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure Cloud",
    "azureedge.net": "Azure CDN",
    "trafficmanager.net": "Azure Traffic Manager",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "bigcartel.com": "Big Cartel",
    "squarespace.com": "Squarespace",
    "squarespacedns.com": "Squarespace DNS",
    "tumblr.com": "Tumblr",
    "wpengine.com": "WP Engine",
    "kinsta.com": "Kinsta",
    "readthedocs.io": "ReadTheDocs",
    "surge.sh": "Surge.sh",
    "firebaseapp.com": "Firebase",
    "web.app": "Firebase Hosting",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "helpscoutdocs.com": "HelpScout",
    "ghost.io": "Ghost",
    "webflow.io": "Webflow",
    "readme.io": "ReadMe",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_ip(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _get_cname(host: str) -> Optional[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT
        answers = resolver.resolve(host, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


def _check_takeover(cname: Optional[str]) -> Optional[str]:
    if not cname:
        return None
    cname_lower = cname.lower()
    for fingerprint, service in TAKEOVER_CNAMES.items():
        if fingerprint in cname_lower:
            return service
    return None


def _http_probe(host: str) -> dict:
    """Probe HTTP/HTTPS and return status, redirect target, and server."""
    result = {"status": None, "https": False, "redirect": None, "server": None}
    for scheme in ("https", "http"):
        try:
            r = requests.head(
                f"{scheme}://{host}",
                timeout=TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 ThunderRecon/3.5"},
            )
            result["status"] = r.status_code
            result["https"] = scheme == "https"
            result["server"] = r.headers.get("Server", r.headers.get("x-powered-by"))
            loc = r.headers.get("Location")
            if loc:
                result["redirect"] = loc
            return result
        except Exception:
            continue
    return result


def _probe_subdomain(sub: str, parent: str) -> dict:
    """Full probe for a single subdomain candidate."""
    fqdn = f"{sub}.{parent}"
    ip = _resolve_ip(fqdn)
    if not ip:
        return {"subdomain": fqdn, "resolved": False}

    cname = _get_cname(fqdn)
    takeover_candidate = _check_takeover(cname)
    http_info = _http_probe(fqdn)

    return {
        "subdomain": fqdn,
        "ip": ip,
        "resolved": True,
        "cname": cname,
        "takeover_candidate": takeover_candidate,
        "http_status": http_info["status"],
        "https": http_info["https"],
        "redirect": http_info["redirect"],
        "server": http_info["server"],
        "source": "brute",
    }


# ---------------------------------------------------------------------------
# Primary Enumeration Functions
# ---------------------------------------------------------------------------

def passive_crt_sh(domain: str) -> list[str]:
    """Fetch subdomains from crt.sh Certificate Transparency logs."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "ThunderRecon/3.5"},
        )
        if r.status_code != 200:
            return []
        entries = r.json()
        names = set()
        for entry in entries:
            raw = entry.get("name_value", "")
            for name in raw.splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    names.add(name)
        return sorted(names)
    except Exception:
        return []


def enumerate_subdomains(domain: str, max_workers: int = 40) -> dict:
    """
    Full subdomain enumeration:
      1. Passive discovery via crt.sh
      2. Active brute-force via wordlist + DNS resolution
      3. HTTP live probe per live subdomain
      4. Takeover candidate flagging
    """
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    # --- Phase 1: Passive crt.sh ---
    passive_names = passive_crt_sh(domain)

    # Combine passive names with wordlist-generated candidates
    all_candidates = set()
    for name in passive_names:
        # Only include direct subdomains, not deeply nested ones
        parts = name.replace(f".{domain}", "").split(".")
        sub = parts[-1] if parts else name
        all_candidates.add(sub)

    for word in WORDLIST:
        all_candidates.add(word)

    # Add any full passive names directly to probe list
    direct_fqdns = [n for n in passive_names if n != domain]

    # --- Phase 2: Concurrent DNS resolution + HTTP probe ---
    results = []
    seen_fqdns = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Brute-force wordlist candidates
        brute_futures = {
            executor.submit(_probe_subdomain, sub, domain): sub
            for sub in all_candidates
        }

        for future in concurrent.futures.as_completed(brute_futures, timeout=60):
            try:
                result = future.result()
                if result.get("resolved"):
                    fqdn = result["subdomain"]
                    if fqdn not in seen_fqdns:
                        seen_fqdns.add(fqdn)
                        result["source"] = "brute"
                        results.append(result)
            except Exception:
                pass

    # Add passive CT results that weren't hit by brute-force
    for fqdn in direct_fqdns:
        if fqdn not in seen_fqdns:
            ip = _resolve_ip(fqdn)
            if ip:
                cname = _get_cname(fqdn)
                http_info = _http_probe(fqdn)
                results.append({
                    "subdomain": fqdn,
                    "ip": ip,
                    "resolved": True,
                    "cname": cname,
                    "takeover_candidate": _check_takeover(cname),
                    "http_status": http_info["status"],
                    "https": http_info["https"],
                    "redirect": http_info["redirect"],
                    "server": http_info["server"],
                    "source": "crt.sh",
                })
                seen_fqdns.add(fqdn)

    # Sort: live HTTPS first, then HTTP, then others
    results.sort(key=lambda r: (
        0 if r.get("takeover_candidate") else 1,
        0 if r.get("https") else 1,
        r["subdomain"],
    ))

    takeover_count = sum(1 for r in results if r.get("takeover_candidate"))
    live_count = sum(1 for r in results if r.get("http_status") and r["http_status"] < 400)

    return {
        "domain": domain,
        "total_discovered": len(results),
        "live_count": live_count,
        "takeover_candidates": takeover_count,
        "passive_ct_names": len(passive_names),
        "wordlist_size": len(WORDLIST),
        "subdomains": results,
    }
