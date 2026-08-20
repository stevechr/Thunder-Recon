"""
Robots.txt & Sitemap Intelligence Service.
Fetches and parses robots.txt and sitemap.xml from a target domain.

Capabilities:
  1. Full robots.txt parsing — all Disallow/Allow rules, User-agents, Sitemaps
  2. Sensitive path detection — flags exposed admin/backup/API paths
  3. Sitemap parsing — extract all URLs from sitemap.xml / sitemap_index.xml
  4. Active probing — HEAD-checks interesting Disallowed paths
  5. common sensitive path probing — /.env, /backup.zip, /phpinfo.php etc.
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from typing import Optional
import xml.etree.ElementTree as ET

TIMEOUT = 8
HEADERS = {
    "User-Agent": "Mozilla/5.0 ThunderRecon/3.5 Security Research",
    "Accept": "text/plain,text/html,application/xml,*/*",
}

SENSITIVE_PATTERNS = [
    r"/admin", r"/administrator", r"/wp-admin", r"/dashboard",
    r"/panel", r"/console", r"/manager",
    r"/backup", r"/bak", r"/old", r"/archive", r"\.bak$", r"\.zip$", r"\.tar",
    r"/api", r"/graphql", r"/swagger", r"/api-docs", r"/openapi",
    r"/\.env", r"/\.git", r"/\.htaccess", r"/\.htpasswd",
    r"/config", r"/settings", r"/setup", r"/install",
    r"/logs?", r"/debug", r"/trace",
    r"/phpinfo", r"/test", r"/server-status", r"/server-info",
    r"/private", r"/internal", r"/secret",
    r"/upload", r"/uploads", r"/files", r"/data",
    r"/db", r"/database", r"/mysql", r"/phpmyadmin",
]

COMMON_SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/.htaccess", "/backup.zip", "/backup.tar.gz",
    "/config.php", "/wp-config.php", "/database.sql", "/phpinfo.php",
    "/admin", "/administrator", "/admin/login", "/wp-admin/",
    "/api/v1", "/api/v2", "/graphql", "/swagger-ui.html", "/openapi.json",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/sitemap.xml", "/robots.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/package.json", "/composer.json", "/Makefile", "/Dockerfile",
    "/debug", "/test", "/console", "/logs/",
]


def _fetch(url: str) -> Optional[requests.Response]:
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
        return r
    except Exception:
        return None


def _head(url: str) -> Optional[dict]:
    try:
        r = requests.head(url, timeout=5, headers=HEADERS, allow_redirects=True)
        return {"status": r.status_code, "content_type": r.headers.get("Content-Type", ""), "server": r.headers.get("Server", "")}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Robots.txt Parser
# ---------------------------------------------------------------------------

def parse_robots(domain: str) -> dict:
    """Fetch and parse robots.txt."""
    url = f"https://{domain}/robots.txt"
    r = _fetch(url)

    # Try HTTP if HTTPS fails
    if not r or r.status_code != 200:
        url = f"http://{domain}/robots.txt"
        r = _fetch(url)

    if not r or r.status_code != 200:
        return {
            "found": False,
            "url": url,
            "error": f"HTTP {r.status_code if r else 'unreachable'}",
            "rules": [],
            "sitemaps": [],
            "sensitive_paths": [],
        }

    content = r.text
    lines = content.splitlines()

    rules = []
    current_agent = "*"
    sitemaps = []
    current_rules = []

    def flush_agent():
        if current_rules:
            rules.append({"user_agent": current_agent, "rules": current_rules.copy()})

    for line in lines:
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "user-agent":
                flush_agent()
                current_agent = value
                current_rules = []
            elif key == "disallow":
                current_rules.append({"type": "Disallow", "path": value})
            elif key == "allow":
                current_rules.append({"type": "Allow", "path": value})
            elif key == "sitemap":
                sitemaps.append(value)
            elif key == "crawl-delay":
                current_rules.append({"type": "CrawlDelay", "path": value})

    flush_agent()

    # Collect all disallowed paths
    all_disallowed = []
    for agent_block in rules:
        for rule in agent_block["rules"]:
            if rule["type"] == "Disallow" and rule["path"]:
                all_disallowed.append(rule["path"])

    # Flag sensitive paths
    sensitive_paths = []
    for path in all_disallowed:
        for pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                sensitive_paths.append(path)
                break

    return {
        "found": True,
        "url": url,
        "raw": content[:3000],
        "rules": rules,
        "sitemaps": sitemaps,
        "total_disallowed": len(all_disallowed),
        "all_disallowed_paths": all_disallowed[:50],
        "sensitive_paths": list(set(sensitive_paths)),
    }


# ---------------------------------------------------------------------------
# Sitemap Parser
# ---------------------------------------------------------------------------

def parse_sitemap(sitemap_url: str, max_urls: int = 100) -> dict:
    """Fetch and parse a sitemap XML."""
    r = _fetch(sitemap_url)
    if not r or r.status_code != 200:
        return {"found": False, "url": sitemap_url, "urls": [], "error": f"HTTP {r.status_code if r else 'unreachable'}"}

    content = r.text
    urls = []
    sub_sitemaps = []

    try:
        # Strip namespaces for simpler parsing
        content_stripped = re.sub(r'\sxmlns[^"]*"[^"]*"', "", content)
        root = ET.fromstring(content_stripped)

        # Sitemap index (contains other sitemaps)
        for sitemap_elem in root.findall(".//sitemap"):
            loc = sitemap_elem.findtext("loc")
            if loc:
                sub_sitemaps.append(loc.strip())

        # Regular sitemap (contains URLs)
        for url_elem in root.findall(".//url"):
            loc = url_elem.findtext("loc")
            if loc:
                urls.append({
                    "url": loc.strip(),
                    "lastmod": url_elem.findtext("lastmod"),
                    "changefreq": url_elem.findtext("changefreq"),
                    "priority": url_elem.findtext("priority"),
                })
                if len(urls) >= max_urls:
                    break
    except ET.ParseError:
        # Try regex fallback
        locs = re.findall(r"<loc>(.*?)</loc>", content)
        urls = [{"url": l.strip(), "lastmod": None, "changefreq": None, "priority": None} for l in locs[:max_urls]]

    return {
        "found": True,
        "url": sitemap_url,
        "url_count": len(urls),
        "urls": urls,
        "sub_sitemaps": sub_sitemaps,
        "is_index": len(sub_sitemaps) > 0,
    }


# ---------------------------------------------------------------------------
# Sensitive Path Probing
# ---------------------------------------------------------------------------

def probe_sensitive_paths(domain: str, extra_paths: list[str] = None) -> list[dict]:
    """HEAD-probe a list of sensitive paths to see which ones respond."""
    paths_to_probe = list(COMMON_SENSITIVE_PATHS)
    if extra_paths:
        paths_to_probe.extend(extra_paths)

    results = []
    import concurrent.futures

    def probe(path):
        url = f"https://{domain}{path}"
        info = _head(url)
        if info and info["status"] not in (404, 410):
            return {
                "path": path,
                "url": url,
                "status": info["status"],
                "content_type": info["content_type"],
                "server": info["server"],
                "risk": "HIGH" if info["status"] == 200 else "MEDIUM" if info["status"] in (301, 302, 403) else "LOW",
                "is_accessible": info["status"] == 200,
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(probe, p) for p in paths_to_probe]
        for f in concurrent.futures.as_completed(futures, timeout=30):
            try:
                result = f.result()
                if result:
                    results.append(result)
            except Exception:
                pass

    results.sort(key=lambda r: (0 if r["is_accessible"] else 1, r["path"]))
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def crawl_intelligence(domain: str) -> dict:
    """Full robots.txt and sitemap intelligence for a domain."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    robots = parse_robots(domain)

    # Parse sitemaps found in robots.txt
    sitemaps_data = []
    sitemap_urls = robots.get("sitemaps", [])
    if not sitemap_urls:
        # Try common locations
        sitemap_urls = [
            f"https://{domain}/sitemap.xml",
            f"https://{domain}/sitemap_index.xml",
        ]

    for sm_url in sitemap_urls[:3]:
        sm_data = parse_sitemap(sm_url)
        if sm_data["found"]:
            sitemaps_data.append(sm_data)
            # If it's an index, parse the first sub-sitemap
            for sub_url in sm_data.get("sub_sitemaps", [])[:2]:
                sub_data = parse_sitemap(sub_url, max_urls=50)
                if sub_data["found"]:
                    sitemaps_data.append(sub_data)

    # Probe sensitive paths (includes those from robots.txt)
    extra_paths = robots.get("sensitive_paths", [])[:10]
    probe_results = probe_sensitive_paths(domain, extra_paths)

    accessible_count = sum(1 for p in probe_results if p["is_accessible"])
    total_sitemap_urls = sum(s.get("url_count", 0) for s in sitemaps_data)

    return {
        "domain": domain,
        "robots": robots,
        "sitemaps": sitemaps_data,
        "total_sitemap_urls": total_sitemap_urls,
        "sensitive_probes": probe_results,
        "accessible_sensitive_paths": accessible_count,
        "summary": {
            "has_robots": robots["found"],
            "disallowed_count": robots.get("total_disallowed", 0),
            "sensitive_paths_in_robots": len(robots.get("sensitive_paths", [])),
            "sitemaps_found": len(sitemaps_data),
            "total_urls_in_sitemaps": total_sitemap_urls,
            "accessible_exposed_paths": accessible_count,
        },
    }
