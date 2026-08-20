"""
Standalone Tools Router.
Endpoints for: Subdomain Enumeration, ASN/BGP, OSINT, WAF Testing,
Email Security, Cloud Storage Buckets, Phishing Detector, Robots & Sitemap Crawl, and Port Scanner.
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional, List
import socket

from app.routers.auth import verify_session_token
from app.services import (
    subdomain_service,
    asn_service,
    osint_service,
    waf_service,
    email_security_service,
    bucket_service,
    phishing_service,
    crawl_service,
    port_service,
    threat_feed_service,
)

router = APIRouter(tags=["tools"])


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class SubdomainRequest(BaseModel):
    domain: str = Field(..., description="Target domain to enumerate subdomains for")
    authorized: bool = Field(..., description="Must be true: confirms ownership or authorization")
    session_token: Optional[str] = None


class AsnRequest(BaseModel):
    query: str = Field(..., description="IP address (e.g. 8.8.8.8) or ASN (e.g. AS15169 or 15169)")


class OsintRequest(BaseModel):
    domain: str = Field(..., description="Target domain for OSINT aggregation")
    email: Optional[str] = Field(default=None, description="Optional email for Gravatar / personal OSINT")
    session_token: Optional[str] = None


class WafRequest(BaseModel):
    domain: str = Field(..., description="Target domain to probe for WAF/firewall")
    authorized: bool = Field(..., description="Must be true: confirms ownership or authorization")
    session_token: Optional[str] = None


class EmailSecurityRequest(BaseModel):
    domain: str = Field(..., description="Target domain to analyze SPF, DKIM, DMARC")


class BucketRequest(BaseModel):
    domain: str = Field(..., description="Target domain/brand to search for public buckets")
    authorized: bool = Field(..., description="Must be true: confirms authorization to search")
    session_token: Optional[str] = None


class PhishingRequest(BaseModel):
    url: str = Field(..., description="URL or domain to analyze for phishing/threats")


class CrawlRequest(BaseModel):
    domain: str = Field(..., description="Target domain to parse robots.txt and sitemaps")


class PortScanRequest(BaseModel):
    target: str = Field(..., description="IP address or domain to scan")
    ports: Optional[List[int]] = Field(default=None, description="Specific ports to scan")
    authorized: bool = Field(..., description="Must be true: confirms ownership or authorization")
    session_token: Optional[str] = None


# ---------------------------------------------------------------------------
# Subdomain Enumeration
# ---------------------------------------------------------------------------

@router.post("/api/tools/subdomains")
@router.post("/tools/subdomains")
def enumerate_subdomains(
    req: SubdomainRequest,
    authorization: str | None = Header(default=None),
):
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or are authorized to enumerate this domain (authorized=true).",
        )

    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif req.session_token:
        token = req.session_token

    is_valid, _ = verify_session_token(token)
    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Authentication required for subdomain enumeration.",
        )

    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    return subdomain_service.enumerate_subdomains(domain)


# ---------------------------------------------------------------------------
# ASN / BGP Intelligence
# ---------------------------------------------------------------------------

@router.post("/api/tools/asn")
@router.post("/tools/asn")
def asn_lookup(req: AsnRequest):
    """No authentication required — public data only."""
    query = req.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
    return asn_service.full_asn_lookup(query)


@router.get("/api/tools/asn/{query}")
@router.get("/tools/asn/{query}")
def asn_lookup_get(query: str):
    return asn_service.full_asn_lookup(query)


# ---------------------------------------------------------------------------
# OSINT Aggregation
# ---------------------------------------------------------------------------

@router.post("/api/tools/osint")
@router.post("/tools/osint")
def run_osint(
    req: OsintRequest,
    authorization: str | None = Header(default=None),
):
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif req.session_token:
        token = req.session_token

    is_valid, _ = verify_session_token(token)
    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Authentication required for OSINT aggregation.",
        )

    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    return osint_service.run_osint(domain, req.email)


# ---------------------------------------------------------------------------
# WAF / Firewall Testing
# ---------------------------------------------------------------------------

@router.post("/api/tools/waf")
@router.post("/tools/waf")
def waf_test(
    req: WafRequest,
    authorization: str | None = Header(default=None),
):
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or are authorized to probe this domain (authorized=true).",
        )

    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif req.session_token:
        token = req.session_token

    is_valid, _ = verify_session_token(token)
    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Authentication required for WAF testing.",
        )

    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    return waf_service.run_waf_test(domain)


# ---------------------------------------------------------------------------
# Email Security Analyzer (SPF / DKIM / DMARC / MX)
# ---------------------------------------------------------------------------

@router.post("/api/tools/email-security")
@router.post("/tools/email-security")
def analyze_email(req: EmailSecurityRequest):
    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    return email_security_service.analyze_email_security(domain)


# ---------------------------------------------------------------------------
# Cloud Storage Bucket Finder
# ---------------------------------------------------------------------------

@router.post("/api/tools/buckets")
@router.post("/tools/buckets")
def find_cloud_buckets(
    req: BucketRequest,
    authorization: str | None = Header(default=None),
):
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you are authorized to search for buckets related to this target.",
        )

    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif req.session_token:
        token = req.session_token

    is_valid, _ = verify_session_token(token)
    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Authentication required for cloud bucket enumeration.",
        )

    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    return bucket_service.find_buckets(domain)


# ---------------------------------------------------------------------------
# Phishing / Malicious URL Detector
# ---------------------------------------------------------------------------

@router.post("/api/tools/phishing")
@router.post("/tools/phishing")
def check_phishing(req: PhishingRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    return phishing_service.analyze_url_threat(url)


# ---------------------------------------------------------------------------
# Robots.txt & Sitemap Crawler Intelligence
# ---------------------------------------------------------------------------

@router.post("/api/tools/crawl")
@router.post("/tools/crawl")
def crawl_intel(req: CrawlRequest):
    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    return crawl_service.crawl_intelligence(domain)


# ---------------------------------------------------------------------------
# Dedicated Port Scanner
# ---------------------------------------------------------------------------

@router.post("/api/tools/ports")
@router.post("/tools/ports")
def port_scan(
    req: PortScanRequest,
    authorization: str | None = Header(default=None),
):
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or are authorized to scan this target (authorized=true).",
        )

    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif req.session_token:
        token = req.session_token

    is_valid, _ = verify_session_token(token)
    if not is_valid:
        raise HTTPException(
            status_code=401,
            detail="Authentication required for port scanning.",
        )

    target = req.target.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Could not resolve host: {target}")

    open_ports = port_service.scan_ports(ip, req.ports)
    return {
        "target": target,
        "ip": ip,
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
    }


# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities (KEV) Live Threat Feed
# ---------------------------------------------------------------------------

@router.get("/api/tools/cisa-kev")
@router.get("/tools/cisa-kev")
def get_cisa_kev(q: Optional[str] = None, limit: int = 50):
    return threat_feed_service.fetch_cisa_kev(query=q, limit=limit)

