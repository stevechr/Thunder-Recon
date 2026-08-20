"""
Standalone Tools Router.
Endpoints for: Subdomain Enumeration, ASN/BGP, OSINT, WAF Testing.
All require authorization (Bearer session token) for active scan endpoints.
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional

from app.routers.auth import verify_session_token
from app.services import subdomain_service, asn_service, osint_service, waf_service

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
