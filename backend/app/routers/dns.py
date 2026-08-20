"""
DNS Record & Security Audit Router
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services import dns_service

router = APIRouter(tags=["dns"])

class DnsInspectRequest(BaseModel):
    domain: str

@router.post("/api/dns/inspect")
@router.post("/dns/inspect")
def dns_inspect(req: DnsInspectRequest):
    if not req.domain.strip():
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    try:
        return dns_service.inspect_dns_records(req.domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS inspection failed: {str(e)}")
