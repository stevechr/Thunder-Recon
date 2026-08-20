"""
WHOIS Intelligence Router
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend_app.services import whois_service

router = APIRouter(tags=["whois"])

class WhoisLookupRequest(BaseModel):
    domain: str

@router.post("/api/whois/lookup")
@router.post("/whois/lookup")
def whois_lookup(req: WhoisLookupRequest):
    if not req.domain.strip():
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    try:
        return whois_service.lookup_whois_record(req.domain)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"WHOIS lookup failed: {str(e)}")
