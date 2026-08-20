"""
IP Intelligence Router
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend_app.services import ip_service

router = APIRouter(tags=["ip"])

class IpLookupRequest(BaseModel):
    target: str

@router.post("/api/ip/lookup")
@router.post("/ip/lookup")
def ip_lookup(req: IpLookupRequest):
    if not req.target.strip():
        raise HTTPException(status_code=400, detail="Target IP or domain cannot be empty.")
    try:
        return ip_service.lookup_ip_intelligence(req.target)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IP lookup failed: {str(e)}")
