"""
HTTP Security Headers Router
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend_app.services import headers_service

router = APIRouter(tags=["headers"])

class HeaderAuditRequest(BaseModel):
    url: str

@router.post("/api/headers/audit")
@router.post("/headers/audit")
def audit_headers(req: HeaderAuditRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")
    try:
        return headers_service.audit_security_headers(req.url)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Header audit failed: {str(e)}")
