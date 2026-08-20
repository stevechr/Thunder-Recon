"""
CVE Search Router
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services import cve_service

router = APIRouter(tags=["cve"])

class CveSearchRequest(BaseModel):
    query: str

@router.post("/api/cve/search")
@router.post("/cve/search")
def cve_search(req: CveSearchRequest):
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Search query cannot be empty.")
    try:
        return cve_service.search_cve_vulnerabilities(req.query)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE search failed: {str(e)}")
