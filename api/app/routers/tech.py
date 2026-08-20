"""
Web Tech Stack Fingerprinting Router
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services import tech_service

router = APIRouter(tags=["tech"])

class TechDetectRequest(BaseModel):
    url: str

@router.post("/api/tech/detect")
@router.post("/tech/detect")
def detect_tech(req: TechDetectRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")
    try:
        return tech_service.detect_tech_stack(req.url)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Technology fingerprinting failed: {str(e)}")
