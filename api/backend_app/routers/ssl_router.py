"""
SSL/TLS Inspector Router
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend_app.services import ssl_service

router = APIRouter(tags=["ssl"])

class SslInspectRequest(BaseModel):
    target: str
    port: int = 443

@router.post("/api/ssl/inspect")
@router.post("/ssl/inspect")
def ssl_inspect(req: SslInspectRequest):
    if not req.target.strip():
        raise HTTPException(status_code=400, detail="Target hostname cannot be empty.")
    try:
        return ssl_service.inspect_ssl_certificate(req.target, req.port)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL inspection failed: {str(e)}")
