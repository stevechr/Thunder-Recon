from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.services import url_service, mail_header_service

router = APIRouter(tags=["analyze"])


class UrlAnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect and analyze across AV engines")


class MailHeaderAnalyzeRequest(BaseModel):
    raw_headers: str = Field(..., description="Raw RFC 822 / RFC 5322 email headers text")


@router.post("/api/analyze/url")
@router.post("/analyze/url")
def analyze_target_url(req: UrlAnalyzeRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="A valid URL is required.")
    try:
        return url_service.analyze_url(req.url.strip())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis error: {str(e)}")


@router.post("/api/analyze/mail-header")
@router.post("/analyze/mail-header")
def analyze_email_headers_endpoint(req: MailHeaderAnalyzeRequest):
    if not req.raw_headers or not req.raw_headers.strip():
        raise HTTPException(status_code=400, detail="Raw email header text is required.")
    try:
        return mail_header_service.analyze_email_headers(req.raw_headers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Mail header analysis error: {str(e)}")
