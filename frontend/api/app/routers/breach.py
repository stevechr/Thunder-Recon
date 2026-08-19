from fastapi import APIRouter, HTTPException
from app.models import EmailCheckRequest, PasswordCheckRequest
from app.services import breach_service

router = APIRouter(tags=["breach"])


@router.post("/api/breach/email")
@router.post("/breach/email")
def check_email(req: EmailCheckRequest):
    if not req.email or "@" not in req.email:
        raise HTTPException(status_code=400, detail="A valid email address is required.")
    return breach_service.check_email_breach(req.email)


@router.post("/api/breach/password")
@router.post("/breach/password")
def check_password(req: PasswordCheckRequest):
    if not req.password:
        raise HTTPException(status_code=400, detail="Password string cannot be empty.")
    return breach_service.check_password_pwned(req.password)


@router.get("/api/breach/domain/{domain}")
@router.get("/breach/domain/{domain}")
def check_domain(domain: str):
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Valid domain name is required.")
    return breach_service.check_domain_breaches(clean_domain)
