from fastapi import APIRouter, HTTPException, Depends, Header
from sqlalchemy.orm import Session

from backend_app.models import ScanRequest, ScanResponse
from backend_app.services import (
    dns_service,
    ip_service,
    ssl_service,
    port_service,
    tech_service,
    risk_service,
    breach_service,
    audit_service,
    threat_service,
    virustotal_service,
)
from backend_app.database import get_db, ScanRecord
from backend_app.routers.auth import verify_session_token

router = APIRouter(tags=["scan"])


@router.post("/api/scan/full", response_model=ScanResponse)
@router.post("/scan/full", response_model=ScanResponse)
def full_scan(
    req: ScanRequest,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or are authorized to scan this domain (authorized=true).",
        )

    # Optional session token extraction (no login required, 100% free)
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif req.session_token:
        token = req.session_token

    is_valid, verified_email = verify_session_token(token)
    if not verified_email:
        verified_email = req.email or "anonymous@thunder-recon.local"

    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    ip = ip_service.resolve_ip(domain)
    if not ip:
        raise HTTPException(status_code=404, detail=f"Could not resolve domain: {domain}")

    dns_records = dns_service.get_dns_records(domain)
    whois_info = ip_service.get_whois(domain)
    ip_intel = ip_service.get_ip_intel(ip)
    ssl_info = ssl_service.get_ssl_info(domain)
    ports = port_service.scan_ports(ip) if req.include_ports else []
    tech = tech_service.analyze(domain)
    breaches = breach_service.check_domain_breaches(domain) if req.include_breaches else {"domain": domain, "breach_count": 0, "breaches": []}
    risk = risk_service.score(dns_records, ssl_info, ports, tech, breaches)

    # Execute 12-Point Comprehensive Security Audit
    audit_modules = audit_service.run_12_point_audit(
        domain=domain,
        ip=ip,
        dns_records=dns_records,
        ssl_info=ssl_info,
        ports=ports,
        tech=tech,
    )

    # Execute Threat, Defacement, Malware & Spoofing Compromise Detection
    threat_intel = threat_service.scan_threat_and_compromise(domain=domain, ip=ip)

    # Execute VirusTotal & Multi-Engine Threat Intelligence
    vt_intel = virustotal_service.get_virustotal_report(domain=domain, ip=ip)

    email = verified_email or (req.email.strip().lower() if req.email else None)

    result = {
        "domain": domain,
        "email": email,
        "ip": ip,
        "dns_records": dns_records,
        "whois": whois_info,
        "ip_intel": ip_intel,
        "ssl": ssl_info,
        "ports": ports,
        "technology": tech,
        "breaches": breaches,
        "risk": risk,
        "audit_modules": audit_modules,
        "threat_intel": threat_intel,
        "virustotal": vt_intel,
    }

    try:
        if db:
            record = ScanRecord(domain=domain, email=email, ip=ip, result=result, risk_score=risk["score"])
            db.add(record)
            db.commit()
    except Exception as e:
        print("Scan record save notice:", e)

    return result


@router.get("/api/scan/history")
@router.get("/scan/history")
def scan_history(limit: int = 20, email: str | None = None, db: Session = Depends(get_db)):
    try:
        if not db:
            return []
        query = db.query(ScanRecord)
        if email:
            query = query.filter(ScanRecord.email == email.strip().lower())
        records = query.order_by(ScanRecord.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "domain": r.domain,
                "email": r.email,
                "ip": r.ip,
                "risk_score": r.risk_score,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ]
    except Exception:
        return []


@router.get("/api/scan/history/{scan_id}", response_model=ScanResponse)
@router.get("/scan/history/{scan_id}", response_model=ScanResponse)
def scan_detail(scan_id: int, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record.result
