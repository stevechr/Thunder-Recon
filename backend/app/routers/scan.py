from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.models import ScanRequest, ScanResponse
from app.services import dns_service, ip_service, ssl_service, port_service, tech_service, risk_service, breach_service
from app.database import get_db, ScanRecord

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/full", response_model=ScanResponse)
def full_scan(req: ScanRequest, db: Session = Depends(get_db)):
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or are authorized to scan this domain (authorized=true).",
        )

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

    result = {
        "domain": domain,
        "ip": ip,
        "dns_records": dns_records,
        "whois": whois_info,
        "ip_intel": ip_intel,
        "ssl": ssl_info,
        "ports": ports,
        "technology": tech,
        "breaches": breaches,
        "risk": risk,
    }

    record = ScanRecord(domain=domain, ip=ip, result=result, risk_score=risk["score"])
    db.add(record)
    db.commit()

    return result


@router.get("/history")
def scan_history(limit: int = 20, db: Session = Depends(get_db)):
    records = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "domain": r.domain,
            "ip": r.ip,
            "risk_score": r.risk_score,
            "created_at": r.created_at.isoformat(),
        }
        for r in records
    ]


@router.get("/history/{scan_id}", response_model=ScanResponse)
def scan_detail(scan_id: int, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record.result
