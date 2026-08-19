"""
Sandbox Router — VirusTotal-style file & URL sandbox submission endpoints.
Accepts file uploads and URL submissions for behavioral threat analysis.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from app.services import sandbox_service, url_service

router = APIRouter(tags=["sandbox"])

MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB


class SandboxUrlRequest(BaseModel):
    url: str


@router.post("/api/sandbox/file")
@router.post("/sandbox/file")
async def sandbox_file(file: UploadFile = File(...)):
    """
    Upload a file for sandbox analysis.
    Computes cryptographic hashes, detects file type, measures entropy,
    extracts embedded IOCs, and checks MalwareBazaar + VirusTotal.
    """
    data = await file.read()

    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty file submitted.")

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is 32 MB (submitted: {len(data) // (1024*1024)} MB).",
        )

    filename = file.filename or "unknown_file"
    report = sandbox_service.build_file_sandbox_report(
        filename=filename,
        size=len(data),
        data=data,
    )
    return report


@router.post("/api/sandbox/url")
@router.post("/sandbox/url")
def sandbox_url(req: SandboxUrlRequest):
    """
    Submit a URL for sandbox behavioral analysis.
    Performs redirect chain tracing, heuristic detonation analysis,
    and multi-engine threat intelligence lookup.
    """
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        raw_url = "https://" + raw_url

    try:
        url_report = url_service.analyze_url(raw_url)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"URL analysis failed: {str(e)}")

    # url_service returns `virustotal` key with the full VT report nested inside
    vt_report = url_report.get("virustotal", {})
    heuristics = url_report.get("heuristics", [])
    engine_results = vt_report.get("engine_results", [])

    malicious_count = vt_report.get("malicious_count", 0)
    suspicious_count = vt_report.get("suspicious_count", 0)
    harmless_count = vt_report.get("harmless_count", 0)
    total_engines = vt_report.get("total_engines", 0)
    reputation = vt_report.get("reputation", 100)
    risk_score = url_report.get("risk_score", 0)

    critical_heuristics = [h for h in heuristics if h.get("severity", "").upper() in ("HIGH", "CRITICAL")]

    if malicious_count > 3 or len(critical_heuristics) >= 2:
        overall_verdict = "MALICIOUS"
        verdict_color = "critical"
    elif malicious_count > 0 or len(critical_heuristics) == 1:
        overall_verdict = "SUSPICIOUS"
        verdict_color = "suspicious"
    elif risk_score > 50:
        overall_verdict = "POTENTIALLY UNWANTED"
        verdict_color = "warn"
    else:
        overall_verdict = "CLEAN"
        verdict_color = "clean"

    domain = url_report.get("domain", "")
    redirect_chain = url_report.get("redirect_chain", [])

    return {
        "type": "url",
        "submission": {
            "raw_url": raw_url,
            "final_url": url_report.get("final_url", raw_url),
            "domain": domain,
            "ip": url_report.get("ip"),
            "redirect_hops": url_report.get("redirect_hops_count", 0),
            "redirect_chain": redirect_chain,
            "status_code": url_report.get("status_code"),
            "content_type": url_report.get("content_type", ""),
            "server": url_report.get("server", ""),
            "is_accessible": url_report.get("is_accessible", False),
            "scheme": url_report.get("scheme", "https"),
            "path": url_report.get("path", "/"),
        },
        "verdict": {
            "overall": overall_verdict,
            "color": verdict_color,
            "risk_score": risk_score,
            "risk_rating": url_report.get("risk_rating", "Unknown"),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "harmless_count": harmless_count,
            "undetected_count": vt_report.get("undetected_count", 0),
            "total_engines": total_engines,
            "reputation": reputation,
        },
        "heuristics": heuristics,
        "engine_results": engine_results,
        "source": vt_report.get("source", "Thunder Recon Sandbox"),
        "vt_link": vt_report.get("vt_url_link") or vt_report.get("vt_link") or f"https://www.virustotal.com/gui/domain/{domain}",
    }
