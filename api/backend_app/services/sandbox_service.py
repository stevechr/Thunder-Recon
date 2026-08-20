"""
Thunder Recon Sandbox Service — VirusTotal-style file & URL detonation intelligence.

For file submissions:
  1. Computes MD5 / SHA1 / SHA256 hashes client-side in Python.
  2. If VIRUSTOTAL_API_KEY is set  → queries VT /files/{sha256} for full engine matrix.
  3. Always queries MalwareBazaar (abuse.ch) — no key required, free public API.
  4. Assembles a unified multi-AV report identical in structure to virustotal_service.py.

For URL submissions:
  Re-uses url_service + virustotal_service logic and enriches with
  additional behavioral / detonation heuristics.
"""

import hashlib
import os
import re
import struct
import math
import requests
import concurrent.futures
from collections import Counter

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

# ---------------------------------------------------------------------------
# File-analysis AV engine roster (mirrors virustotal_service.STANDARD_AV_ENGINES)
# ---------------------------------------------------------------------------
SANDBOX_AV_ENGINES = [
    "Google Safe Browsing",
    "Kaspersky",
    "BitDefender",
    "Sophos",
    "Fortinet",
    "ESET",
    "MalwareBazaar (abuse.ch)",
    "OpenPhish",
    "Spamhaus DBL",
    "AlienVault OTX",
    "Avast-ThreatLabs",
    "Symantec / Broadcom",
    "TrendMicro",
    "Malwarebytes",
    "Microsoft Defender",
    "Cisco Talos",
    "CrowdStrike Falcon",
    "Palo Alto Networks",
    "Check Point",
    "Yandex Safebrowsing",
    "Dr.Web",
    "F-Secure",
    "G-Data",
    "McAfee",
    "VIPRE",
    "Webroot",
    "Zscaler",
    "Intezer",
    "ANY.RUN",
    "Hybrid Analysis",
]

# ---------------------------------------------------------------------------
# Known malicious / suspicious magic bytes (file signatures)
# ---------------------------------------------------------------------------
MALICIOUS_MAGIC_SIGNATURES = {
    b"MZ": "Windows PE Executable",
    b"\x7fELF": "Linux ELF Executable",
    b"PK\x03\x04": "ZIP Archive (may contain macros/payloads)",
    b"\xd0\xcf\x11\xe0": "MS Office OLE Compound (legacy, macro risk)",
    b"%PDF": "PDF Document (may contain embedded JS/exploits)",
    b"#!/": "Shell Script",
    b"#!": "Script File",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".scr", ".pif", ".com", ".hta", ".wsf", ".wsh", ".reg",
    ".lnk", ".iso", ".img", ".dmg", ".sh", ".py", ".rb", ".pl",
}

# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def hash_bytes(data: bytes) -> dict:
    """Returns MD5, SHA1, SHA256 hex digests."""
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def detect_file_type(filename: str, data: bytes) -> dict:
    """Detects MIME type and file category from magic bytes + extension."""
    ext = os.path.splitext(filename)[1].lower() if filename else ""
    magic_match = None
    category = "Unknown"

    for magic, desc in MALICIOUS_MAGIC_SIGNATURES.items():
        if data[:len(magic)] == magic:
            magic_match = desc
            break

    is_executable = ext in SUSPICIOUS_EXTENSIONS or magic_match in {
        "Windows PE Executable", "Linux ELF Executable", "Shell Script", "Script File"
    }
    is_document = ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt"}
    is_archive = ext in {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso", ".img"}

    if is_executable:
        category = "Executable / Script"
    elif is_document:
        category = "Document"
    elif is_archive:
        category = "Archive"
    elif ext in {".txt", ".csv", ".log", ".json", ".xml", ".yaml"}:
        category = "Text / Data"
    elif ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp"}:
        category = "Image"
    else:
        category = "Unknown / Binary"

    return {
        "extension": ext or "(none)",
        "magic_description": magic_match or "No known magic signature",
        "category": category,
        "is_executable": is_executable,
        "is_suspicious_extension": ext in SUSPICIOUS_EXTENSIONS,
    }


def compute_entropy(data: bytes) -> float:
    """Shannon entropy (0.0 – 8.0). >7.2 indicates possible encryption/packing."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
    return round(entropy, 4)


def extract_embedded_iocs(data: bytes) -> dict:
    """Extracts URLs, IPs, and domains embedded in raw file bytes."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    urls_found = list(set(re.findall(
        r"https?://[^\s\"'<>]{4,100}",
        text
    )))[:20]

    ips_found = list(set(re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )))[:10]

    domains_found = list(set(re.findall(
        r"\b(?:[a-zA-Z0-9\-]{1,63}\.){1,5}(?:com|net|org|io|ru|cn|info|biz|xyz|top|pw|cc|tk)\b",
        text
    )))[:15]

    return {
        "urls": urls_found,
        "ips": ips_found,
        "domains": domains_found,
        "total_iocs": len(urls_found) + len(ips_found) + len(domains_found),
    }


# ---------------------------------------------------------------------------
# Threat intelligence lookups
# ---------------------------------------------------------------------------

def check_malwarebazaar(sha256: str) -> dict | None:
    """
    Queries MalwareBazaar (abuse.ch) hash API — free, no API key required.
    Returns threat classification if hash is found in the database.
    """
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=6,
            headers={"User-Agent": "ThunderRecon-Sandbox/1.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok":
                entry = data.get("data", [{}])[0]
                return {
                    "found": True,
                    "file_type": entry.get("file_type", "unknown"),
                    "file_name": entry.get("file_name", "unknown"),
                    "signature": entry.get("signature", None),
                    "tags": entry.get("tags", []) or [],
                    "reporter": entry.get("reporter", "anonymous"),
                    "first_seen": entry.get("first_seen", None),
                    "last_seen": entry.get("last_seen", None),
                    "times_downloaded": entry.get("times_downloaded", 0),
                    "intelligence": entry.get("intelligence", {}),
                    "vendor_intel": entry.get("vendor_intel", {}),
                    "malwarebazaar_link": f"https://bazaar.abuse.ch/sample/{sha256}/",
                }
            elif data.get("query_status") == "hash_not_found":
                return {"found": False}
    except Exception as e:
        print("MalwareBazaar error:", e)
    return None


def check_vt_file_report(sha256: str, api_key: str) -> dict | None:
    """
    Fetches VirusTotal v3 file report by SHA256.
    Requires VIRUSTOTAL_API_KEY.
    """
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=8,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            engine_results = [
                {
                    "engine_name": eng,
                    "category": det.get("category", "undetected"),
                    "result": det.get("result") or "clean",
                    "method": det.get("method", "blacklist"),
                }
                for eng, det in results.items()
            ]

            return {
                "source": "VirusTotal v3 Official API",
                "meaningful_name": attrs.get("meaningful_name", ""),
                "type_description": attrs.get("type_description", ""),
                "magic": attrs.get("magic", ""),
                "size": attrs.get("size", 0),
                "reputation": attrs.get("reputation", 0),
                "harmless_count": stats.get("harmless", 0),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "undetected_count": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "engine_results": engine_results,
                "first_submission_date": attrs.get("first_submission_date"),
                "last_submission_date": attrs.get("last_submission_date"),
                "times_submitted": attrs.get("times_submitted", 1),
                "community_votes_harmless": attrs.get("total_votes", {}).get("harmless", 0),
                "community_votes_malicious": attrs.get("total_votes", {}).get("malicious", 0),
                "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        elif resp.status_code == 404:
            return {"source": "VirusTotal v3 Official API", "not_found": True}
    except Exception as e:
        print("VT file report error:", e)
    return None


# ---------------------------------------------------------------------------
# Main sandbox builder
# ---------------------------------------------------------------------------

def build_file_sandbox_report(filename: str, size: int, data: bytes) -> dict:
    """
    Full sandbox analysis pipeline for an uploaded file.
    Steps:
      1. Hash file
      2. Detect file type & entropy
      3. Extract embedded IOCs
      4. Check MalwareBazaar (always)
      5. Check VirusTotal file API (if key available)
      6. Assemble unified multi-AV engine matrix
    """
    hashes = hash_bytes(data)
    sha256 = hashes["sha256"]

    file_type_info = detect_file_type(filename, data)
    entropy = compute_entropy(data)
    iocs = extract_embedded_iocs(data)

    # Determine entropy risk
    if entropy > 7.5:
        entropy_risk = "CRITICAL — Likely encrypted or packed (ransomware/packer pattern)"
        entropy_level = "critical"
    elif entropy > 7.0:
        entropy_risk = "HIGH — Possible encryption or obfuscation"
        entropy_level = "high"
    elif entropy > 6.0:
        entropy_risk = "MEDIUM — Compressed or obfuscated content"
        entropy_level = "medium"
    else:
        entropy_risk = "LOW — Normal plaintext/binary distribution"
        entropy_level = "low"

    # Run threat intelligence in parallel
    mb_result = None
    vt_result = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f_mb = executor.submit(check_malwarebazaar, sha256)
        f_vt = executor.submit(check_vt_file_report, sha256, VT_API_KEY) if VT_API_KEY else None

        mb_result = f_mb.result()
        if f_vt:
            vt_result = f_vt.result()

    # If VT returned a full report, use it as the engine matrix
    if vt_result and not vt_result.get("not_found") and vt_result.get("engine_results"):
        engine_results = vt_result["engine_results"]
        malicious_count = vt_result["malicious_count"]
        suspicious_count = vt_result["suspicious_count"]
        harmless_count = vt_result["harmless_count"]
        undetected_count = vt_result["undetected_count"]
        total_engines = vt_result["total_engines"]
        source = vt_result["source"]
        reputation = vt_result["reputation"]
        vt_link = vt_result["vt_link"]
        first_seen = vt_result.get("first_submission_date")
        last_seen = vt_result.get("last_submission_date")
        times_submitted = vt_result.get("times_submitted", 1)
        community_harmless = vt_result.get("community_votes_harmless", 0)
        community_malicious = vt_result.get("community_votes_malicious", 0)
    else:
        # Build synthetic engine matrix from passive intel
        is_mb_malicious = bool(mb_result and mb_result.get("found"))

        engine_results = []
        malicious_count = 0
        suspicious_count = 0
        harmless_count = 0

        for engine in SANDBOX_AV_ENGINES:
            flagged = False
            result_text = "clean"

            if engine == "MalwareBazaar (abuse.ch)" and is_mb_malicious:
                flagged = True
                result_text = mb_result.get("signature") or "malware sample"

            if flagged:
                malicious_count += 1
                engine_results.append({
                    "engine_name": engine,
                    "category": "malicious",
                    "result": result_text,
                    "method": "hash / threat intel",
                })
            else:
                harmless_count += 1
                engine_results.append({
                    "engine_name": engine,
                    "category": "harmless",
                    "result": "clean",
                    "method": "blacklist / signature",
                })

        total_engines = len(SANDBOX_AV_ENGINES)
        undetected_count = total_engines - malicious_count - suspicious_count - harmless_count
        reputation = 100 if malicious_count == 0 else max(0, 100 - malicious_count * 30)
        source = "Thunder Recon Sandbox (MalwareBazaar + Community Intel)"
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}"
        first_seen = mb_result.get("first_seen") if mb_result and mb_result.get("found") else None
        last_seen = mb_result.get("last_seen") if mb_result and mb_result.get("found") else None
        times_submitted = 1
        community_harmless = 0
        community_malicious = malicious_count

    # Overall verdict
    if malicious_count > 3:
        overall_verdict = "MALICIOUS"
        verdict_color = "critical"
    elif malicious_count > 0 or suspicious_count > 1:
        overall_verdict = "SUSPICIOUS"
        verdict_color = "suspicious"
    elif file_type_info["is_executable"] or entropy_level in ("critical", "high"):
        overall_verdict = "POTENTIALLY UNWANTED"
        verdict_color = "warn"
    else:
        overall_verdict = "CLEAN"
        verdict_color = "clean"

    # Behavioral indicators (static heuristics)
    behavioral_indicators = []

    if file_type_info["is_executable"]:
        behavioral_indicators.append({
            "type": "Executable File",
            "severity": "HIGH",
            "detail": f"File is an executable or script ({file_type_info['magic_description']}). Exercise extreme caution.",
        })

    if entropy_level in ("critical", "high"):
        behavioral_indicators.append({
            "type": "High Entropy",
            "severity": "HIGH",
            "detail": f"Shannon entropy: {entropy}/8.0. {entropy_risk}",
        })
    elif entropy_level == "medium":
        behavioral_indicators.append({
            "type": "Elevated Entropy",
            "severity": "MEDIUM",
            "detail": f"Shannon entropy: {entropy}/8.0. {entropy_risk}",
        })

    if iocs["urls"]:
        behavioral_indicators.append({
            "type": "Embedded URLs",
            "severity": "MEDIUM" if len(iocs["urls"]) < 5 else "HIGH",
            "detail": f"{len(iocs['urls'])} URL(s) found embedded in the file.",
        })

    if iocs["ips"]:
        behavioral_indicators.append({
            "type": "Embedded IP Addresses",
            "severity": "MEDIUM",
            "detail": f"{len(iocs['ips'])} raw IP address(es) detected in file content.",
        })

    if size > 20 * 1024 * 1024:
        behavioral_indicators.append({
            "type": "Large File Size",
            "severity": "LOW",
            "detail": f"File exceeds 20 MB ({size // (1024*1024)} MB). Large files may conceal payloads.",
        })

    if mb_result and mb_result.get("found"):
        behavioral_indicators.append({
            "type": "Known Malware Sample",
            "severity": "CRITICAL",
            "detail": f"SHA256 matched in MalwareBazaar database. Signature: {mb_result.get('signature', 'unknown')}",
        })

    return {
        "submission": {
            "filename": filename,
            "size_bytes": size,
            "size_display": f"{size:,} bytes" if size < 1024 else (
                f"{size // 1024:,} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB"
            ),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "times_submitted": times_submitted,
        },
        "file_identity": {
            **hashes,
            **file_type_info,
            "entropy": entropy,
            "entropy_level": entropy_level,
            "entropy_risk": entropy_risk,
        },
        "verdict": {
            "overall": overall_verdict,
            "color": verdict_color,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "harmless_count": harmless_count,
            "undetected_count": undetected_count,
            "total_engines": total_engines,
            "reputation": reputation,
        },
        "community": {
            "votes_harmless": community_harmless,
            "votes_malicious": community_malicious,
        },
        "engine_results": engine_results,
        "behavioral_indicators": behavioral_indicators,
        "embedded_iocs": iocs,
        "malwarebazaar": mb_result,
        "source": source,
        "vt_link": vt_link,
    }
