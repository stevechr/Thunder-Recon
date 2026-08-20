"""
Threat Intelligence Feed Service.
Fetches and caches the CISA Known Exploited Vulnerabilities (KEV) Catalog.
Public, free feed from CISA / DHS.
"""

import requests
import time
from typing import Optional, List, Dict

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL = 3600  # 1 hour cache
_cache_data: Optional[Dict] = None
_cache_time: float = 0


def fetch_cisa_kev(query: Optional[str] = None, limit: int = 50) -> Dict:
    """Fetch and filter CISA Known Exploited Vulnerabilities catalog."""
    global _cache_data, _cache_time

    now = time.time()
    if _cache_data is None or (now - _cache_time) > CACHE_TTL:
        try:
            r = requests.get(
                CISA_KEV_URL,
                timeout=10,
                headers={"User-Agent": "ThunderRecon/4.0 Cyber Intelligence"},
            )
            if r.status_code == 200:
                _cache_data = r.json()
                _cache_time = now
        except Exception:
            pass

    if not _cache_data:
        # Return structured fallback if network fails
        return {
            "title": "CISA Known Exploited Vulnerabilities (KEV)",
            "count": 0,
            "vulnerabilities": [],
            "source": "CISA / DHS (Offline Fallback)",
        }

    vulns: List[Dict] = _cache_data.get("vulnerabilities", [])
    total_count = len(vulns)

    # Sort descending by dateAdded (newest first)
    vulns_sorted = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)

    if query and query.strip():
        q = query.strip().lower()
        vulns_filtered = [
            v for v in vulns_sorted
            if q in v.get("cveID", "").lower()
            or q in v.get("vendorProject", "").lower()
            or q in v.get("product", "").lower()
            or q in v.get("vulnerabilityName", "").lower()
            or q in v.get("shortDescription", "").lower()
        ]
    else:
        vulns_filtered = vulns_sorted

    return {
        "title": _cache_data.get("title", "CISA Known Exploited Vulnerabilities Catalog"),
        "catalog_version": _cache_data.get("catalogVersion", "1.0"),
        "date_released": _cache_data.get("dateReleased", ""),
        "total_in_catalog": total_count,
        "matched_count": len(vulns_filtered),
        "vulnerabilities": vulns_filtered[:limit],
    }
