"""
CVE & Vulnerability Intelligence Search Service.
Queries National Vulnerability Database (NVD API v2.0) by CVE ID or software keyword.
"""

import requests
from urllib.parse import quote

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cve_vulnerabilities(query: str, results_per_page: int = 15) -> dict:
    query = query.strip()
    if not query:
        raise ValueError("Search query cannot be empty.")

    params = {"resultsPerPage": min(results_per_page, 30)}

    # If query is a CVE ID (e.g. CVE-2021-44228 or 2021-44228)
    if query.upper().startswith("CVE-") or (len(query.split("-")) == 2 and query.replace("-", "").isdigit()):
        cve_id = query.upper() if query.upper().startswith("CVE-") else f"CVE-{query}"
        params["cveId"] = cve_id
    else:
        params["keywordSearch"] = query

    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=7, headers={"User-Agent": "ThunderRecon-CVE/1.0"})
        if resp.status_code != 200:
            return {"query": query, "total_results": 0, "cves": [], "error": f"NVD API returned status {resp.status_code}"}
        
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        cves = []
        for item in vulnerabilities:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "Unknown")
            published = cve_obj.get("published", "")[:10]
            last_modified = cve_obj.get("lastModified", "")[:10]

            # Description
            descriptions = cve_obj.get("descriptions", [])
            desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")

            # Metrics / CVSS Score
            metrics = cve_obj.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
            cvss_v2  = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})

            cvss = cvss_v31 or cvss_v30 or cvss_v2
            base_score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity") or (
                "CRITICAL" if base_score >= 9.0 else "HIGH" if base_score >= 7.0 else "MEDIUM" if base_score >= 4.0 else "LOW" if base_score > 0 else "UNKNOWN"
            )

            attack_vector = cvss.get("attackVector", "N/A")
            exploitability = cvss.get("exploitabilityScore", "N/A")

            # References
            references = [r.get("url") for r in cve_obj.get("references", [])[:5] if r.get("url")]

            cves.append({
                "cve_id": cve_id,
                "published": published,
                "last_modified": last_modified,
                "description": desc_en,
                "cvss_score": base_score,
                "severity": severity,
                "attack_vector": attack_vector,
                "vector_string": cvss.get("vectorString", ""),
                "references": references,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        return {
            "query": query,
            "total_results": total_results,
            "cves": cves,
        }
    except Exception as e:
        return {"query": query, "total_results": 0, "cves": [], "error": f"CVE search failed: {str(e)}"}
