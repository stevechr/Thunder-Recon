"""
Simple heuristic risk scorer. Combines signals from other services into a
0-100 score plus a findings list. Replace with CVE/NVD lookups for a more
serious implementation.
"""

RISKY_PORTS = {21: "FTP (unencrypted)", 23: "Telnet (unencrypted)", 3389: "RDP exposed",
               3306: "MySQL exposed", 5432: "PostgreSQL exposed", 6379: "Redis exposed",
               27017: "MongoDB exposed", 445: "SMB exposed"}


def score(dns_records: dict, ssl_info: dict, ports: list[dict], tech: dict, breach_info: dict = None) -> dict:
    findings = []
    penalty = 0

    for p in ports:
        if p["port"] in RISKY_PORTS:
            findings.append(f"Risky service exposed: {RISKY_PORTS[p['port']]} on port {p['port']}")
            penalty += 15

    if ssl_info.get("valid") is False:
        findings.append(f"SSL/TLS issue: {ssl_info.get('error', 'invalid certificate')}")
        penalty += 20
    elif ssl_info.get("expired"):
        findings.append("SSL certificate has expired")
        penalty += 25
    elif ssl_info.get("expiring_soon"):
        findings.append(f"SSL certificate expires in {ssl_info.get('days_remaining')} days")
        penalty += 10

    headers = tech.get("security_headers", {})
    missing = [h for h, present in headers.items() if not present]
    if missing:
        findings.append(f"Missing security headers: {', '.join(missing)}")
        penalty += min(len(missing) * 3, 15)

    if not dns_records.get("CAA"):
        findings.append("No CAA record set (any CA can issue certs for this domain)")
        penalty += 5

    # Data breach risk scoring
    if breach_info and breach_info.get("breach_count", 0) > 0:
        b_count = breach_info["breach_count"]
        findings.append(f"Domain featured in {b_count} known data breaches / credential dumps")
        penalty += min(b_count * 10, 30)

        if breach_info.get("has_sensitive_leaks"):
            findings.append("Critical leak risk: Sensitive account data (passwords/hashes) exposed in historical breaches")
            penalty += 15

    score_value = max(0, 100 - penalty)
    if score_value >= 80:
        rating = "Low risk"
    elif score_value >= 50:
        rating = "Medium risk"
    else:
        rating = "High risk"

    return {"score": score_value, "rating": rating, "findings": findings}
