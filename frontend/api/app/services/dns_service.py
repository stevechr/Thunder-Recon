"""
Deep DNS Record & Security Audit Service.
Queries A, AAAA, MX, NS, TXT, CAA, SOA, CNAME records, checks DNSSEC, and evaluates email authentication policies.
"""

import dns.resolver
import dns.flags
from urllib.parse import urlparse

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA", "CNAME"]

def inspect_dns_records(domain: str) -> dict:
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc.split(":")[0]
    
    # Strip port if present
    domain = domain.split(":")[0]

    records = {}
    total_records_count = 0

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.5
    resolver.lifetime = 3.5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            items = []
            for rdata in answers:
                if rtype == "MX":
                    items.append({"preference": rdata.preference, "exchange": str(rdata.exchange).rstrip(".")})
                elif rtype == "SOA":
                    items.append({
                        "mname": str(rdata.mname).rstrip("."),
                        "rname": str(rdata.rname).rstrip("."),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum,
                    })
                elif rtype == "TXT":
                    items.append(str(rdata).strip('"'))
                else:
                    items.append(str(rdata).rstrip("."))
            records[rtype] = items
            total_records_count += len(items)
        except Exception:
            records[rtype] = []

    # Check DNSSEC status
    dnssec_enabled = False
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
        resp = dns.query.udp(query, "8.8.8.8", timeout=3)
        if resp.flags & dns.flags.AD:
            dnssec_enabled = True
    except Exception:
        pass

    # Extract & Audit Email Security Policies (SPF / DMARC / DKIM)
    txt_records = records.get("TXT", [])
    spf_record = next((r for r in txt_records if r.startswith("v=spf1")), None)

    # Query DMARC record explicitly (_dmarc.domain)
    dmarc_record = None
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            txt_val = str(rdata).strip('"')
            if txt_val.startswith("v=DMARC1"):
                dmarc_record = txt_val
                break
    except Exception:
        pass

    # Mail Security Evaluation
    mail_security_findings = []
    if not spf_record:
        mail_security_findings.append({"level": "HIGH", "title": "Missing SPF Record", "detail": "Domain lacks an SPF policy, allowing unauthorized servers to spoof emails from this domain."})
    elif "+all" in spf_record or "?all" in spf_record:
        mail_security_findings.append({"level": "MEDIUM", "title": "Permissive SPF Policy", "detail": f"SPF ends with '{spf_record[-4:]}' instead of '-all' (hardfail)."})

    if not dmarc_record:
        mail_security_findings.append({"level": "HIGH", "title": "Missing DMARC Policy", "detail": "No _dmarc TXT record found. Emails failing SPF/DKIM will not be rejected or reported."})
    elif "p=none" in dmarc_record:
        mail_security_findings.append({"level": "MEDIUM", "title": "DMARC Policy is 'none'", "detail": "DMARC policy is set to 'p=none' (monitoring only). Spoofed emails are not blocked."})

    if not records.get("CAA"):
        mail_security_findings.append({"level": "LOW", "title": "Missing CAA Record", "detail": "No CAA records configured. Any Certificate Authority (CA) can issue certificates for this domain."})

    return {
        "domain": domain,
        "total_records": total_records_count,
        "dnssec_enabled": dnssec_enabled,
        "records": records,
        "mail_security": {
            "spf_record": spf_record,
            "dmarc_record": dmarc_record,
            "findings": mail_security_findings,
        }
    }
