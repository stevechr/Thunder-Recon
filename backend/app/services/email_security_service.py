"""
Email Security Analyzer Service.
Checks SPF, DKIM, and DMARC DNS records for a domain.
Grades overall email security posture A-F.
No API key required — pure DNS lookups.
"""

import dns.resolver
import dns.exception
import re
from typing import Optional

TIMEOUT = 6

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "email", "k1",
    "selector1", "selector2", "s1", "s2", "key1", "key2",
    "smtp", "mta", "mx", "proofpoint", "mimecast", "everlytickey1",
    "everlytickey2", "dkimla", "ctct1", "ctct2",
]


def _resolve_txt(name: str) -> list[str]:
    """Resolve TXT records for a DNS name."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT
        answers = resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            txt = " ".join(
                part.decode() if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            records.append(txt)
        return records
    except Exception:
        return []


def _resolve_mx(domain: str) -> list[dict]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT
        answers = resolver.resolve(domain, "MX")
        mx_list = []
        for rdata in sorted(answers, key=lambda r: r.preference):
            mx_list.append({
                "host": str(rdata.exchange).rstrip("."),
                "priority": rdata.preference,
            })
        return mx_list
    except Exception:
        return []


# ---------------------------------------------------------------------------
# SPF Analysis
# ---------------------------------------------------------------------------

def analyze_spf(domain: str) -> dict:
    """Parse and analyze the SPF record for a domain."""
    records = _resolve_txt(domain)
    spf_record = next((r for r in records if r.startswith("v=spf1")), None)

    if not spf_record:
        return {
            "found": False,
            "record": None,
            "grade": "F",
            "issues": ["No SPF record found — anyone can spoof email from this domain."],
            "mechanisms": [],
            "all_qualifier": None,
        }

    # Parse mechanisms
    mechanisms = spf_record.split()[1:]  # Skip v=spf1
    all_qualifier = None
    issues = []
    for m in mechanisms:
        if m.endswith("all"):
            all_qualifier = m

    # Grade
    if all_qualifier == "+all":
        grade = "F"
        issues.append("CRITICAL: '+all' allows anyone to send email as this domain!")
    elif all_qualifier == "?all":
        grade = "D"
        issues.append("'?all' (neutral) provides no protection — use '-all' or '~all'.")
    elif all_qualifier == "~all":
        grade = "B"
        issues.append("'~all' (softfail) is permissive — consider '-all' for strict enforcement.")
    elif all_qualifier == "-all":
        grade = "A"
    else:
        grade = "C"
        issues.append("No 'all' mechanism found — SPF record is incomplete.")

    # Check for lookup limit (max 10 DNS lookups)
    lookup_mechanisms = [m for m in mechanisms if any(
        m.startswith(p) for p in ("include:", "a:", "mx:", "redirect=", "exists:")
    )]
    if len(lookup_mechanisms) > 8:
        issues.append(f"High number of DNS lookups ({len(lookup_mechanisms)}) — may exceed 10-lookup limit causing errors.")

    return {
        "found": True,
        "record": spf_record,
        "grade": grade,
        "issues": issues,
        "mechanisms": mechanisms,
        "all_qualifier": all_qualifier,
        "lookup_count": len(lookup_mechanisms),
    }


# ---------------------------------------------------------------------------
# DKIM Analysis
# ---------------------------------------------------------------------------

def analyze_dkim(domain: str) -> dict:
    """Probe common DKIM selectors and return found public keys."""
    found_selectors = []

    for selector in DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = _resolve_txt(name)
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                # Extract key size hint
                key_match = re.search(r"p=([A-Za-z0-9+/=]+)", r)
                key_b64 = key_match.group(1) if key_match else None
                key_size_hint = None
                if key_b64:
                    # Rough estimate: base64 length → byte length → bit length
                    byte_len = (len(key_b64) * 3) // 4
                    key_size_hint = byte_len * 8

                version_match = re.search(r"v=DKIM1", r)
                algo_match = re.search(r"k=(\w+)", r)
                found_selectors.append({
                    "selector": selector,
                    "record": r[:200] + ("..." if len(r) > 200 else ""),
                    "algorithm": algo_match.group(1) if algo_match else "rsa",
                    "estimated_key_bits": key_size_hint,
                    "is_revoked": key_b64 == "" if key_b64 is not None else False,
                })
                break

    issues = []
    if not found_selectors:
        issues.append("No DKIM selectors found — emails cannot be authenticated via DKIM.")
    else:
        for fs in found_selectors:
            if fs["is_revoked"]:
                issues.append(f"Selector '{fs['selector']}' has an empty key (revoked DKIM key).")
            if fs["estimated_key_bits"] and fs["estimated_key_bits"] < 1024:
                issues.append(f"Selector '{fs['selector']}' appears to use a weak key (<1024 bits).")

    grade = "A" if found_selectors and not issues else ("B" if found_selectors else "F")

    return {
        "found": len(found_selectors) > 0,
        "selectors_found": found_selectors,
        "selectors_probed": len(DKIM_SELECTORS),
        "grade": grade,
        "issues": issues,
    }


# ---------------------------------------------------------------------------
# DMARC Analysis
# ---------------------------------------------------------------------------

def analyze_dmarc(domain: str) -> dict:
    """Parse the DMARC record for a domain."""
    records = _resolve_txt(f"_dmarc.{domain}")
    dmarc_record = next((r for r in records if r.startswith("v=DMARC1")), None)

    if not dmarc_record:
        return {
            "found": False,
            "record": None,
            "grade": "F",
            "policy": None,
            "subdomain_policy": None,
            "pct": None,
            "rua": None,
            "ruf": None,
            "issues": ["No DMARC record found — spoofed emails won't be rejected/quarantined."],
        }

    tags = {}
    for part in dmarc_record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none")
    subdomain_policy = tags.get("sp", policy)
    pct = int(tags.get("pct", 100))
    rua = tags.get("rua")
    ruf = tags.get("ruf")

    issues = []
    if policy == "none":
        grade = "C"
        issues.append("Policy 'none' only monitors — emails won't be rejected. Set p=quarantine or p=reject.")
    elif policy == "quarantine":
        grade = "B" if pct == 100 else "C"
        if pct < 100:
            issues.append(f"pct={pct}%: Only {pct}% of mail is evaluated. Raise to 100% for full enforcement.")
    elif policy == "reject":
        grade = "A" if pct == 100 else "B"
        if pct < 100:
            issues.append(f"pct={pct}%: Not fully enforced. Raise to 100% for maximum protection.")
    else:
        grade = "D"
        issues.append(f"Unknown policy '{policy}'.")

    if not rua:
        issues.append("No 'rua' reporting address — you won't receive aggregate DMARC reports.")

    if subdomain_policy == "none" and policy != "none":
        issues.append("Subdomain policy is 'none' — subdomains are unprotected from spoofing.")

    return {
        "found": True,
        "record": dmarc_record,
        "grade": grade,
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "pct": pct,
        "rua": rua,
        "ruf": ruf,
        "issues": issues,
        "adkim": tags.get("adkim", "r"),  # r=relaxed, s=strict
        "aspf": tags.get("aspf", "r"),
    }


# ---------------------------------------------------------------------------
# Overall Email Security Grade
# ---------------------------------------------------------------------------

GRADE_RANK = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}


def _overall_grade(spf_grade: str, dkim_grade: str, dmarc_grade: str) -> str:
    avg = (GRADE_RANK[spf_grade] + GRADE_RANK[dkim_grade] + GRADE_RANK[dmarc_grade]) / 3
    if avg >= 3.5:
        return "A"
    elif avg >= 2.5:
        return "B"
    elif avg >= 1.5:
        return "C"
    elif avg >= 0.5:
        return "D"
    return "F"


def analyze_email_security(domain: str) -> dict:
    """Full email security analysis for a domain."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")

    spf = analyze_spf(domain)
    dkim = analyze_dkim(domain)
    dmarc = analyze_dmarc(domain)
    mx = _resolve_mx(domain)

    overall = _overall_grade(spf["grade"], dkim["grade"], dmarc["grade"])

    all_issues = spf["issues"] + dkim["issues"] + dmarc["issues"]

    return {
        "domain": domain,
        "overall_grade": overall,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "mx_records": mx,
        "has_mx": len(mx) > 0,
        "all_issues": all_issues,
        "issue_count": len(all_issues),
    }
