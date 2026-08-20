import hashlib
import requests
from typing import Dict, Any, List

# Official XposedOrNot V1 & HIBP API endpoints
XPOSED_EMAIL_API = "https://api.xposedornot.com/v1/check-email/"
XPOSED_ANALYTICS_API = "https://api.xposedornot.com/v1/breach-analytics?email="
XPOSED_BREACHES_METADATA_API = "https://api.xposedornot.com/v1/breaches"
PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com/range/"

HEADERS = {
    "User-Agent": "ThunderRecon-BreachScanner/1.0",
    "Accept": "application/json"
}

# Cache metadata to avoid repetitive calls
_BREACHES_METADATA_CACHE: List[Dict[str, Any]] = []


def _get_all_breaches_metadata() -> List[Dict[str, Any]]:
    global _BREACHES_METADATA_CACHE
    if _BREACHES_METADATA_CACHE:
        return _BREACHES_METADATA_CACHE
    try:
        resp = requests.get(XPOSED_BREACHES_METADATA_API, headers=HEADERS, timeout=7)
        if resp.status_code == 200:
            data = resp.json()
            _BREACHES_METADATA_CACHE = data.get("exposedBreaches", [])
    except Exception:
        pass
    return _BREACHES_METADATA_CACHE


def check_domain_breaches(domain: str) -> Dict[str, Any]:
    """
    Advanced domain breach intelligence scanning matching direct host, subdomains, and corporate entity identities.
    """
    domain = domain.lower().strip()
    result = {
        "domain": domain,
        "breach_count": 0,
        "total_pwned_accounts": 0,
        "breaches": [],
        "risk_level": "Clean",
        "exposed_data_types": [],
        "has_sensitive_leaks": False,
        "threat_summary": ""
    }

    try:
        all_metadata = _get_all_breaches_metadata()
        all_data_types = set()
        total_accounts = 0

        clean_domain = domain.replace("www.", "").lower()
        domain_stem = clean_domain.split(".")[0]

        for b in all_metadata:
            b_domain = (b.get("domain") or "").lower().strip().replace("www.", "")
            b_id = b.get("breachID", b.get("name", ""))
            b_id_lower = b_id.lower()
            
            is_match = False
            if clean_domain and b_domain and (clean_domain in b_domain or b_domain in clean_domain):
                is_match = True
            elif len(domain_stem) > 3 and (domain_stem == b_id_lower or domain_stem == b_domain.split(".")[0]):
                is_match = True

            if is_match:
                x_data = b.get("exposedData", "") or b.get("xposedData", "")
                data_classes = [d.strip() for d in x_data.split(";") if d.strip()] if isinstance(x_data, str) else x_data
                all_data_types.update(data_classes)
                acc_count = b.get("exposedRecords", 0) or 0
                total_accounts += acc_count

                is_sensitive = any(term in str(data_classes).lower() for term in ["password", "financial", "ssn", "credit card", "bank", "hash"])
                if is_sensitive:
                    result["has_sensitive_leaks"] = True

                b_date = str(b.get("breachedDate", "Unknown"))
                formatted_date = b_date[:10] if len(b_date) >= 10 else b_date

                result["breaches"].append({
                    "name": b_id,
                    "title": b_id,
                    "domain": b_domain or clean_domain,
                    "breach_date": formatted_date,
                    "pwn_count": acc_count,
                    "data_classes": data_classes or ["User Accounts", "Email addresses"],
                    "description": b.get("exposureDescription", f"Security breach exposing {clean_domain} infrastructure/users."),
                    "is_verified": b.get("verified", "Yes") == "Yes",
                    "industry": b.get("industry", "Technology/Enterprise")
                })

        result["breach_count"] = len(result["breaches"])
        result["total_pwned_accounts"] = total_accounts
        result["exposed_data_types"] = sorted(list(all_data_types))

    except Exception as e:
        result["error"] = f"Breach API lookup timeout or limitation: {str(e)}"

    if result["breach_count"] == 0:
        result["risk_level"] = "Clean"
        result["threat_summary"] = f"No historical breach dumps found for {domain}."
    elif result["has_sensitive_leaks"] or result["breach_count"] > 3:
        result["risk_level"] = "Critical Risk"
        result["threat_summary"] = f"CRITICAL LEAK: {result['breach_count']} breach events exposing passwords/sensitive credentials."
    elif result["breach_count"] > 0:
        result["risk_level"] = "Moderate Risk"
        result["threat_summary"] = f"MODERATE EXPOSURE: Domain featured in {result['breach_count']} public leak datasets."

    return result


def check_email_breach(email: str) -> Dict[str, Any]:
    """
    Advanced email exposure search using combined XposedOrNot V1 Analytics & Check APIs.
    """
    email = email.lower().strip()
    result = {
        "email": email,
        "is_pwned": False,
        "breach_count": 0,
        "breaches": [],
        "exposed_data_types": [],
        "risk_level": "Safe",
        "analytics": {}
    }

    if not email or "@" not in email:
        result["error"] = "Invalid email format"
        return result

    try:
        # First try rich breach-analytics API
        analytics_resp = requests.get(f"{XPOSED_ANALYTICS_API}{email}", headers=HEADERS, timeout=8)
        if analytics_resp.status_code == 200:
            data = analytics_resp.json()
            exposed_breaches = data.get("ExposedBreaches", {}).get("breaches_details", [])
            if exposed_breaches:
                result["is_pwned"] = True
                result["breach_count"] = len(exposed_breaches)
                all_data_types = set()

                metrics = data.get("BreachMetrics", {})
                result["analytics"] = {
                    "risk_score": metrics.get("risk", [{}])[0].get("risk_score", 0) if metrics.get("risk") else 0,
                    "risk_label": metrics.get("risk", [{}])[0].get("risk_label", "Low") if metrics.get("risk") else "Low",
                    "password_strength": metrics.get("passwords_strength", [{}])[0] if metrics.get("passwords_strength") else {}
                }

                for b in exposed_breaches:
                    x_data = b.get("xposed_data", "")
                    data_classes = [d.strip() for d in x_data.split(";") if d.strip()] if isinstance(x_data, str) else x_data
                    all_data_types.update(data_classes)

                    result["breaches"].append({
                        "name": b.get("breach", "Data Leak"),
                        "title": b.get("breach", "Data Leak"),
                        "domain": b.get("domain", ""),
                        "breach_date": str(b.get("xposed_date", "Unknown")),
                        "pwn_count": b.get("xposed_records", 0),
                        "data_classes": data_classes or ["Email addresses", "Passwords"],
                        "description": b.get("details", "Exposed in third-party database breach."),
                        "industry": b.get("industry", "Web Service")
                    })
                result["exposed_data_types"] = sorted(list(all_data_types))

        # Fallback to simple v1 check-email if analytics yielded no breaches or errored
        if not result["is_pwned"]:
            resp = requests.get(f"{XPOSED_EMAIL_API}{email}", headers=HEADERS, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                breaches_list = data.get("breaches", [])
                if breaches_list and isinstance(breaches_list, list):
                    flat_breaches = []
                    for item in breaches_list:
                        if isinstance(item, list):
                            flat_breaches.extend(item)
                        else:
                            flat_breaches.append(item)

                    if flat_breaches:
                        result["is_pwned"] = True
                        result["breach_count"] = len(flat_breaches)
                        all_metadata = _get_all_breaches_metadata()
                        metadata_by_id = {b.get("breachID", "").lower(): b for b in all_metadata}
                        all_data_types = set()

                        for b_name in flat_breaches:
                            b_info = metadata_by_id.get(str(b_name).lower(), {})
                            x_data = b_info.get("exposedData", "") or "Email addresses;Passwords"
                            data_classes = [d.strip() for d in x_data.split(";") if d.strip()] if isinstance(x_data, str) else x_data
                            all_data_types.update(data_classes)

                            result["breaches"].append({
                                "name": str(b_name),
                                "title": b_info.get("breachID", str(b_name)),
                                "domain": b_info.get("domain", ""),
                                "breach_date": str(b_info.get("breachedDate", "Historical Leak"))[:10],
                                "pwn_count": b_info.get("exposedRecords", 0),
                                "data_classes": data_classes,
                                "description": b_info.get("exposureDescription", f"Credentials and account details exposed in {b_name} breach."),
                                "industry": b_info.get("industry", "Online Platform")
                            })
                        result["exposed_data_types"] = sorted(list(all_data_types))

    except Exception as e:
        result["error"] = f"Breach service error: {str(e)}"

    if result["is_pwned"]:
        if result["breach_count"] >= 4 or any("password" in d.lower() for d in result["exposed_data_types"]):
            result["risk_level"] = "HIGH EXPOSURE"
        else:
            result["risk_level"] = "MODERATE EXPOSURE"
    else:
        result["risk_level"] = "NO LEAKS FOUND"

    return result


def check_password_pwned(password: str) -> Dict[str, Any]:
    """
    k-Anonymity Passwords check using HaveIBeenPwned API.
    Sends only first 5 chars of SHA-1 hash to preserve complete zero-knowledge privacy.
    """
    if not password:
        return {"error": "Password cannot be empty"}

    # Compute SHA1 hash of the password
    sha1_pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_pwd[:5]
    suffix = sha1_pwd[5:]

    try:
        resp = requests.get(f"{PWNED_PASSWORDS_API}{prefix}", headers=HEADERS, timeout=6)
        if resp.status_code == 200:
            hashes = resp.text.splitlines()
            for line in hashes:
                parts = line.split(":")
                if len(parts) == 2:
                    line_suffix, count_str = parts[0].strip(), parts[1].strip()
                    if line_suffix == suffix:
                        count = int(count_str)
                        return {
                            "pwned": True,
                            "count": count,
                            "sha1_prefix": prefix,
                            "risk_level": "CRITICAL" if count > 100 else "HIGH",
                            "recommendation": f"This password has been seen {count:,} times in data breaches. Do not use it!"
                        }
            return {
                "pwned": False,
                "count": 0,
                "sha1_prefix": prefix,
                "risk_level": "SAFE",
                "recommendation": "This password was not found in known pwned database compilations."
            }
        else:
            return {"error": f"Pwned Passwords API returned HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": f"Failed to reach Pwned Passwords service: {str(e)}"}
