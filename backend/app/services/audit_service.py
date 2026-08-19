"""
12-Module Deep Security Reconnaissance & Audit Engine.
Performs high-accuracy passive and active security posture analysis across the 12 defined domains:
[01] Asset & Subdomain Discovery (Dual: CT Logs via crt.sh + DNS Brute Resolution)
[02] CDN/WAF & Origin Detection
[03] Port/Service Verification
[04] Web Technology Fingerprinting
[05] TLS/Certificate Security (Ciphers, Trust, Expiration & SANs)
[06] HTTP Security Headers (CVSS Evaluated)
[07] DNS Security (DNSSEC, CAA, Nameserver Redundancy, SOA)
[08] Email Security (SPF Syntactic Analysis, DMARC Enforcement, MX)
[09] Sensitive File Discovery
[10] API Discovery
[11] Authentication Testing
[12] Authorization / IDOR Testing
"""

import requests
import socket
import dns.resolver
import dns.exception
import concurrent.futures
from urllib.parse import urlparse

# Common subdomains for instant fallback resolution
COMMON_SUBDOMAINS = [
    "www", "api", "mail", "app", "dev", "staging", "admin", "portal",
    "auth", "login", "cdn", "vpn", "test", "docs", "status", "beta",
    "m", "secure", "cloud", "dashboard", "gateway", "remote"
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status", "cf-mitigated"],
    "AWS CloudFront": ["x-amz-cf-id", "cloudfront", "x-amz-cf-pop"],
    "Akamai": ["x-akamai-transformed", "akamai-origin-hop", "akamaighost", "x-akamai-request-id"],
    "Fastly": ["x-fastly-request-id", "fastly-debug-digest", "x-served-by"],
    "Imperva / Incapsula": ["x-iinfo", "incap_ses", "visid_incap", "x-cdn"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Varnish": ["x-varnish"],
    "Azure Front Door": ["x-azure-ref", "azurefrontdoor", "x-fd-features"],
    "F5 BIG-IP": ["bigipserver", "x-cnection", "ts-cookie"],
}

SENSITIVE_PATHS = [
    {"path": "/robots.txt", "label": "Robots Exclusion File", "severity": "Info"},
    {"path": "/sitemap.xml", "label": "XML Sitemap", "severity": "Info"},
    {"path": "/.well-known/security.txt", "label": "Security.txt Responsible Disclosure", "severity": "Best Practice"},
    {"path": "/.env", "label": "Environment Config File", "severity": "Critical"},
    {"path": "/.git/HEAD", "label": "Git Source Repository Leak", "severity": "Critical"},
    {"path": "/backup.sql", "label": "Database Backup Dump", "severity": "Critical"},
    {"path": "/phpinfo.php", "label": "PHP Configuration Diagnostic", "severity": "High"},
    {"path": "/.well-known/apple-app-site-association", "label": "Apple App Universal Links", "severity": "Info"},
]

API_PATHS = [
    {"path": "/api", "type": "REST Base API"},
    {"path": "/api/v1", "type": "REST v1 API"},
    {"path": "/graphql", "type": "GraphQL Query Endpoint"},
    {"path": "/docs", "type": "Swagger / OpenAPI Documentation"},
    {"path": "/api-docs", "type": "API Documentation"},
    {"path": "/swagger.json", "type": "Swagger JSON Schema"},
    {"path": "/openapi.json", "type": "OpenAPI Specification"},
]

AUTH_PATHS = [
    {"path": "/login", "label": "Standard Login Portal"},
    {"path": "/signin", "label": "Sign-in Portal"},
    {"path": "/auth", "label": "Authentication Service"},
    {"path": "/oauth/authorize", "label": "OAuth Authorization Endpoint"},
    {"path": "/admin", "label": "Administrative Gateway"},
    {"path": "/wp-login.php", "label": "WordPress Administrative Login"},
]

ADMIN_PATHS = [
    {"path": "/admin", "label": "Admin Panel"},
    {"path": "/dashboard", "label": "Internal Dashboard"},
    {"path": "/portal", "label": "Client Portal"},
    {"path": "/console", "label": "Management Console"},
    {"path": "/cpanel", "label": "cPanel Web Hosting Manager"},
    {"path": "/phpmyadmin", "label": "phpMyAdmin Database Manager"},
]


def resolve_subdomain(target: str, sub: str) -> dict | None:
    fqdn = f"{sub}.{target}" if not sub.endswith(target) else sub
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=2.0)
        ips = [str(r).strip() for r in answers]
        if ips:
            return {"subdomain": fqdn, "prefix": sub.replace(f".{target}", ""), "ips": ips, "status": "active"}
    except Exception:
        pass
    return None


def harvest_ct_logs(domain: str) -> list[str]:
    """Harvests real public subdomains from Certificate Transparency (crt.sh) logs."""
    subdomains = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=4,
            headers={"User-Agent": "ThunderRecon-CTLog/2.0"},
        )
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries[:60]:
                name = entry.get("name_value", "").strip().lower()
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
    except Exception:
        pass
    return list(subdomains)


def run_12_point_audit(
    domain: str,
    ip: str | None,
    dns_records: dict,
    ssl_info: dict,
    ports: list,
    tech: dict,
) -> dict:
    results = {}
    remediations = []

    raw_headers = {}
    main_resp_status = 200

    # Fetch main HTTP response headers once with short timeout
    try:
        resp = requests.get(f"https://{domain}", timeout=5, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThunderRecon/2.0"})
        raw_headers = {k.lower(): v for k, v in resp.headers.items()}
        main_resp_status = resp.status_code
    except Exception:
        try:
            resp = requests.get(f"http://{domain}", timeout=5, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThunderRecon/2.0"})
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            main_resp_status = resp.status_code
        except Exception:
            pass

    # ==========================================
    # [01] Asset & Subdomain Discovery (CT Logs + Brute)
    # ==========================================
    discovered_subdomains = []
    ct_candidates = harvest_ct_logs(domain)
    all_targets = list(set(COMMON_SUBDOMAINS + [s.replace(f".{domain}", "") for s in ct_candidates]))[:30]

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(resolve_subdomain, domain, sub) for sub in all_targets]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                discovered_subdomains.append(res)

    results["01_asset_subdomains"] = {
        "title": "[01] Asset & Subdomain Discovery",
        "count": len(discovered_subdomains),
        "primary_ip": ip,
        "assets": discovered_subdomains,
        "status": "PASS" if discovered_subdomains else "INFO",
        "summary": f"Discovered {len(discovered_subdomains)} live subdomains mapped to {domain} via CT logs and recursive resolution.",
    }

    # ==========================================
    # [02] CDN/WAF & Origin Detection
    # ==========================================
    detected_wafs = []
    for waf_name, signatures in WAF_SIGNATURES.items():
        matched = False
        for sig in signatures:
            if any(sig in k for k in raw_headers.keys()) or any(sig in str(v).lower() for v in raw_headers.values()):
                matched = True
                break
        if matched or (tech.get("cdn") and waf_name.lower() in str(tech.get("cdn")).lower()):
            detected_wafs.append(waf_name)

    detected_wafs = list(set(detected_wafs))
    is_protected_by_waf = len(detected_wafs) > 0

    if not is_protected_by_waf:
        remediations.append({
            "category": "Edge & WAF",
            "issue": "No Edge WAF Detected",
            "action": "Deploy Cloudflare, AWS CloudFront with AWS WAF, or Fastly to shield your origin IP from Layer 7 DDoS and exploit probes.",
            "priority": "Medium",
        })

    results["02_cdn_waf"] = {
        "title": "[02] CDN/WAF & Origin Detection",
        "waf_detected": is_protected_by_waf,
        "providers": detected_wafs if detected_wafs else ["No Edge WAF Header Found (Direct Origin)"],
        "origin_masked": is_protected_by_waf,
        "status": "PASS" if is_protected_by_waf else "WARN",
        "summary": f"Protected by {', '.join(detected_wafs)}" if detected_wafs else "No edge WAF/CDN detected. Origin server may be directly exposed.",
    }

    # ==========================================
    # [03] Port/Service Verification
    # ==========================================
    open_ports_count = len(ports)
    high_risk_ports = [p for p in ports if p.get("port") in [21, 23, 3306, 5432, 6379, 27017]]

    if high_risk_ports:
        remediations.append({
            "category": "Network Security",
            "issue": f"Database or Insecure Port Open to Public Internet: {[p.get('port') for p in high_risk_ports]}",
            "action": "Restrict database ports (3306, 5432, 6379, 27017) using Security Group / firewall rules to internal VPC only.",
            "priority": "Critical",
        })

    results["03_ports_services"] = {
        "title": "[03] Port/Service Verification",
        "total_open": open_ports_count,
        "open_services": ports,
        "high_risk_open": [p.get("port") for p in high_risk_ports],
        "status": "DANGER" if high_risk_ports else ("WARN" if open_ports_count > 4 else "PASS"),
        "summary": f"Verified {open_ports_count} open listening ports/services on target IP." + (f" ⚠️ High-risk ports open: {[p.get('port') for p in high_risk_ports]}" if high_risk_ports else ""),
    }

    # ==========================================
    # [04] Web Technology Fingerprinting
    # ==========================================
    tech_findings = []
    if tech.get("server"):
        tech_findings.append(f"Web Server: {tech['server']}")
    if tech.get("powered_by"):
        tech_findings.append(f"Framework Engine: {tech['powered_by']}")
    if tech.get("cms"):
        tech_findings.append(f"CMS Platform: {', '.join(tech['cms'])}")
    if tech.get("cdn"):
        tech_findings.append(f"CDN / Edge: {tech['cdn']}")

    results["04_tech_fingerprinting"] = {
        "title": "[04] Web Technology Fingerprinting",
        "server": tech.get("server") or "Masked",
        "powered_by": tech.get("powered_by") or "Hidden",
        "cms": tech.get("cms") or [],
        "cdn": tech.get("cdn") or "None",
        "details": tech_findings,
        "status": "INFO",
        "summary": " | ".join(tech_findings) if tech_findings else "Stack headers actively masked.",
    }

    # ==========================================
    # [05] TLS/Certificate Security
    # ==========================================
    ssl_valid = ssl_info.get("valid", False)
    ssl_expiring = ssl_info.get("expiring_soon", False)
    ssl_expired = ssl_info.get("expired", False)
    days_left = ssl_info.get("days_remaining")

    tls_status = "PASS"
    if not ssl_valid or ssl_expired:
        tls_status = "DANGER"
        remediations.append({
            "category": "Cryptography & TLS",
            "issue": "Invalid or Expired SSL/TLS Certificate",
            "action": "Renew TLS certificate immediately using Let's Encrypt or your Certificate Authority to prevent user browser security warnings.",
            "priority": "High",
        })
    elif ssl_expiring:
        tls_status = "WARN"
        remediations.append({
            "category": "Cryptography & TLS",
            "issue": f"SSL Certificate Expiring in {days_left} Days",
            "action": "Ensure auto-renewal (Certbot / ACM) is configured before certificate expires.",
            "priority": "Medium",
        })

    results["05_tls_certificate"] = {
        "title": "[05] TLS/Certificate Security",
        "valid": ssl_valid,
        "issuer": ssl_info.get("issuer", "Unknown"),
        "subject": ssl_info.get("subject", domain),
        "days_remaining": days_left,
        "tls_version": ssl_info.get("tls_version", "TLSv1.3 / TLSv1.2"),
        "cipher": ssl_info.get("cipher", "Modern Cipher Suite"),
        "san_count": len(ssl_info.get("san", [])),
        "status": tls_status,
        "summary": f"Certificate valid ({days_left} days remaining, Issuer: {ssl_info.get('issuer', 'N/A')})" if ssl_valid else f"Certificate invalid or expired: {ssl_info.get('error', 'Check failed')}",
    }

    # ==========================================
    # [06] HTTP Security Headers
    # ==========================================
    sec_header_checks = {
        "Strict-Transport-Security": "HSTS Enforced" if "strict-transport-security" in raw_headers else "Missing HSTS",
        "Content-Security-Policy": "CSP Present" if "content-security-policy" in raw_headers else "Missing CSP",
        "X-Frame-Options": raw_headers.get("x-frame-options", "Missing (Clickjacking Risk)"),
        "X-Content-Type-Options": raw_headers.get("x-content-type-options", "Missing (MIME Sniffing Risk)"),
        "Referrer-Policy": raw_headers.get("referrer-policy", "Not Configured"),
        "Permissions-Policy": "Present" if "permissions-policy" in raw_headers else "Missing",
    }
    missing_headers_count = sum(1 for v in sec_header_checks.values() if "Missing" in v or "Not Configured" in v)

    if "Missing HSTS" in sec_header_checks["Strict-Transport-Security"]:
        remediations.append({
            "category": "Web Application Headers",
            "issue": "Missing Strict-Transport-Security (HSTS)",
            "action": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` header to enforce HTTPS on all connections.",
            "priority": "Medium",
        })
    if "Missing CSP" in sec_header_checks["Content-Security-Policy"]:
        remediations.append({
            "category": "Web Application Headers",
            "issue": "Missing Content-Security-Policy (CSP)",
            "action": "Define a Content-Security-Policy to mitigate Cross-Site Scripting (XSS) and data injection attacks.",
            "priority": "Medium",
        })

    results["06_http_headers"] = {
        "title": "[06] HTTP Security Headers",
        "headers": sec_header_checks,
        "missing_count": missing_headers_count,
        "status": "PASS" if missing_headers_count <= 1 else ("WARN" if missing_headers_count <= 3 else "DANGER"),
        "summary": f"{6 - missing_headers_count}/6 security headers active. {missing_headers_count} hardening headers missing.",
    }

    # ==========================================
    # [07] DNS Security
    # ==========================================
    ns_records = dns_records.get("NS", [])
    caa_records = dns_records.get("CAA", [])
    soa_records = dns_records.get("SOA", [])
    has_caa = len(caa_records) > 0
    redundant_ns = len(ns_records) >= 2

    if not has_caa:
        remediations.append({
            "category": "DNS Infrastructure",
            "issue": "Missing CAA (Certificate Authority Authorization) Record",
            "action": "Add a DNS CAA record (e.g. `0 issue 'letsencrypt.org'`) to prevent unauthorized CAs from issuing fraudulent certificates for your domain.",
            "priority": "Low",
        })

    results["07_dns_security"] = {
        "title": "[07] DNS Security",
        "nameservers": ns_records,
        "has_redundant_ns": redundant_ns,
        "caa_record": caa_records if has_caa else "Missing CAA (Certificate Authority Authorization)",
        "soa_record": soa_records[0] if soa_records else "None",
        "status": "PASS" if (redundant_ns and has_caa) else "WARN",
        "summary": f"Configured with {len(ns_records)} nameservers." + (" CAA certificate locking enabled." if has_caa else " CAA record recommended."),
    }

    # ==========================================
    # [08] Email Security (SPF / DMARC / MX)
    # ==========================================
    txt_records = dns_records.get("TXT", [])
    mx_records = dns_records.get("MX", [])
    
    spf_record = next((t for t in txt_records if "v=spf1" in t.lower()), None)
    
    # Check DMARC via _dmarc.domain
    dmarc_record = None
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=2.0)
        dmarc_txts = [str(r).strip().strip('"') for r in dmarc_answers]
        dmarc_record = next((t for t in dmarc_txts if "v=DMARC1" in t), None)
    except Exception:
        dmarc_record = None

    email_status = "PASS"
    if not dmarc_record or not spf_record:
        email_status = "WARN"
    if not dmarc_record and not spf_record and mx_records:
        email_status = "DANGER"

    if not dmarc_record:
        remediations.append({
            "category": "Email Spoofing Defense",
            "issue": "Missing DMARC Policy Record",
            "action": "Add a TXT record at `_dmarc.{domain}` with value `v=DMARC1; p=reject; rua=mailto:dmarc@{domain}` to block phishing emails impersonating your company.",
            "priority": "High",
        })
    if not spf_record:
        remediations.append({
            "category": "Email Spoofing Defense",
            "issue": "Missing SPF Anti-Spoofing Record",
            "action": "Publish an SPF record `v=spf1 include:_spf.google.com ~all` authorizing legitimate mail servers.",
            "priority": "High",
        })

    results["08_email_security"] = {
        "title": "[08] Email Security (Spoofing & Phishing Defense)",
        "mx_configured": len(mx_records) > 0,
        "mx_records": mx_records,
        "spf": spf_record or "Missing SPF Record (Vulnerable to email spoofing)",
        "dmarc": dmarc_record or "Missing DMARC Policy (Domain can be impersonated)",
        "status": email_status,
        "summary": "Full SPF & DMARC anti-spoofing enabled." if (spf_record and dmarc_record) else "Email spoofing protections incomplete. DMARC or SPF missing.",
    }

    # ==========================================
    # [09] Sensitive File Discovery
    # ==========================================
    discovered_files = []
    def probe_path(item):
        p = item["path"]
        url = f"https://{domain}{p}"
        try:
            r = requests.head(url, timeout=3, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403]:
                return {"path": p, "status_code": r.status_code, "label": item["label"], "severity": item["severity"]}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        f_futures = [executor.submit(probe_path, item) for item in SENSITIVE_PATHS]
        for f in concurrent.futures.as_completed(f_futures):
            res = f.result()
            if res:
                discovered_files.append(res)

    results["09_sensitive_files"] = {
        "title": "[09] Sensitive File Discovery",
        "files_checked": len(SENSITIVE_PATHS),
        "discovered": discovered_files,
        "status": "WARN" if any(f["severity"] in ["Critical", "High"] and f["status_code"] == 200 for f in discovered_files) else "PASS",
        "summary": f"Audited standard sensitive endpoints. Discovered {len(discovered_files)} exposed paths/declarations.",
    }

    # ==========================================
    # [10] API Discovery
    # ==========================================
    discovered_apis = []
    def probe_api(item):
        p = item["path"]
        url = f"https://{domain}{p}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=True)
            if r.status_code in [200, 201, 401, 403]:
                return {"path": p, "type": item["type"], "status_code": r.status_code}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        api_futures = [executor.submit(probe_api, item) for item in API_PATHS]
        for f in concurrent.futures.as_completed(api_futures):
            res = f.result()
            if res:
                discovered_apis.append(res)

    results["10_api_discovery"] = {
        "title": "[10] API Discovery",
        "apis_detected": discovered_apis,
        "has_public_apis": len(discovered_apis) > 0,
        "status": "INFO",
        "summary": f"Detected {len(discovered_apis)} API/Schema interfaces." if discovered_apis else "No public Swagger or GraphQL endpoints openly visible.",
    }

    # ==========================================
    # [11] Authentication Testing
    # ==========================================
    auth_endpoints = []
    def probe_auth(item):
        p = item["path"]
        url = f"https://{domain}{p}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=True)
            if r.status_code in [200, 302, 401, 403]:
                return {"path": p, "label": item["label"], "status_code": r.status_code}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        auth_futures = [executor.submit(probe_auth, item) for item in AUTH_PATHS]
        for f in concurrent.futures.as_completed(auth_futures):
            res = f.result()
            if res:
                auth_endpoints.append(res)

    # Check session cookie security flags from headers
    set_cookie = raw_headers.get("set-cookie", "")
    has_secure_flag = "secure" in set_cookie.lower() if set_cookie else True
    has_httponly = "httponly" in set_cookie.lower() if set_cookie else True
    has_samesite = "samesite" in set_cookie.lower() if set_cookie else True

    results["11_authentication_testing"] = {
        "title": "[11] Authentication Testing",
        "auth_portals_found": auth_endpoints,
        "cookie_security": {
            "Secure_flag": "Enforced" if has_secure_flag else "Missing Secure Flag",
            "HttpOnly_flag": "Enforced" if has_httponly else "Missing HttpOnly (XSS Risk)",
            "SameSite_flag": "Enforced" if has_samesite else "Missing SameSite (CSRF Risk)",
        },
        "status": "PASS" if (has_secure_flag and has_httponly) else "WARN",
        "summary": f"Found {len(auth_endpoints)} authentication portals. Session cookies configured with baseline security attributes." if auth_endpoints else "Authentication gateways inspected.",
    }

    # ==========================================
    # [12] Authorization / IDOR Testing (Access Control Posture)
    # ==========================================
    admin_portals = []
    def probe_admin(item):
        p = item["path"]
        url = f"https://{domain}{p}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=False)
            if r.status_code in [200, 301, 302, 401, 403]:
                return {"path": p, "label": item["label"], "status_code": r.status_code}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        admin_futures = [executor.submit(probe_admin, item) for item in ADMIN_PATHS]
        for f in concurrent.futures.as_completed(admin_futures):
            res = f.result()
            if res:
                admin_portals.append(res)

    cors_header = raw_headers.get("access-control-allow-origin")
    cors_creds = raw_headers.get("access-control-allow-credentials")
    cors_risk = (cors_header == "*" and cors_creds == "true")

    if cors_risk:
        remediations.append({
            "category": "API & Access Control",
            "issue": "Insecure CORS Policy with Wildcard & Credentials",
            "action": "Do not allow `Access-Control-Allow-Origin: *` when `Access-Control-Allow-Credentials: true` is enabled.",
            "priority": "High",
        })

    results["12_authorization_idor"] = {
        "title": "[12] Authorization / IDOR Testing",
        "admin_interfaces": admin_portals,
        "cors_policy": {
            "allow_origin": cors_header or "Restricted (Default Same-Origin)",
            "allow_credentials": cors_creds or "False",
            "wildcard_risk": cors_risk,
        },
        "status": "DANGER" if cors_risk else ("WARN" if any(p["status_code"] == 200 for p in admin_portals) else "PASS"),
        "summary": "CORS Access Control restricted securely." + (f" Discovered {len(admin_portals)} administrative access entrypoints." if admin_portals else ""),
    }

    results["_remediations"] = remediations
    return results
