"""
WAF / Firewall Detection & Tester Service.
Performs active probe-based WAF fingerprinting and misconfiguration detection:
 1. WAF Vendor Detection (crafted payload headers + response analysis)
 2. HTTP Method Fuzzer (HEAD/OPTIONS/TRACE/PUT/DELETE response analysis)
 3. Rate Limit Probe (rapid burst requests to detect 429)
 4. CORS misconfiguration check
 5. Security headers baseline check
 6. TRACE method enabled detection
 7. Server banner disclosure
"""

import requests
import time
import concurrent.futures
from typing import Optional

TIMEOUT = 8
BASE_HEADERS = {"User-Agent": "Mozilla/5.0 ThunderRecon/3.5"}

# WAF signatures — header-based fingerprinting
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-mitigated", "cf-request-id"],
        "server": ["cloudflare"],
        "cookie": ["__cfduid", "__cf_bm"],
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-request-id"],
        "server": ["cloudfront"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id", "akamai-origin-hop"],
        "server": ["akamaighost", "akamai"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-debug-digest", "x-served-by", "x-cache-hits"],
        "server": ["fastly"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "cookie": ["incap_ses", "visid_incap"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-cnection", "ts"],
        "cookie": ["bigipserver", "ts"],
    },
    "Azure Front Door": {
        "headers": ["x-azure-ref", "x-fd-features", "x-msedge-ref"],
        "server": ["eas"],
    },
    "Varnish Cache": {
        "headers": ["x-varnish", "via"],
        "server": ["varnish"],
    },
    "Nginx": {
        "server": ["nginx"],
    },
    "Apache": {
        "server": ["apache"],
    },
}

# SQL injection / XSS probes to send (safe, logged as recon)
WAF_PROBE_PAYLOADS = [
    ("X-Forwarded-For", "' OR 1=1--"),
    ("X-Real-IP", "127.0.0.1' OR '1'='1"),
    ("User-Agent", "() { :; }; echo vulnerable"),  # Shellshock
    ("Referer", "<script>alert(1)</script>"),
]

HTTP_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT"]


def _make_request(url: str, method: str = "GET", headers: dict = None, timeout: int = TIMEOUT) -> Optional[requests.Response]:
    try:
        h = {**BASE_HEADERS, **(headers or {})}
        return requests.request(method, url, headers=h, timeout=timeout, allow_redirects=False)
    except Exception:
        return None


def _detect_waf_from_response(r: requests.Response) -> list[str]:
    """Identify WAF vendor from response headers and cookies."""
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
    cookies_lower = {k.lower(): v.lower() for k, v in r.cookies.items()}
    server_val = headers_lower.get("server", "")

    for waf_name, sigs in WAF_SIGNATURES.items():
        matched = False
        for header in sigs.get("headers", []):
            if header.lower() in headers_lower:
                matched = True
                break
        for srv in sigs.get("server", []):
            if srv.lower() in server_val:
                matched = True
                break
        for cookie in sigs.get("cookie", []):
            if cookie.lower() in cookies_lower:
                matched = True
                break
        if matched:
            detected.append(waf_name)

    return detected


def detect_waf(domain: str) -> dict:
    """Attempt WAF/CDN detection via normal request + crafted probe payloads."""
    url = f"https://{domain}" if not domain.startswith("http") else domain
    domain_clean = domain.replace("https://", "").replace("http://", "").split("/")[0]

    # Normal request
    normal_resp = _make_request(url)
    waf_detected = []
    headers_snapshot = {}

    if normal_resp is not None:
        waf_detected = _detect_waf_from_response(normal_resp)
        headers_snapshot = dict(normal_resp.headers)

    # Probe with malicious headers to trigger WAF
    blocked_by_payload = False
    probe_responses = []
    for header_name, payload in WAF_PROBE_PAYLOADS:
        r = _make_request(url, headers={header_name: payload})
        if r is not None:
            probe_responses.append({
                "probe_header": header_name,
                "status": r.status_code,
                "blocked": r.status_code in (403, 406, 429, 503),
            })
            if r.status_code in (403, 406, 429, 503):
                blocked_by_payload = True
                new_wafs = _detect_waf_from_response(r)
                for w in new_wafs:
                    if w not in waf_detected:
                        waf_detected.append(w)

    server_banner = headers_snapshot.get("Server", headers_snapshot.get("server", "Not disclosed"))
    x_powered_by = headers_snapshot.get("X-Powered-By", headers_snapshot.get("x-powered-by"))

    return {
        "domain": domain_clean,
        "waf_detected": waf_detected if waf_detected else ["None detected"],
        "waf_protected": len(waf_detected) > 0,
        "payload_blocked": blocked_by_payload,
        "server_banner": server_banner,
        "x_powered_by": x_powered_by,
        "probe_results": probe_responses,
        "response_headers": {
            k: v for k, v in headers_snapshot.items()
            if k.lower() in [
                "server", "x-powered-by", "cf-ray", "x-amz-cf-id",
                "x-fastly-request-id", "x-varnish", "via", "x-cache",
                "x-sucuri-id", "x-azure-ref",
            ]
        },
    }


def test_http_methods(domain: str) -> dict:
    """Test which HTTP methods are allowed by the server."""
    url = f"https://{domain}" if not domain.startswith("http") else domain

    results = []
    risky_methods_found = []

    def probe_method(method: str) -> dict:
        r = _make_request(url, method=method, timeout=6)
        is_risky = method in ("TRACE", "PUT", "DELETE", "CONNECT")
        if r is None:
            return {"method": method, "status": None, "allowed": False, "risky": is_risky}
        # TRACE enabled is a security risk (can expose headers / bypass CSRF)
        allowed = r.status_code not in (405, 501)
        return {
            "method": method,
            "status": r.status_code,
            "allowed": allowed,
            "risky": is_risky and allowed,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(probe_method, m): m for m in HTTP_METHODS}
        for f in concurrent.futures.as_completed(futures, timeout=20):
            try:
                res = f.result()
                results.append(res)
                if res.get("risky"):
                    risky_methods_found.append(res["method"])
            except Exception:
                pass

    results.sort(key=lambda r: HTTP_METHODS.index(r["method"]) if r["method"] in HTTP_METHODS else 99)

    return {
        "domain": domain,
        "methods_tested": len(results),
        "risky_methods_found": risky_methods_found,
        "has_risky_methods": len(risky_methods_found) > 0,
        "results": results,
    }


def check_cors(domain: str) -> dict:
    """Check for CORS misconfiguration."""
    url = f"https://{domain}" if not domain.startswith("http") else domain
    evil_origin = "https://evil.thunderrecon.io"

    r = _make_request(url, headers={"Origin": evil_origin})
    if r is None:
        return {"error": "Could not connect"}

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")

    is_wildcard = acao == "*"
    reflects_origin = acao == evil_origin
    dangerous = reflects_origin and acac.lower() == "true"

    severity = "OK"
    findings = []
    if dangerous:
        severity = "CRITICAL"
        findings.append("Server reflects arbitrary Origin with credentials=true — full CORS bypass possible.")
    elif reflects_origin:
        severity = "HIGH"
        findings.append("Server reflects arbitrary Origin header — potential CORS misconfiguration.")
    elif is_wildcard:
        severity = "MEDIUM"
        findings.append("Wildcard CORS (*) allows any origin — may expose API data.")

    return {
        "url": url,
        "cors_header": acao or "Not present",
        "allow_credentials": acac or "Not present",
        "is_wildcard": is_wildcard,
        "reflects_evil_origin": reflects_origin,
        "dangerous_combination": dangerous,
        "severity": severity,
        "findings": findings,
    }


def probe_rate_limit(domain: str, burst: int = 15) -> dict:
    """Send rapid requests and detect rate limiting."""
    url = f"https://{domain}" if not domain.startswith("http") else domain
    results = []
    start = time.time()

    def single_req(_):
        t0 = time.time()
        r = _make_request(url, timeout=5)
        latency = round((time.time() - t0) * 1000)
        if r:
            return {"status": r.status_code, "latency_ms": latency}
        return {"status": None, "latency_ms": latency}

    with concurrent.futures.ThreadPoolExecutor(max_workers=burst) as executor:
        futures = [executor.submit(single_req, i) for i in range(burst)]
        for f in concurrent.futures.as_completed(futures, timeout=15):
            try:
                results.append(f.result())
            except Exception:
                pass

    elapsed = round(time.time() - start, 2)
    statuses = [r["status"] for r in results if r["status"]]
    rate_limited_count = sum(1 for s in statuses if s == 429)
    blocked_count = sum(1 for s in statuses if s in (403, 503))
    avg_latency = round(sum(r["latency_ms"] for r in results) / len(results)) if results else 0

    return {
        "domain": domain,
        "burst_size": burst,
        "elapsed_seconds": elapsed,
        "responses": len(results),
        "rate_limited_count": rate_limited_count,
        "blocked_count": blocked_count,
        "rate_limiting_detected": rate_limited_count > 0,
        "avg_latency_ms": avg_latency,
        "status_distribution": {str(s): statuses.count(s) for s in set(statuses)},
    }


def run_waf_test(domain: str) -> dict:
    """Full WAF / firewall assessment."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    return {
        "domain": domain,
        "waf_detection": detect_waf(domain),
        "http_methods": test_http_methods(domain),
        "cors_check": check_cors(domain),
        "rate_limit": probe_rate_limit(domain),
    }
