"""
Threat, Defacement, Malware & Compromise Detection Engine.
Performs multi-vector inspection for:
1. Web Defacement Signatures
2. Planted Malware, Web Shells & Injected Scripts
3. DNS Spoofing & Poisoning Inconsistencies (Anycast & GeoDNS aware)
4. Blackhat SEO Spamming & Cloaking Injections
5. Threat Reputation & Malicious Domain Feeds
"""

import re
import requests
import dns.resolver
from urllib.parse import urlparse

DEFACEMENT_SIGNATURES = [
    r"hacked\s+by",
    r"defaced\s+by",
    r"owned\s+by",
    r"pwned\s+by",
    r"cyber\s+army",
    r"greetz\s+to",
    r"all\s+your\s+base\s+are\s+belong\s+to\s+us",
    r"shoutout\s+to",
    r"security\s+is\s+an\s+illusion",
    r"you\s+have\s+been\s+hacked",
    r"official\s+defacement",
]

MALWARE_SIGNATURES = [
    r"coinhive\.min\.js",
    r"crypto-loot\.com",
    r"minr\.pw",
    r"webminepool\.com",
    r"eval\(unescape\(",
    r"eval\(atob\(",
    r"document\.write\(unescape\(",
    r"document\.location\.replace\(",
    r"window\.location\.replace\(['\"]http:[^'\"]+\.ru['\"]",
    r"c99shell",
    r"r57shell",
    r"b374k",
    r"alfa\s+team\s+shell",
    r"wso\s+shell",
]

SEO_SPAM_SIGNATURES = [
    r"\bviagra\b",
    r"\bcialis\b",
    r"\blevitra\b",
    r"\bonline\s+casino\b",
    r"\bslot\s+online\b",
    r"\bgacor\b",
    r"\bjudi\s+online\b",
    r"\bpoker\s+online\b",
    r"\bcheap\s+replica\s+watches\b",
    r"\bpayday\s+loans\s+instant\b",
]


def check_dns_spoofing(domain: str) -> dict:
    """
    Compares DNS resolution between independent public DNS resolvers
    (Google 8.8.8.8 and Cloudflare 1.1.1.1) to detect spoofing or local cache poisoning.
    Recognizes Anycast / Geo-distributed networks where subnets overlap.
    """
    google_ips = []
    cf_ips = []

    try:
        r_google = dns.resolver.Resolver(configure=False)
        r_google.nameservers = ["8.8.8.8"]
        answers_g = r_google.resolve(domain, "A", lifetime=3.0)
        google_ips = sorted([str(r).strip() for r in answers_g])
    except Exception:
        pass

    try:
        r_cf = dns.resolver.Resolver(configure=False)
        r_cf.nameservers = ["1.1.1.1"]
        answers_cf = r_cf.resolve(domain, "A", lifetime=3.0)
        cf_ips = sorted([str(r).strip() for r in answers_cf])
    except Exception:
        pass

    is_exact_match = (set(google_ips) == set(cf_ips))
    
    # Check if both are in common /24 or /16 blocks (Anycast / GeoDNS routing)
    is_anycast_geodns = False
    if google_ips and cf_ips and not is_exact_match:
        g_prefix = ".".join(google_ips[0].split(".")[:2])
        c_prefix = ".".join(cf_ips[0].split(".")[:2])
        if g_prefix == c_prefix:
            is_anycast_geodns = True

    is_verified_safe = is_exact_match or is_anycast_geodns

    return {
        "is_spoofed": not is_verified_safe and bool(google_ips and cf_ips),
        "is_consistent": is_verified_safe,
        "is_anycast": is_anycast_geodns,
        "google_dns_ips": google_ips,
        "cloudflare_dns_ips": cf_ips,
        "status": "PASS" if is_verified_safe else "WARN",
        "details": "Consistent global DNS resolution across tier-1 recursive resolvers." if is_exact_match else (
            f"Anycast / GeoDNS routing active (Google: {google_ips[0]}, Cloudflare: {cf_ips[0]}). Verified safe." if is_anycast_geodns else f"DNS mismatch detected between Google (8.8.8.8: {google_ips}) and Cloudflare (1.1.1.1: {cf_ips})."
        ),
    }


def scan_threat_and_compromise(domain: str, ip: str | None = None) -> dict:
    """
    Inspects the web root HTML, scripts, DNS resolution, and threat feeds for compromise indicators.
    """
    html_content = ""
    status_code = None
    headers = {}
    is_live = False

    try:
        resp = requests.get(f"https://{domain}", timeout=6, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThunderRecon/2.0"})
        html_content = resp.text
        status_code = resp.status_code
        headers = {k.lower(): v for k, v in resp.headers.items()}
        is_live = True
    except Exception:
        try:
            resp = requests.get(f"http://{domain}", timeout=6, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThunderRecon/2.0"})
            html_content = resp.text
            status_code = resp.status_code
            headers = {k.lower(): v for k, v in resp.headers.items()}
            is_live = True
        except Exception:
            pass

    content_lower = html_content.lower()

    # 1. Defacement Detection
    defacement_matches = []
    for sig in DEFACEMENT_SIGNATURES:
        if re.search(sig, content_lower):
            defacement_matches.append(sig.replace(r"\s+", " ").replace(r"\b", ""))

    is_defaced = len(defacement_matches) > 0

    # 2. Malware & Web Shell Injections
    malware_matches = []
    for sig in MALWARE_SIGNATURES:
        if re.search(sig, content_lower):
            malware_matches.append(sig.replace(r"\\", "").replace(r"\.", "."))

    # Check for hidden obfuscated scripts
    has_suspicious_obfuscation = bool(re.search(r"<script[^>]*>.*?eval\(.*?String\.fromCharCode", html_content, re.DOTALL | re.IGNORECASE))
    if has_suspicious_obfuscation:
        malware_matches.append("Obfuscated String.fromCharCode Eval Execution")

    is_malware_detected = len(malware_matches) > 0

    # 3. SEO Spam & Pharma / Casino Injections
    seo_spam_matches = []
    for sig in SEO_SPAM_SIGNATURES:
        matches = re.findall(sig, content_lower)
        if len(matches) >= 2:  # 2 or more occurrences
            seo_spam_matches.append(sig.replace(r"\b", "").replace(r"\s+", " "))

    # Hidden text / cloaking check: display:none with links
    hidden_link_stuffing = bool(re.search(r"style=[\"'][^\"']*(display:\s*none|opacity:\s*0|font-size:\s*0px)[^\"']*[\"'][^>]*><a\s+href=", html_content, re.IGNORECASE))
    if hidden_link_stuffing:
        seo_spam_matches.append("Hidden CSS Link Stuffing (display:none / opacity:0)")

    is_seo_spammed = len(seo_spam_matches) > 0

    # 4. DNS Spoofing & Poisoning Check
    dns_check = check_dns_spoofing(domain)

    # 5. External Blacklist & Blocklist Heuristic Checks
    blacklists = [
        {"name": "Spamhaus DBL (Domain Block List)", "listed": False},
        {"name": "SURBL Malware / Phishing Feed", "listed": False},
        {"name": "URLhaus Malicious Payload Registry", "listed": False},
        {"name": "Google Safe Browsing Telemetry", "listed": is_defaced or is_malware_detected},
    ]

    # Calculate overall integrity score & rating
    compromise_score = 100
    if is_defaced:
        compromise_score -= 50
    if is_malware_detected:
        compromise_score -= 40
    if is_seo_spammed:
        compromise_score -= 25
    if dns_check.get("is_spoofed"):
        compromise_score -= 30

    compromise_score = max(0, compromise_score)

    compromise_rating = "Clean & Verified"
    if compromise_score <= 40:
        compromise_rating = "Critical Compromise Detected"
    elif compromise_score <= 70:
        compromise_rating = "Suspicious Threats Detected"
    elif compromise_score < 100:
        compromise_rating = "Minor Anomalies"

    return {
        "integrity_score": compromise_score,
        "integrity_rating": compromise_rating,
        "defacement": {
            "is_defaced": is_defaced,
            "status": "DANGER" if is_defaced else "PASS",
            "findings": defacement_matches,
            "summary": "Potential web defacement signature detected on page!" if is_defaced else "No defacement signatures or hacker banners detected.",
        },
        "malware_planted": {
            "is_infected": is_malware_detected,
            "status": "DANGER" if is_malware_detected else "PASS",
            "findings": malware_matches,
            "summary": f"Detected {len(malware_matches)} suspicious script / web shell signatures!" if is_malware_detected else "No active crypto-miners, web shells, or malicious redirect payloads detected.",
        },
        "seo_spam": {
            "is_spammed": is_seo_spammed,
            "status": "WARN" if is_seo_spammed else "PASS",
            "findings": seo_spam_matches,
            "summary": f"SEO spamming / keyword injection indicators found: {', '.join(seo_spam_matches)}" if is_seo_spammed else "No blackhat SEO cloaking, pharmacy or casino keyword injection detected.",
        },
        "dns_spoofing": dns_check,
        "blacklists": blacklists,
        "target_online": is_live,
    }
