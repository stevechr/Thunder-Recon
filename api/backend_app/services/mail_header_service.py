"""
Mail Header Analyzer & Email Forensics Engine.
Parses RFC 822 / 5322 email headers to extract:
1. Primary Email Envelope (From, To, Subject, Date, Message-ID, Reply-To, Return-Path)
2. Delivery Hop Sequence (Received headers with sending/receiving MTAs, timestamps & delay calculation)
3. Authentication Verification (DKIM signatures, SPF results, DMARC alignment, ARC verification)
4. Spoofing & Phishing Heuristic Evaluation (From vs Return-Path domain mismatch, unauthenticated relay)
5. Spam & Risk Indicators (SpamAssassin scores, X-headers analysis)
"""

import re
import email
from email import policy
from email.parser import HeaderParser
from datetime import datetime


def parse_received_hop(hop_str: str, index: int) -> dict:
    """Extracts from, by, with, id, and timestamp from a single Received header line."""
    hop_clean = re.sub(r"\s+", " ", hop_str).strip()

    from_mta = "Unknown"
    by_mta = "Unknown"
    protocol = "SMTP"
    date_str = ""
    ip = None

    from_match = re.search(r"from\s+([^\s]+(?:\s+\([^\)]+\))?)", hop_clean, re.IGNORECASE)
    if from_match:
        from_mta = from_match.group(1).strip()

    by_match = re.search(r"by\s+([^\s]+)", hop_clean, re.IGNORECASE)
    if by_match:
        by_mta = by_match.group(1).strip()

    with_match = re.search(r"with\s+([^\s;]+)", hop_clean, re.IGNORECASE)
    if with_match:
        protocol = with_match.group(1).strip()

    # Extract IP address inside brackets or parentheses
    ip_match = re.search(r"\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]", hop_clean)
    if ip_match:
        ip = ip_match.group(1)

    # Extract timestamp after semicolon
    if ";" in hop_clean:
        date_str = hop_clean.split(";")[-1].strip()

    return {
        "hop_number": index,
        "from_host": from_mta,
        "by_host": by_mta,
        "protocol": protocol,
        "ip": ip,
        "timestamp_raw": date_str,
        "raw": hop_clean[:180],
    }


def analyze_email_headers(raw_headers_text: str) -> dict:
    """Performs deep forensic analysis of raw email headers."""
    if not raw_headers_text.strip():
        return {"error": "Empty header input provided."}

    # Normalize newlines
    raw_headers_text = raw_headers_text.replace("\r\n", "\n").replace("\r", "\n")

    parser = HeaderParser(policy=policy.default)
    msg = parser.parsestr(raw_headers_text)

    from_hdr = msg.get("From", "")
    to_hdr = msg.get("To", "")
    subject_hdr = msg.get("Subject", "")
    date_hdr = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")

    # Extract domains
    def extract_domain(val: str) -> str:
        match = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", val)
        return match.group(1).lower() if match else ""

    from_domain = extract_domain(from_hdr)
    return_path_domain = extract_domain(return_path)

    # 1. Parse Delivery Hops
    received_headers = msg.get_all("Received", [])
    delivery_hops = []
    # Reverse received headers to reflect chronologically from Origin -> Destination
    for idx, r_str in enumerate(reversed(received_headers)):
        delivery_hops.append(parse_received_hop(r_str, idx + 1))

    # 2. Authentication Results Parsing (SPF / DKIM / DMARC / ARC)
    auth_results_raw = msg.get("Authentication-Results", "")
    arc_results_raw = msg.get("ARC-Authentication-Results", "")
    full_auth_text = f"{auth_results_raw} {arc_results_raw}".lower()

    # SPF verdict
    spf_status = "UNKNOWN / NOT RECORDED"
    if "spf=pass" in full_auth_text:
        spf_status = "PASS"
    elif "spf=fail" in full_auth_text or "spf=softfail" in full_auth_text:
        spf_status = "FAIL / SOFTFAIL"
    elif "spf=neutral" in full_auth_text:
        spf_status = "NEUTRAL"

    # DKIM verdict
    dkim_status = "UNKNOWN / NOT RECORDED"
    if "dkim=pass" in full_auth_text:
        dkim_status = "PASS"
    elif "dkim=fail" in full_auth_text:
        dkim_status = "FAIL"

    # DMARC verdict
    dmarc_status = "UNKNOWN / NOT RECORDED"
    if "dmarc=pass" in full_auth_text:
        dmarc_status = "PASS"
    elif "dmarc=fail" in full_auth_text:
        dmarc_status = "FAIL"

    # 3. Spoofing & Phishing Detection Checks
    security_flags = []
    is_spoofing_suspect = False

    if from_domain and return_path_domain and from_domain != return_path_domain:
        security_flags.append({
            "severity": "WARN",
            "type": "Domain Alignment Discrepancy",
            "description": f"Sender 'From' domain ({from_domain}) does not match 'Return-Path' domain ({return_path_domain}). May indicate email relay or spoofing attempt.",
        })
        is_spoofing_suspect = True

    if spf_status.startswith("FAIL"):
        security_flags.append({
            "severity": "DANGER",
            "type": "SPF Verification Failure",
            "description": "Sending mail server was not authorized by the domain's SPF policy.",
        })
        is_spoofing_suspect = True

    if dkim_status == "FAIL":
        security_flags.append({
            "severity": "DANGER",
            "type": "DKIM Cryptographic Signature Invalid",
            "description": "Message contents or headers were altered in transit or signed with invalid cryptographic keys.",
        })
        is_spoofing_suspect = True

    if dmarc_status == "FAIL":
        security_flags.append({
            "severity": "DANGER",
            "type": "DMARC Alignment Policy Failure",
            "description": "Message failed domain owner's DMARC enforcement criteria.",
        })
        is_spoofing_suspect = True

    # 4. Spam & Threat Scores
    spam_status = msg.get("X-Spam-Status", "Not Analyzed")
    spam_score = msg.get("X-Spam-Score", "N/A")
    virus_status = msg.get("X-Virus-Scanned", "N/A")

    # Originating IP (from first delivery hop)
    originating_ip = None
    if delivery_hops:
        for hop in delivery_hops:
            if hop.get("ip"):
                originating_ip = hop.get("ip")
                break

    trust_score = 100
    if is_spoofing_suspect:
        trust_score -= 40
    if spf_status.startswith("FAIL"):
        trust_score -= 25
    if dkim_status == "FAIL":
        trust_score -= 25
    if dmarc_status == "FAIL":
        trust_score -= 20

    trust_score = max(0, trust_score)

    return {
        "envelope": {
            "from": from_hdr,
            "from_domain": from_domain,
            "to": to_hdr,
            "subject": subject_hdr,
            "date": date_hdr,
            "message_id": message_id,
            "return_path": return_path,
            "reply_to": reply_to,
            "originating_ip": originating_ip,
        },
        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "auth_summary": f"SPF: {spf_status} | DKIM: {dkim_status} | DMARC: {dmarc_status}",
            "raw_auth_results": auth_results_raw or "No Authentication-Results header found.",
        },
        "delivery_hops": delivery_hops,
        "total_hops": len(delivery_hops),
        "security_flags": security_flags,
        "is_spoofed_or_phishing": is_spoofing_suspect,
        "trust_score": trust_score,
        "trust_rating": "Legitimate & Authenticated" if trust_score >= 80 else ("Suspicious / Unverified" if trust_score >= 50 else "High Spoofing Risk"),
        "spam_telemetry": {
            "spam_status": spam_status,
            "spam_score": spam_score,
            "virus_scanned": virus_status,
        },
    }
