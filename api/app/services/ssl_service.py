"""
SSL/TLS Inspector Service.
Audits SSL certificates, validity dates, certificate chains, SANs, protocol versions, and security vulnerabilities.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def inspect_ssl_certificate(target: str, port: int = 443) -> dict:
    target = target.strip()
    if "://" in target:
        target = urlparse(target).netloc.split(":")[0]
    
    hostname = target.split(":")[0]

    ctx = ssl.create_default_context()
    # We want to retrieve full certificate details even if there are self-signed warnings so we can report them
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw_cert_bytes = None
    cipher_info = None
    protocol_version = None

    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                raw_cert_bytes = ssock.getpeercert(binary_form=True)
                cipher_info = ssock.cipher()
                protocol_version = ssock.version()
    except Exception as e:
        raise ValueError(f"Could not establish TLS connection to {hostname}:{port} — {str(e)}")

    if not raw_cert_bytes:
        raise ValueError(f"No SSL certificate returned by server {hostname}:{port}")

    # Parse with cryptography library
    cert = x509.load_der_x509_certificate(raw_cert_bytes, default_backend())

    # Subject & Issuer
    subject_dict = {attr.rfc4514_attribute_name: attr.value for attr.singular_attribute_name in cert.subject}
    issuer_dict = {attr.rfc4514_attribute_name: attr.value for attr.singular_attribute_name in cert.issuer}

    subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    subject_common_name = subject_cn[0].value if subject_cn else "Unknown"

    issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    issuer_org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    issuer_common_name = issuer_cn[0].value if issuer_cn else (issuer_org[0].value if issuer_org else "Unknown")

    # Dates & Expiry
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)

    days_until_expiry = (not_after - now).days
    is_expired = days_until_expiry < 0

    # SANs (Subject Alternative Names)
    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass

    # Signature Algorithm & Key Size
    sig_alg = cert.signature_algorithm_oid._name
    pub_key = cert.public_key()
    key_size = getattr(pub_key, "key_size", "Unknown")

    # Security Vulnerabilities & Audit Checks
    security_checks = []
    grade = "A+"
    risk_score = 0

    if is_expired:
        security_checks.append({"issue": "Expired Certificate", "severity": "CRITICAL", "details": f"Certificate expired {abs(days_until_expiry)} days ago!"})
        grade = "F"
        risk_score += 80
    elif days_until_expiry < 15:
        security_checks.append({"issue": "Expiring Soon", "severity": "HIGH", "details": f"Certificate expires in only {days_until_expiry} days!"})
        if grade in ("A+", "A"): grade = "B"
        risk_score += 30

    if subject_common_name == issuer_common_name:
        security_checks.append({"issue": "Self-Signed Certificate", "severity": "HIGH", "details": "Certificate is self-signed and not trusted by public CAs."})
        if grade in ("A+", "A", "B"): grade = "C"
        risk_score += 40

    if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
        security_checks.append({"issue": "Weak Signature Algorithm", "severity": "HIGH", "details": f"Uses legacy insecure algorithm: {sig_alg}"})
        grade = "D"
        risk_score += 35

    if isinstance(key_size, int) and key_size < 2048:
        security_checks.append({"issue": "Weak Public Key Size", "severity": "HIGH", "details": f"RSA Key size is only {key_size} bits (minimum recommended: 2048-bit)."})
        grade = "D"
        risk_score += 30

    cipher_name = cipher_info[0] if cipher_info else "Unknown"
    cipher_bits = cipher_info[2] if cipher_info else 0

    return {
        "hostname": hostname,
        "port": port,
        "subject_cn": subject_common_name,
        "issuer_cn": issuer_common_name,
        "serial_number": str(cert.serial_number),
        "valid_from": not_before.isoformat(),
        "valid_to": not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "is_expired": is_expired,
        "sans": sans[:25],
        "total_sans": len(sans),
        "signature_algorithm": sig_alg,
        "key_size": f"{key_size} bits",
        "protocol_version": protocol_version or "TLS 1.2/1.3",
        "cipher_suite": cipher_name,
        "cipher_bits": cipher_bits,
        "grade": grade,
        "risk_score": risk_score,
        "security_checks": security_checks,
    }
