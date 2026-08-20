"""
SSL/TLS certificate inspection service.
Connects on port 443 (or given port), pulls the certificate, and reports
issuer, validity window, days remaining, and negotiated TLS version.
"""
import socket
import ssl
from datetime import datetime, timezone


def get_ssl_info(domain: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_remaining = (not_after - datetime.now(timezone.utc)).days

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        return {
            "valid": True,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "subject": subject.get("commonName"),
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "days_remaining": days_remaining,
            "expired": days_remaining < 0,
            "expiring_soon": 0 <= days_remaining <= 30,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else None,
            "san": cert.get("subjectAltName", []),
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate verification failed: {e}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"valid": False, "error": f"Could not connect on port {port}: {e}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
