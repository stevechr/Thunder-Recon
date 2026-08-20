"""
DNS enumeration service.
Resolves standard record types for a target domain using dnspython.
"""
import dns.resolver
import dns.exception

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]


def _resolve(domain: str, record_type: str):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5.0)
        return [str(r).strip() for r in answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    except Exception:
        return []


def get_dns_records(domain: str) -> dict:
    """Return a dict of record_type -> list of values for the domain."""
    results = {}
    for record_type in RECORD_TYPES:
        values = _resolve(domain, record_type)
        if values:
            results[record_type] = values
    return results


def get_primary_ip(domain: str) -> str | None:
    a_records = _resolve(domain, "A")
    return a_records[0] if a_records else None
