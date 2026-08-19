"""
IP + WHOIS intelligence service.
- WHOIS via python-whois
- IP geolocation / ASN / ISP via ip-api.com (free tier, no key required)
"""
import socket
import requests
import whois as whois_lib


def get_whois(domain: str) -> dict:
    try:
        # Avoid blocking indefinitely on whois socket lookups
        w = whois_lib.whois(domain)
        return {
            "registrar": _flatten(w.get("registrar")),
            "creation_date": _flatten(w.get("creation_date")),
            "expiration_date": _flatten(w.get("expiration_date")),
            "updated_date": _flatten(w.get("updated_date")),
            "name_servers": _flatten(w.get("name_servers")),
            "org": _flatten(w.get("org")),
            "country": _flatten(w.get("country")),
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed or timed out: {e}"}


def _flatten(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None:
        return None
    return str(value)


def resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_ip_intel(ip: str) -> dict:
    """Query ip-api.com for ASN/ISP/geo info. Free, no key, rate-limited to 45 req/min."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,isp,org,as,reverse,query"},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") != "success":
            return {"error": data.get("message", "lookup failed")}
        return {
            "ip": data.get("query"),
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "reverse_dns": data.get("reverse"),
        }
    except Exception as e:
        return {"error": f"IP intel lookup failed: {e}"}
