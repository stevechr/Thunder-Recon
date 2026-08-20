"""
ASN & BGP Intelligence Service.
Uses bgpview.io REST API (free, no key required).
Provides:
 - ASN lookup by IP address
 - ASN details (name, description, country, rir)
 - Prefixes announced by ASN (IPv4 + IPv6)
 - Peer ASN relationships (upstream/downstream)
 - IX (Internet Exchange) presence
"""

import requests
from typing import Optional

BASE_URL = "https://api.bgpview.io"
TIMEOUT = 10
HEADERS = {"User-Agent": "ThunderRecon/3.5 (security-research)"}


def _get(path: str) -> Optional[dict]:
    try:
        r = requests.get(f"{BASE_URL}{path}", timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "ok":
                return data.get("data", {})
    except Exception:
        pass
    return None


def get_asn_by_ip(ip: str) -> dict:
    """Resolve an IP to its owning ASN and return full ASN details."""
    data = _get(f"/ip/{ip}")
    if not data:
        return {"error": f"Could not resolve ASN for IP: {ip}"}

    prefixes = data.get("prefixes", [])
    rir_alloc = data.get("rir_allocation", {})
    related_prefixes = data.get("related_prefixes", [])

    # Primary ASN info from first prefix
    primary_asn = None
    if prefixes:
        first = prefixes[0]
        asn_info = first.get("asn", {})
        primary_asn = {
            "asn": asn_info.get("asn"),
            "name": asn_info.get("name", ""),
            "description": asn_info.get("description", ""),
            "country_code": asn_info.get("country_code", ""),
            "prefix": first.get("prefix", ""),
            "prefix_name": first.get("name", ""),
        }

    return {
        "ip": ip,
        "primary_asn": primary_asn,
        "rir_allocation": {
            "rir_name": rir_alloc.get("rir_name"),
            "country_code": rir_alloc.get("country_code"),
            "prefix": rir_alloc.get("prefix"),
            "date_allocated": rir_alloc.get("date_allocated"),
        },
        "prefixes_covering_ip": [
            {
                "prefix": p.get("prefix"),
                "name": p.get("name"),
                "asn": p.get("asn", {}).get("asn"),
                "asn_name": p.get("asn", {}).get("name"),
                "country_code": p.get("asn", {}).get("country_code"),
            }
            for p in prefixes
        ],
        "related_prefixes_count": len(related_prefixes),
    }


def get_asn_details(asn: int) -> dict:
    """Fetch full details for a given ASN number."""
    data = _get(f"/asn/{asn}")
    if not data:
        return {"error": f"Could not fetch details for AS{asn}"}

    return {
        "asn": data.get("asn"),
        "name": data.get("name", ""),
        "description_short": data.get("description_short", ""),
        "description_full": data.get("description_full", []),
        "country_code": data.get("country_code", ""),
        "website": data.get("website", ""),
        "email_contacts": data.get("email_contacts", []),
        "abuse_contacts": data.get("abuse_contacts", []),
        "looking_glass": data.get("looking_glass", ""),
        "traffic_estimation": data.get("traffic_estimation", ""),
        "traffic_ratio": data.get("traffic_ratio", ""),
        "rir_allocation": data.get("rir_allocation", {}),
        "iana_assignment": data.get("iana_assignment", {}),
        "date_updated": data.get("date_updated", ""),
    }


def get_asn_prefixes(asn: int) -> dict:
    """Fetch all IPv4 and IPv6 prefixes announced by an ASN."""
    data = _get(f"/asn/{asn}/prefixes")
    if not data:
        return {"error": f"Could not fetch prefixes for AS{asn}"}

    ipv4 = data.get("ipv4_prefixes", [])
    ipv6 = data.get("ipv6_prefixes", [])

    return {
        "asn": asn,
        "ipv4_count": len(ipv4),
        "ipv6_count": len(ipv6),
        "ipv4_prefixes": [
            {
                "prefix": p.get("prefix"),
                "ip": p.get("ip"),
                "cidr": p.get("cidr"),
                "name": p.get("name"),
                "country_code": p.get("country_code"),
                "description": p.get("description"),
                "parent": p.get("parent", {}).get("prefix"),
            }
            for p in ipv4[:50]  # Cap at 50 for performance
        ],
        "ipv6_prefixes": [
            {
                "prefix": p.get("prefix"),
                "name": p.get("name"),
                "country_code": p.get("country_code"),
            }
            for p in ipv6[:20]
        ],
    }


def get_asn_peers(asn: int) -> dict:
    """Fetch upstream/downstream BGP peers for an ASN."""
    data = _get(f"/asn/{asn}/peers")
    if not data:
        return {"error": f"Could not fetch peers for AS{asn}"}

    ipv4_peers = data.get("ipv4_peers", [])
    ipv6_peers = data.get("ipv6_peers", [])

    def summarize_peers(peers: list) -> list:
        return [
            {
                "asn": p.get("asn"),
                "name": p.get("name"),
                "description": p.get("description"),
                "country_code": p.get("country_code"),
            }
            for p in peers[:30]
        ]

    return {
        "asn": asn,
        "ipv4_peers_count": len(ipv4_peers),
        "ipv6_peers_count": len(ipv6_peers),
        "ipv4_peers": summarize_peers(ipv4_peers),
        "ipv6_peers": summarize_peers(ipv6_peers),
    }


def get_asn_ix(asn: int) -> dict:
    """Get Internet Exchange (IX) presence for an ASN."""
    data = _get(f"/asn/{asn}/ixs")
    if not data:
        return {"error": f"Could not fetch IX data for AS{asn}"}

    ix_list = data.get("ix", []) if isinstance(data, dict) else data
    if isinstance(data, list):
        ix_list = data

    return {
        "asn": asn,
        "ix_count": len(ix_list),
        "exchanges": [
            {
                "ix_id": ix.get("ix_id"),
                "name": ix.get("name"),
                "name_full": ix.get("name_full"),
                "country_code": ix.get("country_code"),
                "city": ix.get("city"),
                "ipv4_address": ix.get("ipv4_address"),
                "ipv6_address": ix.get("ipv6_address"),
                "speed": ix.get("speed"),
            }
            for ix in ix_list[:20]
        ],
    }


def full_asn_lookup(query: str) -> dict:
    """
    Unified ASN lookup. Accepts:
      - IP address (e.g. '8.8.8.8')
      - ASN number with or without 'AS' prefix (e.g. 'AS15169' or '15169')
    """
    query = query.strip()

    # Detect if it's an ASN number
    if query.upper().startswith("AS"):
        try:
            asn_num = int(query[2:])
        except ValueError:
            return {"error": "Invalid ASN format. Use AS15169 or 15169."}
    else:
        # Try to parse as integer (bare ASN)
        try:
            asn_num = int(query)
        except ValueError:
            asn_num = None

    if asn_num is not None:
        # Direct ASN lookup
        details = get_asn_details(asn_num)
        if "error" in details:
            return details
        prefixes = get_asn_prefixes(asn_num)
        peers = get_asn_peers(asn_num)
        ix = get_asn_ix(asn_num)
        return {
            "query": query,
            "query_type": "asn",
            "details": details,
            "prefixes": prefixes,
            "peers": peers,
            "internet_exchanges": ix,
        }
    else:
        # IP-based lookup
        ip_info = get_asn_by_ip(query)
        if "error" in ip_info:
            return ip_info

        primary = ip_info.get("primary_asn", {})
        asn_num = primary.get("asn") if primary else None

        result = {
            "query": query,
            "query_type": "ip",
            "ip_info": ip_info,
        }

        if asn_num:
            result["details"] = get_asn_details(asn_num)
            result["prefixes"] = get_asn_prefixes(asn_num)
            result["peers"] = get_asn_peers(asn_num)
            result["internet_exchanges"] = get_asn_ix(asn_num)

        return result
