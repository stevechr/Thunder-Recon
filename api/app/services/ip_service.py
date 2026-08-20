"""
IP Intelligence & Threat Assessment Service.
Provides geolocation, ASN/ISP details, reverse DNS, proxy/Tor exit node detection, and abuse reputation.
"""

import socket
import requests
from urllib.parse import urlparse

def lookup_ip_intelligence(query: str) -> dict:
    query = query.strip()
    
    # If a URL or domain was passed, extract or resolve IP
    if "://" in query:
        query = urlparse(query).netloc.split(":")[0]
    
    # Resolve domain if not a direct IP
    ip_address = query
    is_domain = False
    try:
        socket.inet_aton(query)
    except socket.error:
        # Not a valid IPv4, try resolving hostname
        try:
            ip_address = socket.gethostbyname(query)
            is_domain = True
        except Exception:
            raise ValueError(f"Could not resolve IP address for target '{query}'")

    # 1. Reverse DNS (PTR lookup)
    reverse_dns = None
    try:
        reverse_dns = socket.gethostbyaddr(ip_address)[0]
    except Exception:
        reverse_dns = "No PTR Record"

    # 2. Geolocation & ASN via ip-api.com (free public API)
    geo_data = {}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query",
            timeout=5
        )
        if resp.status_code == 200:
            geo_data = resp.json()
    except Exception as e:
        geo_data = {"status": "fail", "message": str(e)}

    # 3. Calculate Threat Score & Risk Indicators
    is_proxy = geo_data.get("proxy", False)
    is_hosting = geo_data.get("hosting", False)
    is_mobile = geo_data.get("mobile", False)
    
    threat_factors = []
    risk_score = 0

    if is_proxy:
        threat_factors.append({"type": "Proxy / VPN / Tor", "severity": "HIGH", "detail": "IP identified as an anonymizing proxy, VPN, or exit node."})
        risk_score += 45
    if is_hosting:
        threat_factors.append({"type": "Datacenter / Cloud Hosting", "severity": "MEDIUM", "detail": "IP originates from a cloud provider / datacenter block rather than residential ISP."})
        risk_score += 20
    if is_mobile:
        threat_factors.append({"type": "Mobile Cellular Network", "severity": "LOW", "detail": "Carrier mobile IP allocation."})

    # Heuristic threat rating
    if risk_score >= 50:
        threat_rating = "HIGH RISK"
        color = "critical"
    elif risk_score >= 20:
        threat_rating = "SUSPICIOUS / ELEVATED"
        color = "warn"
    else:
        threat_rating = "LOW RISK / RESIDENTIAL"
        color = "clean"

    return {
        "target": query,
        "resolved_ip": ip_address,
        "is_domain": is_domain,
        "reverse_dns": reverse_dns,
        "country": geo_data.get("country", "Unknown"),
        "country_code": geo_data.get("countryCode", "XX"),
        "region": geo_data.get("regionName", "Unknown"),
        "city": geo_data.get("city", "Unknown"),
        "zip": geo_data.get("zip", ""),
        "latitude": geo_data.get("lat", 0.0),
        "longitude": geo_data.get("lon", 0.0),
        "timezone": geo_data.get("timezone", "UTC"),
        "isp": geo_data.get("isp", "Unknown ISP"),
        "organization": geo_data.get("org", "Unknown Org"),
        "asn": geo_data.get("as", "Unknown ASN"),
        "is_proxy": is_proxy,
        "is_hosting": is_hosting,
        "is_mobile": is_mobile,
        "risk_score": risk_score,
        "threat_rating": threat_rating,
        "color": color,
        "threat_factors": threat_factors,
    }
