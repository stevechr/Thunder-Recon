"""
WHOIS & Domain Registration Intelligence Service.
Extracts domain age, creation/expiration dates, registrar, name servers, and WHOIS privacy flags.
"""

import whois
from datetime import datetime
from urllib.parse import urlparse

def lookup_whois_record(domain: str) -> dict:
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc.split(":")[0]
    
    domain = domain.split(":")[0]

    try:
        w = whois.whois(domain)
    except Exception as e:
        raise ValueError(f"WHOIS lookup failed for {domain}: {str(e)}")

    def format_date(dt):
        if isinstance(dt, list):
            dt = dt[0]
        if isinstance(dt, datetime):
            return dt.strftime("%Y-%m-%d")
        return str(dt) if dt else "Unknown"

    creation_date = format_date(w.creation_date)
    expiration_date = format_date(w.expiration_date)
    updated_date = format_date(w.updated_date)

    # Calculate domain age in days
    domain_age_days = None
    if isinstance(w.creation_date, datetime):
        domain_age_days = (datetime.now() - w.creation_date).days
    elif isinstance(w.creation_date, list) and isinstance(w.creation_date[0], datetime):
        domain_age_days = (datetime.now() - w.creation_date[0]).days

    days_to_expiry = None
    if isinstance(w.expiration_date, datetime):
        days_to_expiry = (w.expiration_date - datetime.now()).days
    elif isinstance(w.expiration_date, list) and isinstance(w.expiration_date[0], datetime):
        days_to_expiry = (w.expiration_date[0] - datetime.now()).days

    name_servers = w.name_servers if w.name_servers else []
    if isinstance(name_servers, list):
        name_servers = [str(ns).lower() for ns in name_servers]
    else:
        name_servers = [str(name_servers).lower()]

    registrar = w.registrar if w.registrar else "Unknown Registrar"
    emails = w.emails if w.emails else []
    if isinstance(emails, str):
        emails = [emails]

    status = w.status if w.status else []
    if isinstance(status, str):
        status = [status]

    is_recently_registered = domain_age_days is not None and domain_age_days < 30

    return {
        "domain": domain,
        "registrar": registrar,
        "whois_server": w.whois_server or "Unknown",
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": updated_date,
        "domain_age_days": domain_age_days,
        "days_to_expiry": days_to_expiry,
        "is_recently_registered": is_recently_registered,
        "name_servers": name_servers[:10],
        "abuse_emails": emails[:5],
        "domain_status": [str(s).split()[0] for s in status[:5]],
        "raw_text": str(w.text)[:1500] if hasattr(w, "text") and w.text else "",
    }
