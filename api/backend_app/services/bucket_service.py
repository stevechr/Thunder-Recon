"""
Cloud Storage Bucket Finder Service.
Enumerates potential open cloud storage buckets for a target domain/brand.

Checks:
  - AWS S3 buckets (s3.amazonaws.com)
  - Google Cloud Storage (storage.googleapis.com)
  - Azure Blob Storage (blob.core.windows.net)
  - DigitalOcean Spaces (digitaloceanspaces.com)

Requires authorized=True since it performs active HTTP probes.
"""

import requests
import concurrent.futures
from typing import Optional

TIMEOUT = 6
HEADERS = {"User-Agent": "Mozilla/5.0 ThunderRecon/3.5 Security Research"}


BUCKET_STATUS = {
    200: "OPEN",           # Public, readable
    403: "PRIVATE",        # Exists but access denied
    404: "NOT_FOUND",      # Doesn't exist
    301: "REDIRECT",
    400: "BAD_REQUEST",
}


def _generate_bucket_names(brand: str) -> list[str]:
    """Generate common bucket name permutations for a brand."""
    brand = brand.lower().replace(".", "-").replace("_", "-")
    permutations = [
        brand,
        f"{brand}-prod",
        f"{brand}-production",
        f"{brand}-dev",
        f"{brand}-development",
        f"{brand}-staging",
        f"{brand}-stage",
        f"{brand}-test",
        f"{brand}-backup",
        f"{brand}-backups",
        f"{brand}-bak",
        f"{brand}-data",
        f"{brand}-files",
        f"{brand}-assets",
        f"{brand}-media",
        f"{brand}-static",
        f"{brand}-uploads",
        f"{brand}-images",
        f"{brand}-logs",
        f"{brand}-archive",
        f"{brand}-public",
        f"{brand}-private",
        f"{brand}-internal",
        f"{brand}-content",
        f"{brand}-cdn",
        f"{brand}-storage",
        f"dev-{brand}",
        f"staging-{brand}",
        f"prod-{brand}",
        f"s3-{brand}",
        f"{brand}-s3",
    ]
    return list(dict.fromkeys(permutations))  # deduplicate


def _probe_s3(bucket_name: str) -> Optional[dict]:
    """Check an AWS S3 bucket."""
    url = f"https://{bucket_name}.s3.amazonaws.com"
    path_url = f"https://s3.amazonaws.com/{bucket_name}"
    try:
        r = requests.head(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=False)
        status = r.status_code
        state = BUCKET_STATUS.get(status, f"HTTP_{status}")
        if status in (200, 403):  # Exists
            return {
                "provider": "AWS S3",
                "bucket": bucket_name,
                "url": url,
                "path_url": path_url,
                "status": status,
                "state": state,
                "is_public": status == 200,
                "risk": "CRITICAL" if status == 200 else "INFO",
            }
    except Exception:
        pass
    return None


def _probe_gcs(bucket_name: str) -> Optional[dict]:
    """Check a Google Cloud Storage bucket."""
    url = f"https://storage.googleapis.com/{bucket_name}"
    try:
        r = requests.head(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=False)
        status = r.status_code
        if status in (200, 403):
            return {
                "provider": "Google Cloud Storage",
                "bucket": bucket_name,
                "url": url,
                "path_url": f"https://{bucket_name}.storage.googleapis.com",
                "status": status,
                "state": BUCKET_STATUS.get(status, "EXISTS"),
                "is_public": status == 200,
                "risk": "CRITICAL" if status == 200 else "INFO",
            }
    except Exception:
        pass
    return None


def _probe_azure(bucket_name: str) -> Optional[dict]:
    """Check Azure Blob Storage (storage account)."""
    # Azure storage accounts: brand.blob.core.windows.net
    account_name = bucket_name.replace("-", "")[:24]  # Azure account names: alphanumeric, 3-24 chars
    url = f"https://{account_name}.blob.core.windows.net"
    try:
        r = requests.head(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=False)
        status = r.status_code
        if status in (200, 400, 403, 409):  # 400 = account exists but no container specified
            return {
                "provider": "Azure Blob Storage",
                "bucket": account_name,
                "url": url,
                "path_url": url,
                "status": status,
                "state": "EXISTS" if status in (400, 403) else BUCKET_STATUS.get(status, f"HTTP_{status}"),
                "is_public": status == 200,
                "risk": "CRITICAL" if status == 200 else "LOW",
            }
    except Exception:
        pass
    return None


def _probe_spaces(bucket_name: str) -> Optional[dict]:
    """Check DigitalOcean Spaces."""
    # Spaces are regional; try a few common regions
    for region in ("nyc3", "sfo3", "ams3", "sgp1"):
        url = f"https://{bucket_name}.{region}.digitaloceanspaces.com"
        try:
            r = requests.head(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=False)
            status = r.status_code
            if status in (200, 403):
                return {
                    "provider": f"DigitalOcean Spaces ({region})",
                    "bucket": bucket_name,
                    "url": url,
                    "path_url": url,
                    "status": status,
                    "state": BUCKET_STATUS.get(status, "EXISTS"),
                    "is_public": status == 200,
                    "risk": "CRITICAL" if status == 200 else "INFO",
                }
        except Exception:
            continue
    return None


def find_buckets(domain: str, max_workers: int = 20) -> dict:
    """
    Enumerate potential open cloud storage buckets for a domain.
    """
    # Extract brand name (e.g. 'example' from 'example.com')
    brand = domain.split(".")[0]
    bucket_names = _generate_bucket_names(brand)
    # Also add the full domain without TLD
    parts = domain.split(".")
    if len(parts) >= 2:
        bucket_names.extend(_generate_bucket_names(".".join(parts[:-1])))
    bucket_names = list(dict.fromkeys(bucket_names))  # deduplicate

    found = []
    total_probed = 0

    probes = []
    for name in bucket_names:
        probes.append((_probe_s3, name))
        probes.append((_probe_gcs, name))
        probes.append((_probe_azure, name))

    # DigitalOcean: only top permutations to avoid too many requests
    for name in bucket_names[:10]:
        probes.append((_probe_spaces, name))

    total_probed = len(probes)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fn, name): (fn.__name__, name) for fn, name in probes}
        for future in concurrent.futures.as_completed(futures, timeout=90):
            try:
                result = future.result()
                if result:
                    found.append(result)
            except Exception:
                pass

    # Sort: open first, then private
    found.sort(key=lambda r: (0 if r["is_public"] else 1, r["provider"], r["bucket"]))

    open_count = sum(1 for r in found if r["is_public"])
    private_count = sum(1 for r in found if not r["is_public"])

    return {
        "domain": domain,
        "brand": brand,
        "names_tested": len(bucket_names),
        "total_probes": total_probed,
        "buckets_found": len(found),
        "open_buckets": open_count,
        "private_buckets": private_count,
        "results": found,
    }
