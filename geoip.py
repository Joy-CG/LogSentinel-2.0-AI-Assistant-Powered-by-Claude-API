"""
geoip.py — Free GeoIP lookup using ip-api.com (no API key required).

Rate limit: 45 requests/minute for the free tier.
Results are cached in memory to avoid redundant lookups.
"""

import urllib.request
import json
import time
from typing import Optional

_cache: dict[str, dict] = {}
_last_request_time = 0.0
_MIN_INTERVAL = 1.5  # seconds between requests to respect rate limit


def lookup(ip: str) -> Optional[dict]:
    """
    Look up GeoIP info for an IP address.

    Returns a dict with keys:
        country, regionName, city, isp, org, lat, lon, status
    Returns None on failure.
    """
    global _last_request_time

    if not ip or ip.startswith(("10.", "172.", "192.168.", "127.")):
        return {"country": "Private", "regionName": "", "city": "",
                "isp": "Local Network", "org": "", "status": "private"}

    if ip in _cache:
        return _cache[ip]

    # Respect rate limit
    elapsed = time.time() - _last_request_time
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,lat,lon"
        req = urllib.request.Request(url, headers={"User-Agent": "LogSentinel/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        _last_request_time = time.time()
        _cache[ip] = data
        return data
    except Exception:
        return None


def format_location(geo: Optional[dict]) -> str:
    """Return a human-readable location string."""
    if not geo:
        return "Unknown"
    if geo.get("status") == "private":
        return "Private / Local"
    parts = [geo.get("city", ""), geo.get("regionName", ""), geo.get("country", "")]
    return ", ".join(p for p in parts if p) or "Unknown"
