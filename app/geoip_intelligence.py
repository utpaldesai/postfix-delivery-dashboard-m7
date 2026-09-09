"""Offline Geo-IP enrichment for quarantine and manual email analysis.

No network lookups are performed. Operators may supply MaxMind GeoLite2/GeoIP2
City and ASN MMDB files under the configured data directory.
"""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

try:
    import geoip2.database  # type: ignore
    from geoip2.errors import AddressNotFoundError  # type: ignore
except Exception:  # pragma: no cover - graceful degraded mode
    geoip2 = None
    AddressNotFoundError = Exception

CITY_DB = Path(os.getenv("GEOIP_CITY_DB", "/data/geoip/GeoLite2-City.mmdb"))
ASN_DB = Path(os.getenv("GEOIP_ASN_DB", "/data/geoip/GeoLite2-ASN.mmdb"))

_IP_BRACKET_RE = re.compile(r"\[([0-9A-Fa-f:.]+)\]")
_IP_BARE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])")


def _is_public(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def received_public_ips(header_text: str) -> list[str]:
    """Return unique public IPs observed in Received headers, newest to oldest."""
    text = str(header_text or "").replace("\r\n", "\n")
    lines = text.split("\n")
    received = []
    current = ""
    active = False
    for line in lines:
        if line.lower().startswith("received:"):
            if current:
                received.append(current)
            current = line
            active = True
        elif active and (line.startswith(" ") or line.startswith("\t")):
            current += " " + line.strip()
        else:
            if current:
                received.append(current)
                current = ""
            active = False
    if current:
        received.append(current)

    found: list[str] = []
    seen = set()
    for block in received:
        candidates = _IP_BRACKET_RE.findall(block) + _IP_BARE_RE.findall(block)
        for candidate in candidates:
            candidate = candidate.strip()
            if candidate in seen or not _is_public(candidate):
                continue
            seen.add(candidate)
            found.append(candidate)
    return found


def _lookup_city(ip: str) -> dict:
    if geoip2 is None or not CITY_DB.is_file():
        return {}
    try:
        with geoip2.database.Reader(str(CITY_DB)) as reader:
            r = reader.city(ip)
        return {
            "country": r.country.name or r.country.iso_code or "",
            "country_code": r.country.iso_code or "",
            "city": r.city.name or "",
            "region": (r.subdivisions.most_specific.name if r.subdivisions else "") or "",
            "latitude": r.location.latitude,
            "longitude": r.location.longitude,
        }
    except (AddressNotFoundError, ValueError, OSError):
        return {}


def _lookup_asn(ip: str) -> dict:
    if geoip2 is None or not ASN_DB.is_file():
        return {}
    try:
        with geoip2.database.Reader(str(ASN_DB)) as reader:
            r = reader.asn(ip)
        return {
            "asn": r.autonomous_system_number,
            "organization": r.autonomous_system_organization or "",
        }
    except (AddressNotFoundError, ValueError, OSError):
        return {}


def enrich_ip(ip_value: str) -> dict:
    """Offline Geo-IP enrichment for a single public client IP."""
    selected = str(ip_value or "").strip()
    result = {
        "available": False,
        "source_ip": selected,
        "lookup_mode": "offline-mmdb",
        "network_lookup": False,
        "db_status": status(),
    }
    if not selected:
        result["reason"] = "No IP supplied"
        return result
    try:
        ipaddress.ip_address(selected)
    except ValueError:
        result["reason"] = "Invalid IP address"
        return result
    city = _lookup_city(selected)
    asn = _lookup_asn(selected)
    result.update(city)
    result.update(asn)
    result["available"] = bool(city or asn)
    if not result["available"]:
        if not CITY_DB.is_file() and not ASN_DB.is_file():
            result["reason"] = "Geo-IP MMDB files are not installed"
        else:
            result["reason"] = "No Geo-IP record for client IP"
    return result


def status() -> dict:
    return {
        "enabled": geoip2 is not None,
        "mode": "offline-mmdb",
        "city_db": str(CITY_DB),
        "city_db_available": CITY_DB.is_file(),
        "asn_db": str(ASN_DB),
        "asn_db_available": ASN_DB.is_file(),
        "network_lookup": False,
    }


def enrich_header(header_text: str) -> dict:
    ips = received_public_ips(header_text)
    # Received headers are newest -> oldest. The oldest observed public hop is
    # the best available approximation of the sender-side source relay.
    selected = ips[-1] if ips else ""
    result = {
        "available": False,
        "source_ip": selected,
        "observed_public_hops": ips,
        "lookup_mode": "offline-mmdb",
        "network_lookup": False,
        "db_status": status(),
    }
    if not selected:
        result["reason"] = "No public IP found in Received headers"
        return result
    city = _lookup_city(selected)
    asn = _lookup_asn(selected)
    result.update(city)
    result.update(asn)
    result["available"] = bool(city or asn)
    if not result["available"]:
        if not CITY_DB.is_file() and not ASN_DB.is_file():
            result["reason"] = "Geo-IP MMDB files are not installed"
        else:
            result["reason"] = "No Geo-IP record for observed source IP"
    return result
