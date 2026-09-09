"""Strict analysis-only adapter for an external/dedicated Amavis dry-run helper.

The dashboard deliberately does not submit specimens to the production Amavis SMTP
listener. A helper must be explicitly enabled and must attest that it performed an
analysis-only operation with no delivery, quarantine, release, Bayes/sa-learn, AI
label, or production queue side effects.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request


def _truthy(name: str, default: str = "false") -> bool:
    return str(os.getenv(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def _config():
    return {
        "enabled": _truthy("AMAVIS_DRY_RUN_ENABLED", "false"),
        "url": str(os.getenv("AMAVIS_DRY_RUN_HELPER_URL", "") or "").strip(),
        "timeout": max(1.0, float(os.getenv("AMAVIS_DRY_RUN_TIMEOUT", "20") or 20)),
        "allow_remote": _truthy("AMAVIS_DRY_RUN_ALLOW_REMOTE", "false"),
    }


def _host_is_loopback(host: str) -> bool:
    if not host:
        return False
    if host.lower() in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(host, None)}
        return bool(addresses) and all(ipaddress.ip_address(addr).is_loopback for addr in addresses)
    except Exception:
        return False


def status():
    cfg = _config()
    parsed = urllib.parse.urlsplit(cfg["url"]) if cfg["url"] else None
    safe_target = bool(parsed and parsed.scheme == "http" and parsed.hostname and (cfg["allow_remote"] or _host_is_loopback(parsed.hostname)))
    return {
        "enabled": bool(cfg["enabled"]),
        "configured": bool(cfg["url"]),
        "safe_target": safe_target,
        "analysis_only": True,
        "production_amavis_smtp_forbidden": True,
        "helper_host": parsed.hostname if parsed else "",
    }


def analyze_bytes(raw: bytes, *, filename: str = ""):
    cfg = _config()
    if not cfg["enabled"]:
        raise ValueError("Amavis dry-run is disabled; set AMAVIS_DRY_RUN_ENABLED=true only for a dedicated analysis-only helper")
    if not cfg["url"]:
        raise ValueError("AMAVIS_DRY_RUN_HELPER_URL is not configured")
    parsed = urllib.parse.urlsplit(cfg["url"])
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("Amavis dry-run helper must use an explicit HTTP URL")
    if not cfg["allow_remote"] and not _host_is_loopback(parsed.hostname):
        raise ValueError("Amavis dry-run helper must be loopback-local unless AMAVIS_DRY_RUN_ALLOW_REMOTE=true is explicitly approved")
    # Explicitly refuse common production Amavis SMTP service destinations.
    if parsed.port in {10024, 10025, 9998}:
        raise ValueError("Production Amavis/after-filter/PDP ports are forbidden for dry-run analysis")

    body = json.dumps({
        "mode": "analysis-only",
        "filename": filename or "message.eml",
        "message_b64": base64.b64encode(raw).decode("ascii"),
        "safety": {
            "deliver": False,
            "quarantine": False,
            "release": False,
            "sa_learn": False,
            "bayes_update": False,
            "ai_ground_truth": False,
            "production_queue": False,
        },
    }).encode("utf-8")
    req = urllib.request.Request(cfg["url"], data=body, method="POST", headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=cfg["timeout"]) as response:
            payload = json.loads(response.read(1024 * 1024).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        raise ValueError(f"Amavis dry-run helper returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Amavis dry-run helper unavailable: {exc.reason}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Amavis dry-run helper returned an invalid response")
    if payload.get("analysis_only") is not True:
        raise ValueError("Amavis dry-run helper did not attest analysis_only=true; result rejected")
    safety = payload.get("safety") or {}
    forbidden = ("delivered", "quarantined", "released", "sa_learned", "bayes_updated", "ai_ground_truth_created", "production_queue_created")
    if any(bool(safety.get(key)) for key in forbidden):
        raise ValueError("Amavis dry-run helper reported a prohibited side effect; result rejected")
    payload.setdefault("status", "READY")
    payload["analysis_only"] = True
    payload["authority"] = "NONE"
    return payload
