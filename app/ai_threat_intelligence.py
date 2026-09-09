"""Self-contained three-tier mail threat intelligence for SHADOW inspection.

R1.1.45 boundaries:
- No SMTP, Postfix, Amavis, quarantine, release or mailbox decision authority.
- No network reputation/API dependency. ASN enrichment is offline MMDB only.
- Message AI remains the independent trainer/candidate. This module adds local
  Infrastructure AI evidence, Campaign AI correlation and an explainable
  SHADOW correlation assessment.
- Authentication success is identity evidence, never HAM proof.
- Campaign observations are local metadata/fingerprints only; raw body text,
  credentials and full URLs are not persisted by this module.
"""
from __future__ import annotations

import gzip
import hashlib
import html
import ipaddress
import os
import re
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit

from .db import (
    ai_ti_campaign_stats,
    ai_ti_infrastructure_stats,
    ai_ti_store_observation,
)
from .geoip_intelligence import enrich_ip, received_public_ips

ENGINE_VERSION = "local-ti-v1"
CAMPAIGN_WINDOW_DAYS = max(1, min(3650, int(os.getenv("AI_TI_CAMPAIGN_WINDOW_DAYS", "30"))))

_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']{4,2048}")
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_+.-]{1,48}", re.I)
_IP_RE = re.compile(r"\[([0-9A-Fa-f:.]+)\]")
_FROM_HOST_RE = re.compile(r"(?i)\bfrom\s+([^\s()]+)")
_HELO_RE = re.compile(r"(?i)\b(?:helo|ehlo)[=\s]+([^\s;)]+)")
_BY_HOST_RE = re.compile(r"(?i)\bby\s+([^\s()]+)")
_DKIM_D_RE = re.compile(r"(?i)\bheader\.d\s*=\s*([^\s;]+)|\bd\s*=\s*([^\s;]+)")
_AUTH_RE = re.compile(r"(?i)\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)")


def _domain(address: str) -> str:
    value = parseaddr(str(address or ""))[1].strip().lower()
    return value.rsplit("@", 1)[1].strip(".[]") if "@" in value else ""


def _message_id_domain(value: str) -> str:
    raw = str(value or "").strip().strip("<>")
    return raw.rsplit("@", 1)[1].lower().strip(".[]") if "@" in raw else ""


def _aligned(a: str, b: str) -> bool:
    a, b = str(a or "").lower().strip("."), str(b or "").lower().strip(".")
    return bool(a and b and (a == b or a.endswith("." + b) or b.endswith("." + a)))


def _body_text(msg) -> str:
    values = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if content:
                values.append(str(content))
    else:
        try:
            values.append(str(msg.get_content() or ""))
        except Exception:
            pass
    return "\n".join(values)[:250000]


def _received_headers(msg) -> list[str]:
    return [str(v or "") for v in msg.get_all("Received", [])]


def _oldest_public_received(msg) -> dict:
    received = _received_headers(msg)
    public_ips = received_public_ips("\n".join("Received: " + value for value in received))
    source_ip = public_ips[-1] if public_ips else ""
    selected = ""
    # Received headers are newest -> oldest. Prefer the oldest block containing
    # the selected source IP, otherwise the oldest block.
    for value in reversed(received):
        if source_ip and source_ip in value:
            selected = value
            break
    if not selected and received:
        selected = received[-1]
    from_host = (_FROM_HOST_RE.search(selected).group(1).strip(".;[]()") if _FROM_HOST_RE.search(selected) else "")
    helo_match = _HELO_RE.search(selected)
    helo = helo_match.group(1).strip(".;[]()") if helo_match else from_host
    by_match = _BY_HOST_RE.search(selected)
    by_host = by_match.group(1).strip(".;[]()") if by_match else ""
    return {
        "source_ip": source_ip,
        "observed_reverse_name": from_host.lower(),
        "observed_helo": helo.lower(),
        "received_by": by_host.lower(),
        "public_hops": public_ips,
        "received_block": selected[:2000],
    }


def _auth(msg) -> dict:
    text = "\n".join(str(v or "") for v in msg.get_all("Authentication-Results", []))
    values = {"spf": "", "dkim": "", "dmarc": ""}
    for mech, result in _AUTH_RE.findall(text):
        if not values[mech.lower()]:
            values[mech.lower()] = result.lower()
    dkim_domains = []
    for match in _DKIM_D_RE.findall(text):
        value = (match[0] or match[1] or "").strip(".;<>[]").lower()
        if value and value not in dkim_domains:
            dkim_domains.append(value)
    values["dkim_domains"] = dkim_domains
    return values


def _url_domains(text: str) -> list[str]:
    result = []
    for raw in _URL_RE.findall(text or "")[:300]:
        candidate = raw if raw.lower().startswith(("http://", "https://")) else "http://" + raw
        try:
            host = (urlsplit(candidate).hostname or "").lower().strip(".")
        except Exception:
            host = ""
        if host and host not in result:
            result.append(host)
    return sorted(result)[:100]


def _attachments(msg) -> tuple[list[str], list[str]]:
    names, extensions = [], []
    for part in msg.walk():
        name = str(part.get_filename() or "").strip()
        if not name:
            continue
        names.append(name[:255])
        suffix = Path(name).suffix.lower() or "[none]"
        if suffix not in extensions:
            extensions.append(suffix)
    return names[:100], sorted(extensions)[:50]


def _normalized_subject(value: str) -> str:
    text = html.unescape(str(value or "")).lower()
    text = re.sub(r"(?i)^(?:(?:re|fw|fwd)\s*:\s*)+", "", text)
    text = re.sub(r"\b[0-9a-f]{8,}\b", "#", text)
    text = re.sub(r"\b\d+(?:[.,:/-]\d+)*\b", "#", text)
    return " ".join(_WORD_RE.findall(text))[:1000]


def _body_signature(text: str) -> str:
    value = html.unescape(str(text or "")).lower()
    value = re.sub(r"<[^>]{1,1000}>", " ", value)
    value = _URL_RE.sub(" URL ", value)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", " EMAIL ", value, flags=re.I)
    value = re.sub(r"\b\d+(?:[.,:/-]\d+)*\b", " # ", value)
    words = _WORD_RE.findall(value)[:1800]
    # Persist only a one-way hash of normalized structure, never the body.
    return hashlib.sha256(" ".join(words).encode("utf-8", "ignore")).hexdigest()


def _hash_join(values) -> str:
    return hashlib.sha256("\x1f".join(str(v or "") for v in values).encode("utf-8", "ignore")).hexdigest()


def _source_sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _parse(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)


def _risk_band(score: float) -> str:
    if score >= 75:
        return "HIGH_RISK"
    if score >= 50:
        return "SUSPICIOUS"
    if score >= 25:
        return "ELEVATED"
    return "LOW_EVIDENCE"


def analyze_bytes(raw: bytes, *, message_ai: dict | None = None, source_kind: str = "manual", source_id: str = "", record_observation: bool = False) -> dict:
    """Analyze one RFC822 message using local evidence only.

    `record_observation` should be true only for locally observed production
    evidence (for example a quarantine item), not arbitrary uploaded samples.
    """
    message_ai = message_ai or {}
    msg = _parse(raw)
    body = _body_text(msg)
    subject = str(msg.get("Subject", "") or "")
    from_domain = _domain(str(msg.get("From", "") or ""))
    reply_domain = _domain(str(msg.get("Reply-To", "") or ""))
    return_domain = _domain(str(msg.get("Return-Path", "") or ""))
    mid_domain = _message_id_domain(str(msg.get("Message-ID", "") or ""))
    auth = _auth(msg)
    transport = _oldest_public_received(msg)
    geo = enrich_ip(transport["source_ip"]) if transport["source_ip"] else {"available": False, "network_lookup": False}
    asn = int(geo.get("asn") or 0) if str(geo.get("asn") or "").isdigit() else 0
    organization = str(geo.get("organization") or "")[:255]
    urls = _url_domains(subject + "\n" + body)
    _, attachment_exts = _attachments(msg)

    subject_template = _normalized_subject(subject)
    body_hash = _body_signature(body)
    url_set_hash = _hash_join(urls)
    attachment_set_hash = _hash_join(attachment_exts)
    template_hash = _hash_join([subject_template, body_hash])
    sender_path_hash = _hash_join([from_domain, reply_domain, return_domain, mid_domain])
    campaign_hash = _hash_join([template_hash, url_set_hash, attachment_set_hash, reply_domain])
    source_sha256 = _source_sha(raw)

    infra_signals = []
    reverse_name = transport["observed_reverse_name"]
    helo = transport["observed_helo"]
    if transport["source_ip"] and not reverse_name:
        infra_signals.append({"code": "NO_OBSERVED_REVERSE_NAME", "weight": 8, "detail": "Oldest public Received hop has no observed sender hostname"})
    if reverse_name and helo and not _aligned(reverse_name, helo):
        infra_signals.append({"code": "PTR_HELO_INCONSISTENT", "weight": 12, "detail": f"Observed reverse/from name {reverse_name} differs from HELO {helo}"})
    if from_domain and reverse_name and not _aligned(from_domain, reverse_name):
        infra_signals.append({"code": "SENDER_INFRA_DOMAIN_MISMATCH", "weight": 6, "detail": "Envelope/header sender domain differs from observed sending-host domain; contextual only"})
    if reply_domain and from_domain and not _aligned(reply_domain, from_domain):
        infra_signals.append({"code": "REPLY_TO_DOMAIN_MISMATCH", "weight": 12, "detail": f"Reply-To domain {reply_domain} differs from From domain {from_domain}"})
    if mid_domain and from_domain and not _aligned(mid_domain, from_domain):
        infra_signals.append({"code": "MESSAGE_ID_DOMAIN_MISMATCH", "weight": 5, "detail": "Message-ID domain differs from From domain"})
    # Authentication is identity evidence only. Failures raise infrastructure
    # suspicion; passes do not subtract risk or imply HAM.
    for mech in ("spf", "dkim", "dmarc"):
        if auth.get(mech) in {"fail", "softfail", "permerror", "policy"}:
            infra_signals.append({"code": mech.upper() + "_FAILURE", "weight": 8 if mech != "dmarc" else 12, "detail": f"{mech.upper()}={auth.get(mech)}"})

    history = ai_ti_infrastructure_stats(
        source_ip=transport["source_ip"], asn=asn, sender_domain=from_domain,
        window_days=CAMPAIGN_WINDOW_DAYS,
    )
    if history.get("sender_domain_distinct_ips", 0) >= 5:
        infra_signals.append({"code": "SENDER_IP_ROTATION", "weight": 12, "detail": f"Sender domain observed from {history['sender_domain_distinct_ips']} source IPs locally"})
    if history.get("sender_domain_distinct_asns", 0) >= 3:
        infra_signals.append({"code": "SENDER_ASN_ROTATION", "weight": 10, "detail": f"Sender domain observed across {history['sender_domain_distinct_asns']} ASNs locally"})

    campaign_stats = ai_ti_campaign_stats(
        template_hash=template_hash, campaign_hash=campaign_hash, url_set_hash=url_set_hash,
        sender_domain=from_domain, source_ip=transport["source_ip"], asn=asn,
        window_days=CAMPAIGN_WINDOW_DAYS,
    )
    campaign_signals = []
    if campaign_stats.get("template_messages", 0) >= 3:
        campaign_signals.append({"code": "REPEATED_TEMPLATE", "weight": 10, "detail": f"Template fingerprint seen in {campaign_stats['template_messages']} local messages"})
    if campaign_stats.get("template_distinct_sender_domains", 0) >= 3:
        campaign_signals.append({"code": "SNOWSHOE_TEMPLATE_ROTATION", "weight": 20, "detail": f"Same template across {campaign_stats['template_distinct_sender_domains']} sender domains"})
    if campaign_stats.get("template_distinct_source_ips", 0) >= 3:
        campaign_signals.append({"code": "BOTNET_LIKE_SOURCE_DIVERSITY", "weight": 18, "detail": f"Same template across {campaign_stats['template_distinct_source_ips']} source IPs"})
    if campaign_stats.get("template_distinct_asns", 0) >= 3:
        campaign_signals.append({"code": "MULTI_ASN_CAMPAIGN", "weight": 14, "detail": f"Same template observed across {campaign_stats['template_distinct_asns']} ASNs"})
    if urls and campaign_stats.get("urlset_messages", 0) >= 3:
        campaign_signals.append({"code": "REPEATED_URL_INFRASTRUCTURE", "weight": 12, "detail": f"URL-domain set seen in {campaign_stats['urlset_messages']} local messages"})

    stored = False
    if record_observation:
        stored = bool(ai_ti_store_observation({
            "source_sha256": source_sha256,
            "source_kind": source_kind,
            "source_id": source_id,
            "message_id": str(msg.get("Message-ID", "") or "")[:512],
            "sender_domain": from_domain,
            "reply_domain": reply_domain,
            "return_path_domain": return_domain,
            "message_id_domain": mid_domain,
            "source_ip": transport["source_ip"],
            "observed_reverse_name": reverse_name,
            "observed_helo": helo,
            "asn": asn or None,
            "asn_organization": organization,
            "spf_result": auth.get("spf", ""),
            "dkim_result": auth.get("dkim", ""),
            "dmarc_result": auth.get("dmarc", ""),
            "template_hash": template_hash,
            "body_structure_hash": body_hash,
            "url_domain_set_hash": url_set_hash,
            "attachment_set_hash": attachment_set_hash,
            "sender_path_hash": sender_path_hash,
            "campaign_hash": campaign_hash,
            "url_domain_count": len(urls),
            "attachment_count": len(attachment_exts),
        }))
        # Refresh counts so the current observation participates immediately.
        history = ai_ti_infrastructure_stats(source_ip=transport["source_ip"], asn=asn, sender_domain=from_domain, window_days=CAMPAIGN_WINDOW_DAYS)
        campaign_stats = ai_ti_campaign_stats(template_hash=template_hash, campaign_hash=campaign_hash, url_set_hash=url_set_hash, sender_domain=from_domain, source_ip=transport["source_ip"], asn=asn, window_days=CAMPAIGN_WINDOW_DAYS)

    infra_score = min(100.0, float(sum(int(x["weight"]) for x in infra_signals)))
    campaign_score = min(100.0, float(sum(int(x["weight"]) for x in campaign_signals)))

    message_score = None
    if message_ai.get("available"):
        try:
            probs = message_ai.get("probabilities") or {}
            if "SPAM" in probs:
                message_score = float(probs["SPAM"]) * (100.0 if float(probs["SPAM"]) <= 1.0 else 1.0)
            elif str(message_ai.get("verdict") or "").upper() == "SPAM":
                message_score = float(message_ai.get("confidence") or 0)
            elif str(message_ai.get("verdict") or "").upper() == "HAM":
                message_score = 100.0 - float(message_ai.get("confidence") or 0)
        except Exception:
            message_score = None

    # Explainable shadow correlation: Message AI is dominant when available;
    # infrastructure/campaign evidence can strengthen but never controls mail.
    if message_score is None:
        correlation_score = round(0.45 * infra_score + 0.55 * campaign_score, 2)
        inputs = ["infrastructure", "campaign"]
    else:
        correlation_score = round(0.60 * message_score + 0.18 * infra_score + 0.22 * campaign_score, 2)
        inputs = ["message", "infrastructure", "campaign"]

    return {
        "enabled": True,
        "shadow_only": True,
        "network_lookup": False,
        "engine_version": ENGINE_VERSION,
        "observation_recorded": stored,
        "infrastructure": {
            "status": "OPERATIONAL_LOCAL_EVIDENCE",
            "score": round(infra_score, 2),
            "source_ip": transport["source_ip"],
            "observed_reverse_name": reverse_name,
            "observed_helo": helo,
            "received_by": transport["received_by"],
            "public_hops": transport["public_hops"],
            "asn": asn or None,
            "asn_organization": organization,
            "auth": auth,
            "sender_domain": from_domain,
            "reply_domain": reply_domain,
            "message_id_domain": mid_domain,
            "history": history,
            "signals": infra_signals,
            "limitations": "PTR/HELO uses locally observed Received evidence; no live DNS/reputation lookup is performed.",
        },
        "campaign": {
            "status": "OPERATIONAL_LOCAL_CORRELATION",
            "score": round(campaign_score, 2),
            "window_days": CAMPAIGN_WINDOW_DAYS,
            "stats": campaign_stats,
            "signals": campaign_signals,
            "fingerprints": {
                "template": template_hash,
                "campaign": campaign_hash,
                "url_domain_set": url_set_hash,
                "attachment_set": attachment_set_hash,
                "sender_path": sender_path_hash,
            },
            "url_domains": urls[:20],
            "attachment_extensions": attachment_exts,
            "limitations": "Correlation is limited to locally observed metadata/fingerprints; no third-party/global telemetry is used.",
        },
        "correlation": {
            "status": "SHADOW_EXPLAINABLE_V1",
            "score": correlation_score,
            "assessment": _risk_band(correlation_score),
            "inputs": inputs,
            "message_ai_spam_score": None if message_score is None else round(message_score, 2),
            "infrastructure_score": round(infra_score, 2),
            "campaign_score": round(campaign_score, 2),
            "authority": "NONE",
            "note": "Evidence-only shadow assessment; never blocks, releases, reroutes or labels mail automatically.",
        },
    }


def analyze_file(path: Path, **kwargs) -> dict:
    path = Path(path)
    opener = gzip.open if path.suffix.lower() == ".gz" else open
    with opener(path, "rb") as handle:
        raw = handle.read()
    return analyze_bytes(raw, **kwargs)
