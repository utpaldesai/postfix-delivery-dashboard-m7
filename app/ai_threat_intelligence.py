"""Self-contained three-tier mail threat intelligence for SHADOW inspection.

R1.1.52 boundaries:
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
import socket
import struct
import time
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

ENGINE_VERSION = "local-ti-v1.1-provider-aware"
CAMPAIGN_WINDOW_DAYS = max(1, min(3650, int(os.getenv("AI_TI_CAMPAIGN_WINDOW_DAYS", "30"))))

_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']{4,2048}")
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_+.-]{1,48}", re.I)
_IP_RE = re.compile(r"\[([0-9A-Fa-f:.]+)\]")
_FROM_HOST_RE = re.compile(r"(?i)\bfrom\s+([^\s()]+)")
_HELO_RE = re.compile(r"(?i)\b(?:helo|ehlo)[=\s]+([^\s;)]+)")
_BY_HOST_RE = re.compile(r"(?i)\bby\s+([^\s()]+)")
_DKIM_D_RE = re.compile(r"(?i)\bheader\.d\s*=\s*([^\s;]+)|\bd\s*=\s*([^\s;]+)")
_AUTH_RE = re.compile(r"(?i)\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)")

_GOOGLE_HOST_SUFFIXES = (".google.com", ".googlemail.com", ".gmail.com")
_MICROSOFT_HOST_SUFFIXES = (".outlook.com", ".protection.outlook.com", ".office365.com", ".microsoft.com")
_GOOGLE_CONSUMER_DOMAINS = {"gmail.com", "googlemail.com"}
_MICROSOFT_CONSUMER_DOMAINS = {"outlook.com", "hotmail.com", "live.com", "msn.com"}
_MX_CACHE: dict[str, tuple[float, dict]] = {}
_MX_CACHE_TTL = max(300, min(86400, int(os.getenv("AI_TI_MX_CACHE_TTL_SECONDS", "21600"))))
_MX_TIMEOUT = max(0.05, min(1.0, float(os.getenv("AI_TI_MX_TIMEOUT_SECONDS", "0.35"))))

def _dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels=[]; jumped=False; end=offset; seen=set()
    while offset < len(data):
        if offset in seen: break
        seen.add(offset)
        length=data[offset]
        if length==0:
            offset += 1
            if not jumped: end=offset
            break
        if length & 0xC0 == 0xC0:
            if offset+1 >= len(data): break
            ptr=((length & 0x3F)<<8) | data[offset+1]
            if not jumped: end=offset+2
            offset=ptr; jumped=True; continue
        offset += 1
        if offset+length > len(data): break
        labels.append(data[offset:offset+length].decode("ascii","ignore"))
        offset += length
        if not jumped: end=offset
    return ".".join(x for x in labels if x).lower().strip("."), end

def _resolver_ip() -> str:
    try:
        for line in Path("/etc/resolv.conf").read_text(errors="ignore").splitlines():
            parts=line.split()
            if len(parts)>=2 and parts[0]=="nameserver":
                return parts[1]
    except Exception:
        pass
    return ""

def _mx_provider_lookup(domain: str) -> dict:
    """Bounded DNS MX verification for Infrastructure AI only.

    This result is never included in the model feature vector and never controls
    delivery. DNS failure is UNKNOWN, not suspicious.
    """
    domain=str(domain or "").lower().strip(".")
    if not domain:
        return {"status":"NO_DOMAIN","provider":"unknown","targets":[],"network_lookup":False}
    cached=_MX_CACHE.get(domain)
    now=time.monotonic()
    if cached and now-cached[0] < _MX_CACHE_TTL:
        return dict(cached[1], cached=True)
    resolver=_resolver_ip()
    if not resolver:
        result={"status":"NO_RESOLVER","provider":"unknown","targets":[],"network_lookup":False}
        _MX_CACHE[domain]=(now,result); return result
    try:
        ident=int.from_bytes(os.urandom(2),"big")
        qname=b"".join(bytes([len(x)])+x.encode("idna") for x in domain.split("."))+b"\x00"
        packet=struct.pack("!HHHHHH",ident,0x0100,1,0,0,0)+qname+struct.pack("!HH",15,1)
        family=socket.AF_INET6 if ":" in resolver else socket.AF_INET
        sock=socket.socket(family,socket.SOCK_DGRAM); sock.settimeout(_MX_TIMEOUT)
        try:
            sock.sendto(packet,(resolver,53)); data,_=sock.recvfrom(4096)
        finally:
            sock.close()
        if len(data)<12:
            raise ValueError("short DNS response")
        rid,flags,qd,an,_,_=struct.unpack("!HHHHHH",data[:12])
        if rid!=ident or (flags & 0x000F):
            raise ValueError("DNS response error")
        off=12
        for _ in range(qd):
            _,off=_dns_name(data,off); off += 4
        targets=[]
        for _ in range(an):
            _,off=_dns_name(data,off)
            if off+10>len(data): break
            rtype,rclass,ttl,rdlen=struct.unpack("!HHIH",data[off:off+10]); off += 10
            rstart=off; off += rdlen
            if rtype==15 and rclass==1 and rdlen>=3:
                _,nameoff=(struct.unpack("!H",data[rstart:rstart+2])[0], rstart+2)
                target,_=_dns_name(data,nameoff)
                if target and target not in targets: targets.append(target)
        providers={_transport_provider(t) for t in targets}
        provider="google" if "google" in providers else ("microsoft" if "microsoft" in providers else ("other" if targets else "unknown"))
        result={"status":"OK" if targets else "NO_MX","provider":provider,"targets":targets[:8],"network_lookup":True}
    except Exception as exc:
        result={"status":"LOOKUP_FAILED","provider":"unknown","targets":[],"network_lookup":True,"error":str(exc)[:120]}
    _MX_CACHE[domain]=(now,result)
    return result


def _transport_provider(host: str) -> str:
    value = str(host or "").lower().strip(".[]() ")
    if not value:
        return "unknown"
    if any(value == suffix.lstrip(".") or value.endswith(suffix) for suffix in _GOOGLE_HOST_SUFFIXES):
        return "google"
    if any(value == suffix.lstrip(".") or value.endswith(suffix) for suffix in _MICROSOFT_HOST_SUFFIXES):
        return "microsoft"
    return "other"

def _provider_route_observation(msg) -> dict:
    """Describe provider transitions without treating them as verdict evidence.

    Received headers are newest->oldest and lower blocks can be sender-supplied.
    We therefore expose provider transitions as contextual observations only; no
    provider mismatch adds risk by itself. The newest public-provider hop is the
    most trustworthy external transport observation available in the message.
    """
    hops=[]
    for idx, value in enumerate(_received_headers(msg)[:12]):
        fm=_FROM_HOST_RE.search(value)
        by=_BY_HOST_RE.search(value)
        from_host=(fm.group(1).strip(".;[]() ").lower() if fm else "")
        by_host=(by.group(1).strip(".;[]() ").lower() if by else "")
        provider=_transport_provider(from_host)
        if from_host:
            hops.append({"index": idx, "from_host": from_host, "by_host": by_host, "provider": provider})
    providers=[h["provider"] for h in hops if h["provider"] in {"google","microsoft"}]
    transitions=[]
    for a,b in zip(providers, providers[1:]):
        if a!=b:
            transitions.append(f"{b}->{a}")  # chronological older->newer
    ingress=next((h for h in hops if h["provider"] in {"google","microsoft"}), None)
    return {"ingress_provider": (ingress or {}).get("provider","unknown"), "provider_transitions": transitions[:8], "hops": hops[:8]}


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
    provider_route = _provider_route_observation(msg)
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

    # Provider-aware routing exception: a Gmail/Outlook consumer From domain
    # arriving through its native provider is expected. Custom-domain Google
    # Workspace/M365 traffic is also represented as provider context, but never
    # auto-trusted because outbound and inbound hosting can differ.
    expected_provider = "google" if from_domain in _GOOGLE_CONSUMER_DOMAINS else ("microsoft" if from_domain in _MICROSOFT_CONSUMER_DOMAINS else "")
    mx_verification = _mx_provider_lookup(from_domain)
    provider_context = {
        "from_domain": from_domain,
        "expected_consumer_provider": expected_provider,
        "observed_ingress_provider": provider_route.get("ingress_provider", "unknown"),
        "expected_consumer_provider_match": bool(expected_provider and expected_provider == provider_route.get("ingress_provider")),
        "mx_provider": mx_verification.get("provider", "unknown"),
        "mx_targets": mx_verification.get("targets", []),
        "mx_status": mx_verification.get("status", "UNKNOWN"),
        "mx_network_lookup": bool(mx_verification.get("network_lookup")),
        "hosted_provider_match": bool(mx_verification.get("provider") in {"google","microsoft"} and mx_verification.get("provider") == provider_route.get("ingress_provider")),
        "provider_transitions": provider_route.get("provider_transitions", []),
        "note": "MX/provider verification is contextual only. Google Workspace/Microsoft 365 custom domains, separate outbound providers, forwarding and hybrid routes are valid exceptions; DNS failure is UNKNOWN, never malicious.",
    }

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
        "network_lookup": bool(provider_context.get("mx_network_lookup")),
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
            "provider_context": provider_context,
            "sender_domain": from_domain,
            "reply_domain": reply_domain,
            "message_id_domain": mid_domain,
            "history": history,
            "signals": infra_signals,
            "limitations": "Provider/hop interpretation combines locally observed Received evidence with bounded cached MX verification. Lower Received blocks may be sender-supplied and outbound routing can differ from MX hosting, so provider transitions/MX matches are contextual and never automatic HAM/SPAM proof. No third-party reputation lookup is performed.",
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
