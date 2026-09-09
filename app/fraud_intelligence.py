"""Curated, explainable Fraud Intelligence Repository consumer.

This module never changes mail flow and never creates AI ground truth.  It reads
versioned curated intelligence from the dashboard MariaDB and evaluates a raw
RFC822 message for fraud hypotheses.  Repository evidence is advisory/shadow
only; Mail Admin Ground Truth remains authoritative.
"""
from __future__ import annotations

import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

from .db import fraud_repo_patterns, fraud_repo_status


def _addr(value: str) -> str:
    rows = getaddresses([str(value or "")])
    return (rows[0][1] if rows else "").strip().lower()


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower().rstrip(".") if "@" in addr else ""


def _body_text(msg) -> str:
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() != "text" or part.get_content_disposition() == "attachment":
                continue
            try:
                parts.append(str(part.get_content() or ""))
            except Exception:
                pass
    else:
        try:
            parts.append(str(msg.get_content() or ""))
        except Exception:
            pass
    text = "\n".join(parts)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def _structural(msg) -> dict:
    from_addr = _addr(msg.get("From", ""))
    reply_addr = _addr(msg.get("Reply-To", ""))
    to_addr = _addr(msg.get("To", ""))
    msgid = str(msg.get("Message-ID", "") or "").strip().lower()
    from_domain = _domain(from_addr)
    reply_domain = _domain(reply_addr)
    msgid_domain = ""
    m = re.search(r"@([^>\s]+)", msgid)
    if m:
        msgid_domain = m.group(1).rstrip(".")
    local = to_addr.split("@", 1)[0] if "@" in to_addr else ""
    return {
        "reply_to_domain_mismatch": bool(from_domain and reply_domain and from_domain != reply_domain),
        "message_id_domain_mismatch": bool(from_domain and msgid_domain and from_domain != msgid_domain),
        "generic_recipient": local in {"info", "admin", "sales", "accounts", "finance", "contact", "support", "office", "webmaster"},
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "message_id_domain": msgid_domain,
    }


def _phrase_hits(text: str, phrases: list[str]) -> list[str]:
    hits = []
    for phrase in phrases:
        p = str(phrase or "").strip().lower()
        if p and p in text:
            hits.append(p)
    return hits


def analyze_bytes(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject = str(msg.get("Subject", "") or "")
    body = _body_text(msg)
    text = (subject + " " + body).lower()
    structural = _structural(msg)
    repo = fraud_repo_status()
    patterns = fraud_repo_patterns(repo.get("active_version", ""))
    findings = []

    for row in patterns:
        try:
            spec = json.loads(row.get("pattern_json") or "{}")
        except Exception:
            continue
        phrases = list(spec.get("phrases") or [])
        hit_phrases = _phrase_hits(text, phrases)
        min_hits = max(1, int(spec.get("min_hits") or 1))
        struct_required = list(spec.get("structural_any") or [])
        struct_hits = [name for name in struct_required if structural.get(name)]
        phrase_ok = len(hit_phrases) >= min_hits if phrases else True
        struct_ok = bool(struct_hits) if struct_required else True
        if not (phrase_ok and struct_ok):
            continue
        weight = float(row.get("weight") or 1.0)
        score = weight + min(3.0, max(0, len(hit_phrases) - min_hits) * 0.35) + min(1.5, len(struct_hits) * 0.5)
        findings.append({
            "taxonomy_code": row.get("taxonomy_code") or "OTHER_FRAUD",
            "pattern_key": row.get("pattern_key") or "",
            "title": row.get("title") or row.get("pattern_key") or "Fraud pattern",
            "score": round(score, 2),
            "matched_phrases": hit_phrases[:8],
            "structural_evidence": struct_hits,
            "explanation": row.get("explanation") or "",
            "suggested_classification": row.get("suggested_classification") or "OTHER_SPAM",
        })

    agg = {}
    for f in findings:
        code = f["taxonomy_code"]
        bucket = agg.setdefault(code, {"taxonomy_code": code, "score": 0.0, "evidence": [], "suggested_classification": f["suggested_classification"]})
        bucket["score"] += f["score"]
        bucket["evidence"].append(f)
    hypotheses = sorted(agg.values(), key=lambda x: x["score"], reverse=True)
    for h in hypotheses:
        h["score"] = round(h["score"], 2)
        h["severity"] = "CRITICAL" if h["score"] >= 12 else "HIGH" if h["score"] >= 7 else "SUSPICIOUS" if h["score"] >= 4 else "INFO"
    primary = hypotheses[0] if hypotheses else None
    suggested_label = "SPAM" if primary and primary["severity"] in {"SUSPICIOUS", "HIGH", "CRITICAL"} else ""
    return {
        "enabled": True,
        "shadow_only": True,
        "training_authority": False,
        "repo_version": repo.get("active_version") or "",
        "repo_entry_count": repo.get("entry_count", 0),
        "primary": primary,
        "hypotheses": hypotheses[:8],
        "structural": structural,
        "suggested_label": suggested_label,
        "suggested_classification": (primary or {}).get("suggested_classification", ""),
        "note": "Fraud repository findings are evidence only. Explicit Mail Admin acknowledgement/save is required for Set-2 Ground Truth.",
    }


def analyze_file(path: Path) -> dict:
    return analyze_bytes(Path(path).read_bytes())
