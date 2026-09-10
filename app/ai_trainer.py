"""Shadow-mode AI trainer for Postfix Delivery Dashboard.

Safety guarantees:
- Never participates in SMTP/Amavis delivery decisions.
- Never writes to SpamAssassin Bayes tables.
- Learns only from explicit human HAM/SPAM actions already accepted by sa-learn.
- Uses only independent raw-message, authentication/alignment, URL/domain, contextual BEC/NLP, privacy-reduced stylometric/structural and MIME/attachment features; no SpamAssassin/Amavis verdict/score/rule features, no sandboxing, and no network lookups.
- Hard-HAM examples receive additional training weight to reduce false positives.
- Stores privacy-reduced hashed feature vectors under QUARANTINE_STATE_DIR/ai-trainer.
- Training creates a candidate model; promotion to active is explicit.
"""
from __future__ import annotations

import gzip
import hashlib
import html
import ipaddress
import io
import json
import math
import os
import re
import threading
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Dict, Iterable
from urllib.parse import urlsplit

AI_ENABLED = os.getenv("AI_TRAINER_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
AI_SHADOW_MODE = True  # hard safety boundary; no config can make AI authoritative
STATE_DIR = Path(os.getenv("QUARANTINE_STATE_DIR", "/data/amavis-mgr")) / "ai-trainer"
DATASET = STATE_DIR / "training_samples.jsonl"
CANDIDATE_MODEL = STATE_DIR / "candidate_model.json"
ACTIVE_MODEL = STATE_DIR / "active_model.json"
EVENT_LOG = STATE_DIR / "events.jsonl"
MODEL_META = STATE_DIR / "model_meta.json"
MIN_PER_CLASS = max(1, int(os.getenv("AI_TRAINER_MIN_PER_CLASS", "10")))
MAX_FEATURES_PER_MESSAGE = max(128, int(os.getenv("AI_TRAINER_MAX_FEATURES", "2048")))
TOKEN_BUCKETS = max(2048, int(os.getenv("AI_TRAINER_TOKEN_BUCKETS", "16384")))
AUTO_TRAIN_AFTER_NEW_LABELS = max(0, int(os.getenv("AI_TRAINER_AUTO_TRAIN_AFTER_NEW_LABELS", "250")))
LOGISTIC_EPOCHS = max(2, int(os.getenv("AI_TRAINER_LOGISTIC_EPOCHS", "12")))
LOGISTIC_LR = max(0.001, min(1.0, float(os.getenv("AI_TRAINER_LOGISTIC_LR", "0.08"))))
LOGISTIC_L2 = max(0.0, min(0.1, float(os.getenv("AI_TRAINER_LOGISTIC_L2", "0.0001"))))
HARD_HAM_WEIGHT = max(1.0, min(5.0, float(os.getenv("AI_TRAINER_HARD_HAM_WEIGHT", "1.75"))))
AI_AMAVIS_HOOK_MODE = os.getenv("AI_AMAVIS_HOOK_MODE", "disabled").strip().lower() or "disabled"
AI_AMAVIS_HOOK_ENDPOINT = os.getenv("AI_AMAVIS_HOOK_ENDPOINT", "/api/ai/amavis-hook/v1").strip() or "/api/ai/amavis-hook/v1"
HOME_DOMAINS = {d.strip().lower().lstrip("@") for d in os.getenv("HOME_DOMAINS", "").split(",") if d.strip()}
QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/host-amavis/virusmails"))
CURRENT_FEATURE_SCHEMA = 4
CURRENT_GENERATION = os.getenv("AI_TRAINER_GENERATION", "independent-g1").strip() or "independent-g1"
CURRENT_AUTH_POLICY = "identity-neutral-v1"
HAM_CLASSIFICATIONS = {
    "LEGITIMATE_BUSINESS", "EXPECTED_TRANSACTIONAL", "APPROVED_NEWSLETTER",
    "INTERNAL_OR_TRUSTED", "PERSONAL_OR_DIRECT", "OTHER_HAM",
}
SPAM_CLASSIFICATIONS = {
    "UCE_AUTHENTICATED", "UCE_UNAUTHENTICATED", "PHISHING", "CREDENTIAL_PHISHING",
    "SPEAR_PHISHING", "WHALING", "BEC", "INVOICE_FRAUD", "ADVANCE_FEE_INVESTMENT",
    "INHERITANCE_419", "LOTTERY_PRIZE", "FAKE_JOB", "CHARITY_FRAUD", "TECH_SUPPORT",
    "CALLBACK_PHISHING", "FAKE_ECOMMERCE", "SEO_DIRECTORY", "BOTNET", "BPH",
    "SNOWSHOE", "MALWARE", "OTHER_SPAM",
}
_lock = threading.RLock()
_auto_train_running = False
_status_cache = {"ts": 0.0, "signature": None, "value": None}
STATUS_CACHE_SECONDS = max(1.0, float(os.getenv("AI_TRAINER_STATUS_CACHE_SECONDS", "8")))
ATTACHMENT_SCAN_MAX_DEPTH = max(1, min(8, int(os.getenv("AI_ATTACHMENT_SCAN_MAX_DEPTH", "5"))))
ATTACHMENT_SCAN_MAX_MEMBERS = max(10, min(2000, int(os.getenv("AI_ATTACHMENT_SCAN_MAX_MEMBERS", "250"))))
ATTACHMENT_SCAN_MAX_MEMBER_BYTES = max(65536, int(os.getenv("AI_ATTACHMENT_SCAN_MAX_MEMBER_BYTES", "8388608")))
ATTACHMENT_SCAN_MAX_TOTAL_BYTES = max(1048576, int(os.getenv("AI_ATTACHMENT_SCAN_MAX_TOTAL_BYTES", "33554432")))
_DANGEROUS_ARCHIVE_EXT = {".bat", ".cmd", ".com", ".cpl", ".dll", ".exe", ".hta", ".jar", ".js", ".jse", ".lnk", ".msi", ".msp", ".ps1", ".reg", ".scr", ".vbe", ".vbs", ".wsf", ".wsh"}

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_+.-]{1,48}", re.I)


def _scan_zip_bytes(payload: bytes, *, archive_name: str = "archive.zip", depth: int = 1, budget: dict | None = None) -> dict:
    """Bounded, local-only ZIP member inspection. Never executes or writes members to disk."""
    budget = budget or {"members": 0, "bytes": 0}
    result = {"archive_name": archive_name, "max_depth": depth, "members": [], "dangerous_members": [], "nested_archives": 0, "truncated": False, "errors": []}
    if depth > ATTACHMENT_SCAN_MAX_DEPTH:
        result["truncated"] = True
        return result
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if budget["members"] >= ATTACHMENT_SCAN_MAX_MEMBERS:
                    result["truncated"] = True
                    break
                budget["members"] += 1
                name = str(info.filename or "unnamed")[:512]
                ext = Path(name).suffix.lower()
                entry = {"name": name, "extension": ext, "depth": depth, "size": int(info.file_size or 0), "compressed_size": int(info.compress_size or 0), "dangerous": ext in _DANGEROUS_ARCHIVE_EXT, "archive": ext in _ARCHIVE_EXT}
                result["members"].append(entry)
                if entry["dangerous"]:
                    result["dangerous_members"].append(entry)
                if entry["archive"] and ext == ".zip" and depth < ATTACHMENT_SCAN_MAX_DEPTH:
                    if info.file_size > ATTACHMENT_SCAN_MAX_MEMBER_BYTES or budget["bytes"] + info.file_size > ATTACHMENT_SCAN_MAX_TOTAL_BYTES:
                        result["truncated"] = True
                        continue
                    try:
                        nested = zf.read(info)
                        budget["bytes"] += len(nested)
                        child = _scan_zip_bytes(nested, archive_name=name, depth=depth + 1, budget=budget)
                        result["nested_archives"] += 1 + int(child.get("nested_archives") or 0)
                        result["max_depth"] = max(result["max_depth"], int(child.get("max_depth") or depth))
                        result["members"].extend(child.get("members") or [])
                        result["dangerous_members"].extend(child.get("dangerous_members") or [])
                        result["truncated"] = result["truncated"] or bool(child.get("truncated"))
                    except Exception as exc:
                        result["errors"].append(str(exc)[:160])
    except Exception as exc:
        result["errors"].append(str(exc)[:160])
    return result


def attachment_intelligence(source_path: Path) -> dict:
    """Independent attachment evidence for operator display and model features."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(source_path.read_bytes())
    except Exception as exc:
        return {"available": False, "reason": str(exc)[:200], "local_only": True}
    evidence=[]; dangerous=[]; max_depth=0; nested=0; truncated=False
    for part in msg.walk():
        name=str(part.get_filename() or "").strip()
        if not name: continue
        ext=Path(name).suffix.lower(); payload=part.get_payload(decode=True) or b""
        item={"name":name,"extension":ext,"content_type":str(part.get_content_type() or ""),"size":len(payload),"archive":ext in _ARCHIVE_EXT,"dangerous":ext in _DANGEROUS_ARCHIVE_EXT,"depth":0}
        evidence.append(item)
        if item["dangerous"]: dangerous.append(item)
        if ext==".zip" and payload:
            scan=_scan_zip_bytes(payload, archive_name=name)
            evidence.extend(scan.get("members") or [])
            dangerous.extend(scan.get("dangerous_members") or [])
            max_depth=max(max_depth,int(scan.get("max_depth") or 0)); nested += int(scan.get("nested_archives") or 0); truncated=truncated or bool(scan.get("truncated"))
    risk="CRITICAL" if dangerous and max_depth>=2 else ("HIGH" if dangerous else ("ELEVATED" if nested else "NORMAL"))
    return {"available":True,"local_only":True,"network_lookup":False,"execution":False,"risk":risk,"nested_archive":bool(nested),"archive_depth":max_depth,"dangerous_member_count":len(dangerous),"dangerous_members":dangerous[:30],"evidence":evidence[:120],"truncated":truncated}

def _now():
    return datetime.now(timezone.utc).isoformat()


def _ensure():
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _append_jsonl(path: Path, row: dict):
    _ensure()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def _event(action: str, **detail):
    try:
        _append_jsonl(EVENT_LOG, {"ts": _now(), "action": action, **detail})
    except Exception:
        pass


def _read_message(path: Path):
    opener = gzip.open if path.suffix.lower() == ".gz" else open
    with opener(path, "rb") as handle:
        return BytesParser(policy=policy.default).parse(handle)


def _body_text(msg) -> str:
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype not in {"text/plain", "text/html"}:
                continue
            try:
                value = part.get_content()
            except Exception:
                continue
            if value:
                parts.append(str(value))
    else:
        try:
            parts.append(str(msg.get_content() or ""))
        except Exception:
            pass
    return "\n".join(parts)[:250000]


def _hash_token(token: str) -> str:
    bucket = int(hashlib.sha256(token.encode("utf-8", "ignore")).hexdigest()[:12], 16) % TOKEN_BUCKETS
    return f"t{bucket:05d}"


def _add_tokens(counter: Counter, prefix: str, text: str, limit: int = 6000):
    for token in _WORD_RE.findall((text or "").lower())[:limit]:
        counter[_hash_token(prefix + token)] += 1


def _domain_from_address(value: str) -> str:
    address = parseaddr(str(value or ""))[1].strip().lower()
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip(".[]")


def _domain_aligned(left: str, right: str) -> bool:
    left = str(left or "").lower().strip(".")
    right = str(right or "").lower().strip(".")
    if not left or not right:
        return False
    return left == right or left.endswith("." + right) or right.endswith("." + left)


def _auth_result(text: str, mechanism: str) -> str:
    match = re.search(r"\b" + re.escape(mechanism) + r"\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)", str(text or ""), re.I)
    return match.group(1).lower() if match else ""


def _public_received_ip(received_headers) -> bool:
    for value in received_headers:
        for raw in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", str(value or "")):
            try:
                addr = ipaddress.ip_address(raw)
                if not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved):
                    return True
            except ValueError:
                continue
    return False


_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']{4,2048}")
_PHRASE_GROUPS = {
    "urgency": ("urgent", "immediately", "action required", "act now", "final notice", "within 24 hours", "asap"),
    "credential": ("verify your account", "verify account", "password expires", "reset password", "confirm your password", "login to verify", "sign in to verify", "mailbox quota"),
    "payment": ("wire transfer", "bank transfer", "payment overdue", "outstanding payment", "invoice attached", "change bank details", "payment details", "remittance advice"),
    "impersonation": ("are you available", "confidential request", "do not call", "gift card", "purchase cards", "send me your mobile", "reply urgently"),
    "threat": ("account suspended", "account will be closed", "legal action", "service interruption", "unauthorized access"),
    "financial_request": ("buy gift cards", "gift cards", "send the codes", "wire funds", "wire the funds", "bank account changed", "new bank details", "crypto wallet", "bitcoin payment"),
    "secrecy_pressure": ("keep this confidential", "between us", "do not tell", "do not contact", "don't call", "do not call me", "handle this discreetly"),
    "callback_lure": ("call this number", "call us immediately", "contact support at", "telephone support", "renewal charge", "subscription renewal"),
    "uce_language": ("unsubscribe", "special offer", "limited time offer", "exclusive offer", "marketing communication", "promotional email", "book a demo", "schedule a demo"),
}
_ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tgz", ".bz2", ".xz", ".tar"}
_EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".jar", ".msi", ".hta", ".lnk", ".iso", ".img"}
_MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xltm", ".potm", ".ppam", ".sldm"}


def _extract_features_and_meta(path: Path, item: dict | None = None):
    """Extract fast local message features plus non-content training metadata.

    Raw body, subject, addresses and URLs are never persisted by the trainer;
    the returned vector contains only hashed buckets.  This deliberately uses
    the Python standard library so the production image gains no heavy NLP/ML
    runtime dependency and remains shadow-only.
    """
    # Deliberately ignore dashboard/Amavis/SpamAssassin item metadata.
    # Independent inference is derived only from the RFC822 message itself.
    item = {}
    msg = _read_message(path)
    features = Counter()
    meta = {"hard_ham_score": 0, "feature_families": set()}

    subject = str(msg.get("Subject", item.get("subject", "")) or "")
    body = _body_text(msg)
    combined_text = html.unescape((subject + "\n" + body).lower())
    from_value = str(msg.get("From", item.get("from", "")) or "")
    reply_value = str(msg.get("Reply-To", "") or "")
    return_path = str(msg.get("Return-Path", "") or "")

    # Text / NLP: hashed lexical evidence plus compact BEC/phishing phrase families.
    _add_tokens(features, "subj:", subject, 200)
    _add_tokens(features, "from:", from_value, 80)
    _add_tokens(features, "reply:", reply_value, 80)
    _add_tokens(features, "body:", body, 5000)
    words = _WORD_RE.findall(combined_text)[:2200]
    for left, right in zip(words, words[1:]):
        features[_hash_token("bigram:" + left + "_" + right)] += 1
    for family, phrases in _PHRASE_GROUPS.items():
        hits = sum(1 for phrase in phrases if phrase in combined_text)
        if hits:
            features[_hash_token("nlp:" + family)] += min(hits, 8)
            meta["hard_ham_score"] += 1
    if any(ch.isupper() for ch in subject) and sum(ch.isupper() for ch in subject) >= max(8, len(subject) // 2):
        features[_hash_token("nlp:subject_caps_heavy")] += 1
    if combined_text.count("!") >= 3:
        features[_hash_token("nlp:exclamation_heavy")] += 1

    # Privacy-reduced stylometric / structural signature. No sender profile or raw text is persisted.
    alpha = sum(ch.isalpha() for ch in combined_text)
    upper = sum(ch.isupper() for ch in subject + "\n" + body)
    digits = sum(ch.isdigit() for ch in combined_text)
    punct = sum(ch in "!?;:," for ch in combined_text)
    chars = max(1, len(combined_text))
    sentences = [x for x in re.split(r"[.!?]+", combined_text) if x.strip()]
    avg_sentence = int(sum(len(_WORD_RE.findall(x)) for x in sentences) / max(1, len(sentences)))
    unique_ratio = int(10 * len(set(words)) / max(1, len(words))) if words else 0
    for key, value in (
        ("uppercase_ratio", min(10, int(100 * upper / chars) // 3)),
        ("digit_ratio", min(10, int(100 * digits / chars) // 2)),
        ("punctuation_ratio", min(10, int(100 * punct / chars) // 2)),
        ("avg_sentence_words", min(12, avg_sentence // 4)),
        ("lexical_diversity", min(10, unique_ratio)),
        ("message_length", min(12, int(math.log2(chars)) if chars else 0)),
    ):
        features[_hash_token("style:" + key + ":" + str(value))] += 1
    if re.search(r"(?im)^(dear|hello|hi|good morning|good afternoon)\b", body):
        features[_hash_token("style:greeting_present")] += 1
    if re.search(r"(?im)^(regards|best regards|thanks|thank you|sincerely|cheers)[, !]*$", body):
        features[_hash_token("style:signoff_present")] += 1
    if re.search(r"(?:[$€£₹]|\b(?:usd|eur|gbp|inr)\b)\s*[0-9][0-9,]*(?:\.[0-9]{1,2})?", combined_text, re.I):
        features[_hash_token("nlp:financial_amount_present")] += 1
    meta["feature_families"].add("nlp_text")
    meta["feature_families"].add("stylometry_structural")

    # Authentication and sender identity/alignment relationships.
    auth_headers = " ".join(str(x) for x in msg.get_all("Authentication-Results", []) if x)
    spf_headers = " ".join(str(x) for x in msg.get_all("Received-SPF", []) if x)
    auth_combined = auth_headers + " " + spf_headers
    auth_values = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        value = str(item.get(mechanism, "") or "").strip().lower() or _auth_result(auth_combined, mechanism)
        if value:
            auth_values[mechanism] = value
            # Authentication PASS proves only that a mechanism authenticated the
            # asserted identity. It is deliberately neutral for HAM/SPAM intent: modern
            # UCE/phishing can be fully SPF/DKIM/DMARC aligned. Preserve mechanism
            # presence and negative/error outcomes as anomaly evidence, but do not add
            # direct PASS features that can become a hidden HAM shortcut.
            features[_hash_token("auth:observed:" + mechanism)] += 1
            if value != "pass":
                features[_hash_token("auth:" + mechanism + ":" + value)] += 1
            if value in {"fail", "softfail", "permerror", "temperror"}:
                meta["hard_ham_score"] += 1

    from_domain = _domain_from_address(from_value)
    reply_domain = _domain_from_address(reply_value)
    return_domain = _domain_from_address(return_path)
    dkim_domains = [x.lower().strip(".") for x in re.findall(r"\bd\s*=\s*([A-Za-z0-9._-]+)", " ".join(str(x) for x in msg.get_all("DKIM-Signature", []) if x), re.I)]
    message_id = str(msg.get("Message-ID", "") or "")
    mid_match = re.search(r"@([^>\s]+)", message_id)
    mid_domain = mid_match.group(1).lower().strip(".") if mid_match else ""
    for label, domain in (("from", from_domain), ("reply", reply_domain), ("return", return_domain), ("messageid", mid_domain)):
        if domain:
            features[_hash_token("domain:" + label + ":" + domain)] += 1
    if reply_domain and from_domain:
        aligned = _domain_aligned(from_domain, reply_domain)
        features[_hash_token("align:from_reply:" + ("yes" if aligned else "no"))] += 1
        if not aligned:
            meta["hard_ham_score"] += 1
    if return_domain and from_domain:
        aligned = _domain_aligned(from_domain, return_domain)
        features[_hash_token("align:from_return:" + ("yes" if aligned else "no"))] += 1
        if not aligned:
            meta["hard_ham_score"] += 1
    if dkim_domains and from_domain:
        aligned = any(_domain_aligned(from_domain, d) for d in dkim_domains)
        features[_hash_token("align:from_dkim:" + ("yes" if aligned else "no"))] += 1
        if not aligned:
            meta["hard_ham_score"] += 1
    if mid_domain and from_domain:
        features[_hash_token("align:from_messageid:" + ("yes" if _domain_aligned(from_domain, mid_domain) else "no"))] += 1
    if HOME_DOMAINS and from_domain and any(_domain_aligned(from_domain, d) for d in HOME_DOMAINS):
        features[_hash_token("identity:home_from")] += 1
        if _public_received_ip(msg.get_all("Received", [])):
            features[_hash_token("identity:home_from_public_received")] += 1
            meta["hard_ham_score"] += 2
    received_headers = [str(x) for x in msg.get_all("Received", []) if x]
    received_count = len(received_headers)
    features[_hash_token("header:received_count:" + str(min(received_count, 12)))] += 1
    if received_headers:
        peer = re.search(r"\bfrom\s+([^\s(]+)", received_headers[0], re.I)
        helo = re.search(r"\b(?:helo|ehlo)[= ]+([^\s,)]+)", received_headers[0], re.I)
        peer_domain = (peer.group(1).lower().strip(".[]") if peer else "")
        helo_domain = (helo.group(1).lower().strip(".[]") if helo else "")
        if peer_domain:
            features[_hash_token("received:peer:" + peer_domain)] += 1
            if from_domain:
                features[_hash_token("align:from_received_peer:" + ("yes" if _domain_aligned(from_domain, peer_domain) else "no"))] += 1
        if helo_domain:
            features[_hash_token("received:helo:" + helo_domain)] += 1
            if peer_domain:
                features[_hash_token("align:helo_peer:" + ("yes" if _domain_aligned(helo_domain, peer_domain) else "no"))] += 1
    originating = " ".join(str(x) for x in msg.get_all("X-Originating-IP", []) if x)
    if originating:
        _add_tokens(features, "header:x_originating_ip:", originating, 20)
    for missing in ("Date", "Message-ID", "From"):
        if not msg.get(missing):
            features[_hash_token("header:missing:" + missing.lower())] += 1
    if len(msg.get_all("From", [])) > 1:
        features[_hash_token("header:multiple_from")] += 1
        meta["hard_ham_score"] += 1
    meta["feature_families"].add("authentication_alignment")
    meta["feature_families"].add("sender_header_anomaly")

    # URL/domain intelligence: local structural/reputation evidence only; no network lookup.
    urls = _URL_RE.findall(combined_text)[:120]
    url_domains = []
    for raw in urls:
        candidate = raw if "://" in raw else "http://" + raw
        try:
            parsed = urlsplit(candidate.rstrip(".,);]>'\""))
            domain = (parsed.hostname or "").lower().strip(".")
        except Exception:
            domain = ""
        if not domain:
            continue
        url_domains.append(domain)
        features[_hash_token("url:domain:" + domain)] += 1
        if domain.startswith("xn--") or ".xn--" in domain:
            features[_hash_token("url:punycode")] += 1
            meta["hard_ham_score"] += 1
        try:
            ipaddress.ip_address(domain.strip("[]"))
            features[_hash_token("url:ip_literal")] += 1
            meta["hard_ham_score"] += 1
        except ValueError:
            pass
        if raw.count("%") >= 3 or raw.count("-") >= 5:
            features[_hash_token("url:obfuscated")] += 1
        if len(raw) > 180:
            features[_hash_token("url:long")] += 1
    if urls:
        features[_hash_token("url:count_bucket:" + str(min(len(urls) // 3, 10)))] += 1
    if from_domain and url_domains:
        aligned_urls = sum(1 for d in url_domains if _domain_aligned(from_domain, d))
        features[_hash_token("url:sender_alignment:" + ("some" if aligned_urls else "none"))] += 1
        if not aligned_urls and len(url_domains) >= 2:
            meta["hard_ham_score"] += 1

    # Detect visible-link / href destination mismatch locally. Never follows or opens the URL.
    for part in msg.walk():
        if str(part.get_content_type() or "").lower() != "text/html":
            continue
        try:
            raw_html = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            raw_html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        for href, visible in re.findall(r"(?is)<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", str(raw_html))[:80]:
            visible_text = re.sub(r"<[^>]+>", " ", visible)
            visible_url = _URL_RE.search(html.unescape(visible_text))
            if not visible_url:
                continue
            try:
                href_host = (urlsplit(href if "://" in href else "http://" + href).hostname or "").lower().strip(".")
                vis_raw = visible_url.group(0)
                vis_host = (urlsplit(vis_raw if "://" in vis_raw else "http://" + vis_raw).hostname or "").lower().strip(".")
            except Exception:
                continue
            if href_host and vis_host and not _domain_aligned(href_host, vis_host):
                features[_hash_token("url:visible_href_mismatch")] += 1
                meta["hard_ham_score"] += 1
    meta["feature_families"].add("url_domain")

    # MIME and attachment intelligence (metadata only; no sandbox execution).
    content_type = str(msg.get_content_type() or "unknown").lower()
    features[_hash_token("mime:" + content_type)] += 1
    if msg.is_multipart():
        features[_hash_token("mime:multipart")] += 1
    attachments = 0
    max_depth = 0
    for part in msg.walk():
        # email.message does not expose tree depth cheaply; multipart nesting marker is sufficient and fast.
        if part.is_multipart():
            max_depth += 1
        name = part.get_filename()
        ctype = str(part.get_content_type() or "application/octet-stream").lower()
        disposition = str(part.get_content_disposition() or "")
        if name or disposition == "attachment":
            attachments += 1
            suffixes = [x.lower() for x in Path(name or "unnamed").suffixes]
            suffix = suffixes[-1][:16] if suffixes else ""
            if suffix:
                features[_hash_token("attach:ext:" + suffix)] += 1
            features[_hash_token("attach:mime:" + ctype)] += 1
            if len(suffixes) >= 2:
                features[_hash_token("attach:double_extension")] += 1
                meta["hard_ham_score"] += 1
            if suffix in _ARCHIVE_EXT:
                features[_hash_token("attach:archive")] += 1
            if suffix in _EXEC_EXT:
                features[_hash_token("attach:executable_like")] += 1
                meta["hard_ham_score"] += 2
            if suffix in _MACRO_EXT:
                features[_hash_token("attach:macro_office")] += 1
                meta["hard_ham_score"] += 1
            payload = part.get_payload(decode=True)
            if payload is not None:
                size = len(payload)
                bucket = min(12, int(math.log2(max(1, size))) // 2)
                features[_hash_token("attach:size_bucket:" + str(bucket))] += 1
                if suffix == ".zip" and payload:
                    archive_scan = _scan_zip_bytes(payload, archive_name=str(name or "archive.zip"))
                    depth = int(archive_scan.get("max_depth") or 0)
                    dangerous = archive_scan.get("dangerous_members") or []
                    nested_count = int(archive_scan.get("nested_archives") or 0)
                    if nested_count:
                        features[_hash_token("attach:nested_archive")] += min(nested_count, 5)
                    if depth:
                        features[_hash_token("attach:archive_depth:" + str(min(depth, ATTACHMENT_SCAN_MAX_DEPTH)))] += 1
                    for member in dangerous[:20]:
                        ext = str(member.get("extension") or "")[:16]
                        features[_hash_token("attach:embedded_dangerous")] += 1
                        if ext:
                            features[_hash_token("attach:embedded_ext:" + ext)] += 1
                    if dangerous:
                        features[_hash_token("attach:embedded_executable_or_script")] += 1
                        meta["hard_ham_score"] += 2
    if attachments:
        features[_hash_token("attachments:count:" + str(min(attachments, 10)))] += 1
    if max_depth > 1:
        features[_hash_token("mime:nested_multipart:" + str(min(max_depth, 8)))] += 1
    meta["feature_families"].add("mime_attachment")

    # Independent authentication evidence only. SpamAssassin/Amavis verdicts,
    # scores, rule names, quarantine categories and X-Spam-* headers are
    # deliberately excluded from the AI feature vector. Authentication PASS is
    # also neutral: retain header/mechanism presence and explicit failure/error
    # outcomes, but never feed raw PASS tokens as positive trust evidence.
    for header in ("Authentication-Results", "Received-SPF"):
        values = [str(x) for x in msg.get_all(header, []) if x]
        if values:
            features[_hash_token("authhdr:present:" + header.lower())] += 1
        text = " ".join(values)
        for mechanism in ("spf", "dkim", "dmarc"):
            result = _auth_result(text, mechanism)
            if result and result != "pass":
                features[_hash_token("authhdr:result:" + mechanism + ":" + result)] += 1
    meta["feature_families"].add("independent_authentication")

    # Bounded sparse vector; retain strongest features only.
    return dict(features.most_common(MAX_FEATURES_PER_MESSAGE)), meta


def extract_features(path: Path, item: dict | None = None) -> Dict[str, int]:
    features, _ = _extract_features_and_meta(path, item)
    return features


def _dataset_rows():
    if not DATASET.exists():
        return []
    # Latest approved label wins for the same source fingerprint. Historical
    # JSONL rows remain immutable/auditable, while a human correction does not
    # train contradictory HAM and SPAM copies of the same message.
    latest = {}
    order = []
    with DATASET.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("label") not in {"HAM", "SPAM"} or not isinstance(row.get("features"), dict):
                continue
            key = row.get("source_sha256") or row.get("sample_id")
            if key not in latest:
                order.append(key)
            latest[key] = row
    return [latest[key] for key in order if key in latest]


def _dataset_signature_values():
    try:
        st = DATASET.stat()
        return int(st.st_mtime_ns), int(st.st_size)
    except FileNotFoundError:
        return 0, 0


def _rebuild_status_snapshot_from_dataset():
    """One-time/repair path: scan immutable JSONL, then persist compact counters.

    Normal live status refreshes never call this unless the snapshot is missing or
    the JSONL signature changed outside the normal label-write path.
    """
    all_rows = _dataset_rows() if AI_ENABLED else []
    rows = [row for row in all_rows if _row_is_current_generation(row)]
    legacy_rows = [row for row in all_rows if not _row_is_current_generation(row)]
    counts = Counter(row["label"] for row in rows)
    mtime_ns, size = _dataset_signature_values()
    snapshot = {
        "dataset_samples": len(rows),
        "ham_labels": int(counts["HAM"]),
        "spam_labels": int(counts["SPAM"]),
        "hard_ham_labels": sum(1 for row in rows if row.get("label") == "HAM" and row.get("hard_ham")),
        "legacy_feature_labels": len(legacy_rows),
        "dataset_mtime_ns": mtime_ns,
        "dataset_size": size,
    }
    try:
        from .db import replace_ai_trainer_status_snapshot
        replace_ai_trainer_status_snapshot(generation_id=CURRENT_GENERATION, **snapshot)
    except Exception as exc:
        _event("AI_STATUS_SNAPSHOT_WRITE_FAILED", error=str(exc)[:300])
    return snapshot


def _status_snapshot():
    mtime_ns, size = _dataset_signature_values()
    try:
        from .db import get_ai_trainer_status_snapshot
        snapshot = get_ai_trainer_status_snapshot(CURRENT_GENERATION)
    except Exception:
        snapshot = None
    if snapshot and int(snapshot.get("dataset_mtime_ns") or 0) == mtime_ns and int(snapshot.get("dataset_size") or 0) == size:
        return snapshot
    return _rebuild_status_snapshot_from_dataset()


def _forensic_conflict_review(source_path: Path, prediction: dict):
    """Perform a bounded, local re-analysis of a conflicting message.

    The report stores reduced forensic observations, never the raw message body.
    It performs no network lookup and uses no SpamAssassin/Amavis verdict signal.
    """
    msg=_read_message(source_path)
    subject=str(msg.get("Subject", "") or "")
    body=_body_text(msg)
    text=html.unescape((subject+"\n"+body).lower())
    from_domain=_domain_from_address(str(msg.get("From", "") or ""))
    reply_domain=_domain_from_address(str(msg.get("Reply-To", "") or ""))
    return_domain=_domain_from_address(str(msg.get("Return-Path", "") or ""))
    auth_text="\n".join(str(x or "") for x in (msg.get_all("Authentication-Results", []) or []))
    phrase_hits={}
    for family, phrases in _PHRASE_GROUPS.items():
        hits=[phrase for phrase in phrases if phrase in text]
        if hits: phrase_hits[family]=hits[:8]
    urls=_URL_RE.findall(text)[:100]
    url_domains=[]
    for raw in urls:
        try:
            url=raw if raw.lower().startswith(("http://","https://")) else "http://"+raw
            host=(urlsplit(url).hostname or "").lower().strip(".")
            if host and host not in url_domains: url_domains.append(host)
        except Exception:
            pass
    attachments=[]
    for part in msg.walk():
        fn=str(part.get_filename() or "").strip()
        if fn:
            ext=Path(fn).suffix.lower()
            attachments.append({"extension": ext, "content_type": str(part.get_content_type() or ""), "archive": ext in _ARCHIVE_EXT, "executable": ext in _EXEC_EXT, "macro": ext in _MACRO_EXT})
    auth={m:_auth_result(auth_text,m) or "none" for m in ("spf","dkim","dmarc")}
    anomalies=[]
    if reply_domain and from_domain and not _domain_aligned(reply_domain,from_domain): anomalies.append("reply_to_domain_mismatch")
    if return_domain and from_domain and not _domain_aligned(return_domain,from_domain): anomalies.append("return_path_domain_mismatch")
    if any(a.get("executable") for a in attachments): anomalies.append("executable_attachment")
    if any(a.get("macro") for a in attachments): anomalies.append("macro_attachment")
    return {
        "reviewed_at": _now(), "local_only": True, "network_lookup": False,
        "subject_length": len(subject), "body_length": len(body),
        "from_domain": from_domain, "reply_to_domain": reply_domain, "return_path_domain": return_domain,
        "authentication_identity_only": auth, "phrase_families": phrase_hits,
        "url_count": len(urls), "url_domains": url_domains[:30],
        "attachment_count": len(attachments), "attachment_evidence": attachments[:30],
        "header_anomalies": anomalies,
        "candidate_prediction": prediction,
    }

def _default_root_cause(forensic: dict, ai_prediction: str, admin_label: str):
    phrases=forensic.get("phrase_families") or {}
    anomalies=forensic.get("header_anomalies") or []
    urls=int(forensic.get("url_count") or 0)
    if admin_label=="SPAM" and phrases.get("uce_language"):
        return "Possible missed unsolicited-commercial intent; review UCE language/campaign features."
    if admin_label=="SPAM" and urls and not phrases:
        return "Possible URL/domain-led spam with weak lexical evidence; review URL/domain feature contribution."
    if admin_label=="HAM" and anomalies:
        return "Possible legitimate message penalized by sender/header anomaly features; review Hard-HAM handling."
    return "AI/human conflict requires administrator root-cause review; no automatic model change applied."

def _persist_admin_ground_truth_db(**kwargs):
    """Persist authoritative ground truth; real DB errors are fatal.

    Source-only regression tests intentionally import ai_trainer without
    installing runtime dependencies.  Missing PyMySQL is tolerated only in
    that isolated verifier context; the production application imports app.db
    at startup and cannot run without the driver.
    """
    try:
        from .db import record_ai_ground_truth_history
    except ModuleNotFoundError as exc:
        if getattr(exc, "name", "") == "pymysql":
            _event("GROUND_TRUTH_DB_SKIPPED_NO_DRIVER", error="pymysql unavailable in source-only verifier")
            return None
        raise
    return record_ai_ground_truth_history(**kwargs)

def record_human_label(pdp_id: str, label: str, source_path: Path, item: dict | None, username: str = "", source: str = "admin-ground-truth", classification: str = "", review_reason: str = "", admin_notes: str = ""):
    """Capture explicit admin ground truth for the current independent AI generation."""
    if not AI_ENABLED:
        return {"ok": False, "disabled": True}
    label = str(label).upper()
    if label not in {"HAM", "SPAM"}:
        raise ValueError("AI label must be HAM or SPAM")
    classification=str(classification or "").strip().upper()
    allowed=HAM_CLASSIFICATIONS if label=="HAM" else SPAM_CLASSIFICATIONS
    if classification and classification not in allowed:
        raise ValueError("Invalid classification for selected ground-truth label")
    with _lock:
        raw = source_path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        existing = _dataset_rows()
        previous_label = ""
        previous_row = None
        for row in reversed(existing):
            if row.get("source_sha256") != sha:
                continue
            previous_row = row
            previous_label = str(row.get("label") or "").upper()
            if previous_label == label and str(row.get("classification") or "") == classification:
                # A duplicate training sample is still an explicit administrator save.
                # Persist/refresh the authoritative MariaDB CURRENT state even when
                # the immutable training dataset already contains this label.  This
                # also repairs messages calibrated by R1.1.49 while its DB-history
                # INSERT was defective.
                history=_persist_admin_ground_truth_db(
                    source_sha256=sha, pdp_id=pdp_id, label=label, classification=classification,
                    review_reason=review_reason, admin_notes=admin_notes, reviewer=username, label_source=source,
                    generation_id=CURRENT_GENERATION, feature_schema=CURRENT_FEATURE_SCHEMA,
                )
                if history is None:
                    history={"previous_label": previous_label, "reversal_count": 0, "reversed": False}
                return {
                    "ok": True, "duplicate": True, "sample_id": row.get("sample_id"),
                    "source_sha256": sha, "classification": classification,
                    "reversal": history, "conflict_investigation_id": None,
                    "auto_train_scheduled": False,
                }
            break
        if previous_label and previous_label != label and not str(review_reason or "").strip():
            raise ValueError("A review/reversal reason is required when changing an existing HAM/SPAM ground-truth decision")
        features, feature_meta = _extract_features_and_meta(source_path, item)
        sample_id = "ai-" + hashlib.sha256(f"{sha}:{label}".encode()).hexdigest()[:20]
        row = {
            "sample_id": sample_id,
            "created_at": _now(),
            "pdp_id": str(pdp_id),
            "label": label,
            "source_sha256": sha,
            "feature_schema": CURRENT_FEATURE_SCHEMA,
            "generation_id": CURRENT_GENERATION,
            "features": features,
            "hard_ham": bool(label == "HAM" and int(feature_meta.get("hard_ham_score", 0)) >= 2),
            "hard_ham_score": int(feature_meta.get("hard_ham_score", 0)),
            "feature_families": sorted(feature_meta.get("feature_families", set())),
            "label_source": source,
            "label_user": str(username or ""),
            "classification": classification,
            "review_reason": str(review_reason or "")[:512],
        }
        _append_jsonl(DATASET, row)
        # Keep the compact DB-backed live-status counters in sync with the
        # immutable JSONL write. This avoids reparsing the complete dataset on
        # each 10-second status refresh. Rebuild once here from the in-memory
        # deduped rows already loaded for duplicate/reversal handling.
        try:
            latest = {((r.get("source_sha256") or r.get("sample_id"))): r for r in existing}
            latest[sha] = row
            dedup = list(latest.values())
            current_rows = [r for r in dedup if _row_is_current_generation(r)]
            legacy_rows = [r for r in dedup if not _row_is_current_generation(r)]
            counts_now = Counter(r.get("label") for r in current_rows)
            mtime_ns, dataset_size = _dataset_signature_values()
            from .db import replace_ai_trainer_status_snapshot
            replace_ai_trainer_status_snapshot(
                generation_id=CURRENT_GENERATION, dataset_samples=len(current_rows),
                ham_labels=counts_now["HAM"], spam_labels=counts_now["SPAM"],
                hard_ham_labels=sum(1 for r in current_rows if r.get("label") == "HAM" and r.get("hard_ham")),
                legacy_feature_labels=len(legacy_rows), dataset_mtime_ns=mtime_ns, dataset_size=dataset_size,
            )
        except Exception as exc:
            _event("AI_STATUS_SNAPSHOT_SYNC_FAILED", sample_id=sample_id, error=str(exc)[:300])
        _invalidate_status_cache()
        # MariaDB is authoritative for the Admin Decision state.  Do not silently
        # downgrade a DB persistence failure to a successful calibration response.
        # If this raises, the API returns an explicit failure and the administrator
        # can retry; the duplicate path above safely repairs the DB state on retry.
        history=_persist_admin_ground_truth_db(
            source_sha256=sha, pdp_id=pdp_id, label=label, classification=classification,
            review_reason=review_reason, admin_notes=admin_notes, reviewer=username, label_source=source,
            generation_id=CURRENT_GENERATION, feature_schema=CURRENT_FEATURE_SCHEMA,
        )
        if history is None:
            history={"previous_label": previous_label, "reversal_count": 0, "reversed": bool(previous_label and previous_label != label)}
        conflict_id=None
        candidate=_load_model(CANDIDATE_MODEL)
        if _model_is_current_generation(candidate):
            try:
                pred=_predict_model(candidate, features)
                if pred.get("verdict") != label:
                    forensic=_forensic_conflict_review(source_path, pred)
                    root_cause=_default_root_cause(forensic, str(pred.get("verdict") or ""), label)
                    from .db import store_ai_conflict_investigation
                    conflict_id=store_ai_conflict_investigation(
                        source_sha256=sha, pdp_id=pdp_id, candidate_version=candidate.get("version", ""),
                        candidate_algorithm=candidate.get("algorithm", ""), ai_prediction=pred.get("verdict", ""),
                        admin_label=label, classification=classification, confidence=pred.get("confidence"),
                        probabilities=pred.get("probabilities", {}), forensic=forensic, root_cause=root_cause,
                    )
                    _event("AI_HUMAN_CONFLICT_REVERSE_ENGINEERED", sample_id=sample_id, conflict_id=conflict_id, ai=pred.get("verdict"), admin=label)
            except Exception as exc:
                _event("AI_HUMAN_CONFLICT_REVIEW_FAILED", sample_id=sample_id, error=str(exc)[:300])
        if previous_label and previous_label != label:
            _event("LABEL_CORRECTED", sample_id=sample_id, label=label, previous_label=previous_label, pdp_id=str(pdp_id))
        else:
            _event("LABEL_ADDED", sample_id=sample_id, label=label, pdp_id=str(pdp_id))
        auto_scheduled = _maybe_schedule_auto_train()
        return {"ok": True, "sample_id": sample_id, "source_sha256": sha, "features": len(features), "classification": classification,
                "reversal": history, "conflict_investigation_id": conflict_id, "auto_train_scheduled": auto_scheduled}



def _resolve_retained_source(pdp_id: str) -> Path | None:
    """Resolve a retained quarantine object without modifying it."""
    value = str(pdp_id or "").strip().lstrip("/")
    if not value:
        return None
    try:
        base = QUARANTINE_DIR.resolve()
        candidate = (base / value).resolve()
        candidate.relative_to(base)
    except Exception:
        return None
    return candidate if candidate.is_file() else None


def migrate_legacy_feature_rows() -> dict:
    """Do not migrate legacy labels into the current clean AI generation.

    Historical rows remain available for audit, but clean-generation training is
    isolated and only explicit current-generation ground truth is eligible.
    """
    return {"migrated": 0, "missing_source": 0, "already_current": 0, "disabled_for_clean_generation": True}


def _row_is_current_generation(row: dict) -> bool:
    generation = str(row.get("generation_id") or "").strip()
    if generation:
        return generation == CURRENT_GENERATION and int(row.get("feature_schema") or 0) >= CURRENT_FEATURE_SCHEMA
    # Compatibility bridge for labels created after the clean-start reset but
    # before generation_id was added.  They are schema-v4 rows in the reset
    # dataset and are treated as current; all future rows carry generation_id.
    return int(row.get("feature_schema") or 0) >= CURRENT_FEATURE_SCHEMA


def _model_is_current_generation(model: dict | None) -> bool:
    if not model:
        return False
    return (
        str(model.get("generation_id") or "").strip() == CURRENT_GENERATION
        and int(model.get("feature_schema") or 0) >= CURRENT_FEATURE_SCHEMA
        and str(model.get("authentication_policy") or "").strip() == CURRENT_AUTH_POLICY
    )

def _sanitize_authentication_policy_features(features: dict) -> dict:
    """Remove legacy direct PASS tokens from existing approved label vectors.

    Existing admin ground truth remains valid and auditable. This in-memory
    compatibility scrub prevents pre-R1.1.28 authentication PASS features from
    becoming HAM shortcuts when those historical labels are retrained.
    """
    cleaned = dict(features or {})
    legacy_tokens = []
    for mechanism in ("spf", "dkim", "dmarc"):
        legacy_tokens.append(_hash_token("auth:" + mechanism + ":pass"))
    for header in ("authentication-results", "received-spf"):
        legacy_tokens.append(_hash_token("authhdr:" + header + ":pass"))
    for token in legacy_tokens:
        cleaned.pop(token, None)
    return cleaned


def _rows_for_current_auth_policy(rows):
    normalized = []
    for row in rows:
        copy = dict(row)
        copy["features"] = _sanitize_authentication_policy_features(row.get("features") or {})
        normalized.append(copy)
    return normalized


def _split(rows):
    """Deterministic label-stratified 80/20 split.

    The hash-based split is stable between runs, which lets candidate metrics be
    compared without silently reshuffling the validation set each time.
    """
    train, holdout = [], []
    by_label = {"HAM": [], "SPAM": []}
    for row in rows:
        by_label.setdefault(row["label"], []).append(row)
    for label in ("HAM", "SPAM"):
        group = by_label.get(label, [])
        for row in group:
            key = row.get("source_sha256") or row.get("sample_id") or ""
            if int(hashlib.sha256((label + ":" + key).encode()).hexdigest()[:8], 16) % 5 == 0:
                holdout.append(row)
            else:
                train.append(row)
        # On very small sets, force at least one holdout sample without making
        # the training side empty. MIN_PER_CLASS is still enforced separately.
        if len(group) >= 5 and not any(x["label"] == label for x in holdout):
            candidates = [x for x in train if x["label"] == label]
            if len(candidates) > 1:
                moved = sorted(candidates, key=lambda x: x.get("source_sha256") or x.get("sample_id") or "")[0]
                train.remove(moved)
                holdout.append(moved)
    if not train:
        train = list(rows)
        holdout = []
    return train, holdout


def _fit_mnb(rows):
    classes = {"HAM": {"docs": 0, "total": 0, "counts": defaultdict(int)}, "SPAM": {"docs": 0, "total": 0, "counts": defaultdict(int)}}
    vocabulary = set()
    for row in rows:
        cls = classes[row["label"]]
        cls["docs"] += 1
        for feature, value in row["features"].items():
            count = max(0, min(int(value), 100))
            if not count:
                continue
            cls["counts"][feature] += count
            cls["total"] += count
            vocabulary.add(feature)
    return classes, vocabulary


def _predict_mnb(model: dict, features: dict):
    labels = ("HAM", "SPAM")
    scores = {}
    vocab_size = max(1, int(model.get("vocabulary_size", 1)))
    total_docs = sum(int(model["classes"][x]["docs"]) for x in labels)
    for label in labels:
        cls = model["classes"][label]
        prior = (int(cls["docs"]) + 1.0) / (total_docs + len(labels))
        denom = int(cls["total"]) + vocab_size
        score = math.log(prior)
        counts = cls.get("counts", {})
        for feature, raw_value in features.items():
            value = max(0, min(int(raw_value), 100))
            if value:
                score += value * math.log((int(counts.get(feature, 0)) + 1.0) / denom)
        scores[label] = score
    high = max(scores.values())
    probs = {k: math.exp(v - high) for k, v in scores.items()}
    norm = sum(probs.values()) or 1.0
    probs = {k: v / norm for k, v in probs.items()}
    verdict = max(probs, key=probs.get)
    return {"verdict": verdict, "confidence": round(probs[verdict] * 100, 2), "probabilities": {k: round(v * 100, 2) for k, v in probs.items()}}


def _scaled_features(features: dict):
    for feature, raw_value in features.items():
        try:
            value = max(0.0, min(float(raw_value), 100.0))
        except Exception:
            continue
        if value:
            yield feature, math.log1p(value)


def _sigmoid(z: float) -> float:
    z = max(-35.0, min(35.0, z))
    return 1.0 / (1.0 + math.exp(-z))


def _fit_logistic(rows):
    """Sparse class-balanced logistic regression over the existing hashed features.

    This remains fully local/offline and has no new ML runtime dependency. Class
    weighting prevents the larger SPAM class from dominating the objective.
    """
    class_counts = Counter(row["label"] for row in rows)
    total = max(1, len(rows))
    class_weight = {
        label: total / (2.0 * max(1, class_counts[label]))
        for label in ("HAM", "SPAM")
    }
    weights = defaultdict(float)
    intercept = 0.0
    ordered = sorted(rows, key=lambda x: x.get("source_sha256") or x.get("sample_id") or "")
    for epoch in range(LOGISTIC_EPOCHS):
        lr = LOGISTIC_LR / (1.0 + 0.18 * epoch)
        # Deterministic epoch rotation avoids relying on random state.
        if ordered:
            shift = epoch % len(ordered)
            epoch_rows = ordered[shift:] + ordered[:shift]
        else:
            epoch_rows = ordered
        for row in epoch_rows:
            y = 1.0 if row["label"] == "SPAM" else 0.0
            z = intercept
            scaled = list(_scaled_features(row["features"]))
            for feature, value in scaled:
                z += weights.get(feature, 0.0) * value
            p = _sigmoid(z)
            sample_weight = HARD_HAM_WEIGHT if row["label"] == "HAM" and row.get("hard_ham") else 1.0
            factor = (p - y) * class_weight[row["label"]] * sample_weight
            intercept -= lr * factor
            for feature, value in scaled:
                old = weights.get(feature, 0.0)
                weights[feature] = old - lr * (factor * value + LOGISTIC_L2 * old)
    # Remove numerically irrelevant weights to keep the model compact.
    compact = {k: round(v, 10) for k, v in weights.items() if abs(v) >= 1e-9}
    return {"intercept": round(intercept, 10), "weights": compact, "class_weight": class_weight}


def _predict_logistic(model: dict, features: dict):
    z = float(model.get("intercept", 0.0))
    weights = model.get("weights", {})
    for feature, value in _scaled_features(features):
        z += float(weights.get(feature, 0.0)) * value
    spam = _sigmoid(z)
    ham = 1.0 - spam
    verdict = "SPAM" if spam >= 0.5 else "HAM"
    confidence = spam if verdict == "SPAM" else ham
    return {
        "verdict": verdict,
        "confidence": round(confidence * 100.0, 2),
        "probabilities": {"HAM": round(ham * 100.0, 2), "SPAM": round(spam * 100.0, 2)},
    }


def _predict_model(model: dict, features: dict):
    algorithm = str(model.get("algorithm") or "")
    if algorithm.startswith("balanced-logistic-regression-hashed-v"):
        return _predict_logistic(model, features)
    return _predict_mnb(model, features)


def _metrics(model: dict, holdout):
    cm = {"true_spam": 0, "true_ham": 0, "false_positive": 0, "false_negative": 0}
    validation_errors=[]
    hard_ham_total=hard_ham_correct=hard_ham_fp=0
    for row in holdout:
        prediction = _predict_model(model, row["features"])
        pred = prediction["verdict"]
        actual = row["label"]
        is_hard_ham=bool(actual=="HAM" and row.get("hard_ham"))
        if is_hard_ham:
            hard_ham_total += 1
        if actual == "SPAM" and pred == "SPAM":
            cm["true_spam"] += 1
        elif actual == "HAM" and pred == "HAM":
            cm["true_ham"] += 1
            if is_hard_ham: hard_ham_correct += 1
        elif actual == "HAM" and pred == "SPAM":
            cm["false_positive"] += 1
            if is_hard_ham: hard_ham_fp += 1
        elif actual == "SPAM" and pred == "HAM":
            cm["false_negative"] += 1
        if actual != pred:
            validation_errors.append({
                "sample_id": str(row.get("sample_id") or ""),
                "pdp_id": str(row.get("pdp_id") or ""),
                "actual": actual, "predicted": pred,
                "confidence": prediction.get("confidence"),
                "probabilities": prediction.get("probabilities", {}),
                "hard_ham": bool(row.get("hard_ham")),
                "error_type": "FALSE_POSITIVE" if actual=="HAM" else "FALSE_NEGATIVE",
                "reverse_engineering_required": True,
            })
    n = len(holdout)
    tp, tn, fp, fn = cm["true_spam"], cm["true_ham"], cm["false_positive"], cm["false_negative"]
    spam_total = tp + fn
    ham_total = tn + fp
    spam_precision = tp / (tp + fp) if (tp + fp) else 0.0
    spam_recall = tp / spam_total if spam_total else 0.0
    ham_precision = tn / (tn + fn) if (tn + fn) else 0.0
    ham_recall = tn / ham_total if ham_total else 0.0
    def f1(p, r):
        return 2.0 * p * r / (p + r) if (p + r) else 0.0
    metrics = {
        "holdout_samples": n, "holdout_ham": ham_total, "holdout_spam": spam_total,
        "holdout_hard_ham": hard_ham_total,
        "hard_ham_correct": hard_ham_correct,
        "hard_ham_false_positive": hard_ham_fp,
        "hard_ham_recall": round(100.0*hard_ham_correct/hard_ham_total,2) if hard_ham_total else None,
        "accuracy": round(100.0 * (tp + tn) / n, 2) if n else None,
        "balanced_accuracy": round(50.0 * (spam_recall + ham_recall), 2) if spam_total and ham_total else None,
        "spam_precision": round(100.0 * spam_precision, 2), "spam_recall": round(100.0 * spam_recall, 2),
        "spam_f1": round(100.0 * f1(spam_precision, spam_recall), 2),
        "ham_precision": round(100.0 * ham_precision, 2), "ham_recall": round(100.0 * ham_recall, 2),
        "ham_f1": round(100.0 * f1(ham_precision, ham_recall), 2),
        "false_positive": fp, "false_negative": fn,
        "false_positive_rate": round(100.0 * fp / ham_total, 3) if ham_total else None,
        "false_negative_rate": round(100.0 * fn / spam_total, 3) if spam_total else None,
        "confusion_matrix": cm,
        "validation_errors": validation_errors,
    }
    return metrics


def _model_summary(model: dict):
    return {k: v for k, v in model.items() if k not in {"classes", "weights"}}


def train_candidate(username: str = "", trigger: str = "manual"):
    if not AI_ENABLED:
        raise RuntimeError("AI trainer is disabled")
    with _lock:
        migration = migrate_legacy_feature_rows()
        rows = [row for row in _dataset_rows() if _row_is_current_generation(row)]
        rows = _rows_for_current_auth_policy(rows)
        counts = Counter(row["label"] for row in rows)
        if counts["HAM"] < MIN_PER_CLASS or counts["SPAM"] < MIN_PER_CLASS:
            raise RuntimeError(f"Need at least {MIN_PER_CLASS} HAM and {MIN_PER_CLASS} SPAM labels; have HAM={counts['HAM']} SPAM={counts['SPAM']}")
        train_rows, holdout = _split(rows)
        version = datetime.now(timezone.utc).strftime("ai-%Y%m%d-%H%M%S")

        # Benchmark legacy MNB against the stronger class-balanced logistic model
        # on the same deterministic holdout. Choose by balanced accuracy first,
        # then SPAM F1 and plain accuracy.
        classes, vocabulary = _fit_mnb(train_rows)
        mnb = {
            "version": version,
            "created_at": _now(),
            "algorithm": "multinomial-naive-bayes-hashed-v2-independent",
            "shadow_only": True,
            "feature_schema": CURRENT_FEATURE_SCHEMA,
            "generation_id": CURRENT_GENERATION,
            "authentication_policy": CURRENT_AUTH_POLICY,
            "vocabulary_size": len(vocabulary),
            "training_samples": len(train_rows),
            "dataset_samples": len(rows),
            "class_counts": dict(counts),
            "classes": {label: {"docs": cls["docs"], "total": cls["total"], "counts": dict(cls["counts"])} for label, cls in classes.items()},
        }
        mnb_metrics = _metrics(mnb, holdout) if holdout else _metrics(mnb, [])
        mnb["metrics"] = mnb_metrics

        fitted = _fit_logistic(train_rows)
        logistic = {
            "version": version,
            "created_at": _now(),
            "algorithm": "balanced-logistic-regression-hashed-v4-authneutral-independent",
            "shadow_only": True,
            "feature_schema": CURRENT_FEATURE_SCHEMA,
            "generation_id": CURRENT_GENERATION,
            "authentication_policy": CURRENT_AUTH_POLICY,
            "hard_ham_weight": HARD_HAM_WEIGHT,
            "training_samples": len(train_rows),
            "dataset_samples": len(rows),
            "class_counts": dict(counts),
            "epochs": LOGISTIC_EPOCHS,
            "learning_rate": LOGISTIC_LR,
            "l2": LOGISTIC_L2,
            **fitted,
        }
        logistic_metrics = _metrics(logistic, holdout) if holdout else _metrics(logistic, [])
        logistic["metrics"] = logistic_metrics

        def rank(model):
            m = model.get("metrics", {})
            return (
                -1.0 if m.get("balanced_accuracy") is None else float(m.get("balanced_accuracy")),
                float(m.get("spam_f1") or 0.0),
                -1.0 if m.get("accuracy") is None else float(m.get("accuracy")),
            )
        selected = logistic if rank(logistic) >= rank(mnb) else mnb
        selected["benchmark"] = {
            "selected_algorithm": selected["algorithm"],
            "multinomial_naive_bayes": mnb_metrics,
            "balanced_logistic_regression": logistic_metrics,
        }
        selected["training_trigger"] = trigger
        selected["feature_migration"] = migration

        _ensure()
        tmp = CANDIDATE_MODEL.with_suffix(".tmp")
        tmp.write_text(json.dumps(selected, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        tmp.replace(CANDIDATE_MODEL)
        _invalidate_status_cache()
        _event("CANDIDATE_TRAINED", version=version, username=username, trigger=trigger, samples=len(rows), algorithm=selected["algorithm"], metrics=selected["metrics"])
        return _model_summary(selected)


def promote_candidate(username: str = ""):
    with _lock:
        if not CANDIDATE_MODEL.exists():
            raise RuntimeError("No candidate model is available")
        model = json.loads(CANDIDATE_MODEL.read_text(encoding="utf-8"))
        if not _model_is_current_generation(model):
            raise RuntimeError("No candidate model is available for the current independent AI generation")
        _ensure()
        tmp = ACTIVE_MODEL.with_suffix(".tmp")
        tmp.write_text(json.dumps(model, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        tmp.replace(ACTIVE_MODEL)
        _invalidate_status_cache()
        MODEL_META.write_text(json.dumps({"active_version": model.get("version"), "promoted_at": _now(), "promoted_by": username}, sort_keys=True), encoding="utf-8")
        _event("MODEL_PROMOTED", version=model.get("version"), username=username, algorithm=model.get("algorithm"))
        return {"ok": True, "active_version": model.get("version"), "algorithm": model.get("algorithm"), "shadow_only": True}


def _load_model(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def predict_file(source_path: Path, item: dict | None = None):
    if not AI_ENABLED:
        return {"enabled": False, "shadow_only": True, "available": False}
    model = _load_model(ACTIVE_MODEL)
    if not model:
        return {"enabled": True, "shadow_only": True, "available": False, "reason": "No active AI model"}
    if not _model_is_current_generation(model):
        return {
            "enabled": True, "shadow_only": True, "available": False,
            "reason": "Independent generation started. No active independent model has been promoted yet.",
        }
    features = extract_features(source_path, None)
    result = _predict_model(model, features)
    return {"enabled": True, "shadow_only": True, "available": True, "model_version": model.get("version"), "algorithm": model.get("algorithm"), "attachment_intelligence": attachment_intelligence(source_path), **result}


def predict_shadow_candidate_file(source_path: Path, item: dict | None = None):
    """Predict with the current-generation candidate for manual/shadow analysis only.

    This helper is intentionally separate from predict_file(): production-adjacent
    quarantine views continue to use only an explicitly promoted active model, while
    the manual Email Analysis workbench may inspect the current trainer candidate.
    Neither path can influence delivery or create training labels.
    """
    if not AI_ENABLED:
        return {"enabled": False, "shadow_only": True, "available": False, "model_role": "candidate"}
    model = _load_model(CANDIDATE_MODEL)
    if not model:
        return {"enabled": True, "shadow_only": True, "available": False, "model_role": "candidate", "reason": "No candidate AI model"}
    if not _model_is_current_generation(model):
        return {
            "enabled": True, "shadow_only": True, "available": False, "model_role": "candidate",
            "reason": "No candidate model is available for the current independent generation.",
        }
    features = extract_features(source_path, None)
    result = _predict_model(model, features)
    return {
        "enabled": True, "shadow_only": True, "available": True, "model_role": "candidate",
        "model_version": model.get("version"), "algorithm": model.get("algorithm"),
        "feature_schema": model.get("feature_schema", CURRENT_FEATURE_SCHEMA),
        "generation_id": model.get("generation_id", CURRENT_GENERATION),
        "authentication_policy": model.get("authentication_policy", CURRENT_AUTH_POLICY), "attachment_intelligence": attachment_intelligence(source_path), **result,
    }


def _auto_train_worker():
    global _auto_train_running
    try:
        _event("AUTO_TRAIN_STARTED")
        result = train_candidate(username="auto-trainer", trigger="automatic-threshold")
        _event("AUTO_TRAIN_COMPLETED", version=result.get("version"), samples=result.get("dataset_samples"), algorithm=result.get("algorithm"))
    except Exception as exc:
        _event("AUTO_TRAIN_FAILED", error=str(exc)[:500])
    finally:
        with _lock:
            _auto_train_running = False
_status_cache = {"ts": 0.0, "signature": None, "value": None}
STATUS_CACHE_SECONDS = max(1.0, float(os.getenv("AI_TRAINER_STATUS_CACHE_SECONDS", "8")))


def _maybe_schedule_auto_train():
    global _auto_train_running
    if not AI_ENABLED or AUTO_TRAIN_AFTER_NEW_LABELS <= 0:
        return False
    candidate = _load_model(CANDIDATE_MODEL)
    if not _model_is_current_generation(candidate):
        candidate = None
    current = len([row for row in _dataset_rows() if _row_is_current_generation(row)])
    baseline = int(candidate.get("dataset_samples", 0)) if candidate else 0
    if current - baseline < AUTO_TRAIN_AFTER_NEW_LABELS:
        return False
    with _lock:
        if _auto_train_running:
            return False
        _auto_train_running = True
    thread = threading.Thread(target=_auto_train_worker, name="ai-auto-trainer", daemon=True)
    thread.start()
    return True


def _status_signature():
    values=[]
    for path in (DATASET, CANDIDATE_MODEL, ACTIVE_MODEL):
        try:
            st=path.stat(); values.append((str(path), st.st_mtime_ns, st.st_size))
        except FileNotFoundError:
            values.append((str(path), 0, 0))
    values.append(("auto", int(_auto_train_running), 0))
    return tuple(values)

def _invalidate_status_cache():
    _status_cache["ts"] = 0.0
    _status_cache["signature"] = None
    _status_cache["value"] = None

def status():
    signature=_status_signature()
    now=time.monotonic()
    cached=_status_cache.get("value")
    if cached is not None and _status_cache.get("signature")==signature and now-float(_status_cache.get("ts") or 0.0) < STATUS_CACHE_SECONDS:
        # JSON round-trip prevents callers mutating the shared snapshot.
        return json.loads(json.dumps(cached))
    snapshot = _status_snapshot() if AI_ENABLED else {
        "dataset_samples": 0, "ham_labels": 0, "spam_labels": 0,
        "hard_ham_labels": 0, "legacy_feature_labels": 0,
    }
    stored_candidate = _load_model(CANDIDATE_MODEL)
    stored_active = _load_model(ACTIVE_MODEL)
    candidate = stored_candidate if _model_is_current_generation(stored_candidate) else None
    active = stored_active if _model_is_current_generation(stored_active) else None
    candidate_samples = int(candidate.get("dataset_samples", 0)) if candidate else 0
    dataset_samples = int(snapshot.get("dataset_samples") or 0)
    labels_since_candidate = max(0, dataset_samples - candidate_samples)
    next_auto = None
    if AUTO_TRAIN_AFTER_NEW_LABELS > 0:
        next_auto = max(0, AUTO_TRAIN_AFTER_NEW_LABELS - labels_since_candidate)
    result={
        "enabled": AI_ENABLED, "shadow_only": True, "state_dir": str(STATE_DIR),
        "dataset_samples": dataset_samples, "ham_labels": int(snapshot.get("ham_labels") or 0), "spam_labels": int(snapshot.get("spam_labels") or 0),
        "hard_ham_labels": int(snapshot.get("hard_ham_labels") or 0),
        "feature_schema": CURRENT_FEATURE_SCHEMA, "generation_id": CURRENT_GENERATION,
        "legacy_feature_labels": int(snapshot.get("legacy_feature_labels") or 0),
        "legacy_candidate_archived": bool(stored_candidate and candidate is None),
        "legacy_active_archived": bool(stored_active and active is None),
        "hard_ham_weight": HARD_HAM_WEIGHT,
        "feature_families": ["nlp_text", "stylometry_structural", "authentication_alignment", "sender_header_anomaly", "url_domain", "mime_attachment", "independent_authentication"],
        "amavis_hook": {"mode": "disabled", "configured_mode": AI_AMAVIS_HOOK_MODE, "reserved": True, "endpoint_contract": AI_AMAVIS_HOOK_ENDPOINT, "decision_capable_in_this_release": False, "feeds_ai_features": False, "note": "Reserved future integration contract only; current AI remains independent and shadow-only."},
        "minimum_per_class": MIN_PER_CLASS, "auto_train_after_new_labels": AUTO_TRAIN_AFTER_NEW_LABELS,
        "labels_since_candidate": labels_since_candidate, "next_auto_train_in": next_auto,
        "auto_train_running": _auto_train_running,
        "status_cache_seconds": STATUS_CACHE_SECONDS,
        "candidate": (_model_summary(candidate) if candidate else None),
        "active": (_model_summary(active) if active else None),
    }
    _status_cache.update({"ts": now, "signature": signature, "value": result})
    return json.loads(json.dumps(result))
