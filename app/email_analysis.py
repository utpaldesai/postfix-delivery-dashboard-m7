"""Non-persistent manual RFC822 email analysis for the dashboard."""
from __future__ import annotations

import re
import os
import tempfile
from urllib.parse import urlsplit
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from .geoip_intelligence import enrich_header


def _rules(distribution: str):
    rows = []
    for token in (distribution or "").split(","):
        token = token.strip()
        if not token:
            continue
        if "=" in token:
            name, value = token.split("=", 1)
        else:
            name, value = token, ""
        name, value = name.strip(), value.strip()
        try:
            score = float(value) if value else None
        except ValueError:
            score = None
        if name:
            rows.append({"name": name, "value": value, "score": score})
    return rows


URL_RE = re.compile(r"https?://[^\\s<>\\\"']+", re.I)

def _message_content(msg):
    attachments=[]
    text_parts=[]
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            payload=part.get_payload(decode=True) or b""
            filename=part.get_filename()
            disposition=(part.get_content_disposition() or "").lower()
            ctype=part.get_content_type()
            if filename or disposition=="attachment":
                attachments.append({"filename": str(filename or "unnamed"), "content_type": ctype, "size": len(payload)})
            elif ctype in ("text/plain","text/html"):
                charset=part.get_content_charset() or "utf-8"
                try: text_parts.append(payload.decode(charset,"replace"))
                except LookupError: text_parts.append(payload.decode("utf-8","replace"))
    else:
        payload=msg.get_payload(decode=True) or b""
        charset=msg.get_content_charset() or "utf-8"
        try: text_parts.append(payload.decode(charset,"replace"))
        except LookupError: text_parts.append(payload.decode("utf-8","replace"))
    urls=[]
    seen=set()
    for text in text_parts:
        for url in URL_RE.findall(text or ""):
            url=url.rstrip(".,);]}>\\\"")
            if url not in seen:
                seen.add(url); urls.append(url)
    return attachments, urls[:100]


SHARED_INFRA_HINTS = ("sendgrid.net", "amazonses.com", "amazonaws.com", "mailgun.org", "sparkpostmail.com")
FINANCIAL_LURES = (
    "bank details", "bank account", "beneficiary", "payment instruction", "payment instructions",
    "wire transfer", "remittance", "invoice", "outstanding payment", "change of account",
    "new account", "revised account", "payment today", "urgent payment", "gift card", "payroll"
)
URGENCY_LURES = ("urgent", "immediately", "asap", "confidential", "do not call", "don't call", "secret", "today only")

def _domain(addr: str) -> str:
    email=parseaddr(addr or "")[1].lower().strip()
    return email.rsplit("@",1)[1] if "@" in email else ""

def _bec_intelligence(msg, urls):
    from_raw=str(msg.get("From", "") or "")
    display, from_addr=parseaddr(from_raw)
    reply=str(msg.get("Reply-To", "") or "")
    reply_addr=parseaddr(reply)[1]
    from_domain=_domain(from_raw); reply_domain=_domain(reply)
    subject=str(msg.get("Subject", "") or "")
    body_parts=[]
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain","text/html") and not part.is_multipart():
                    payload=part.get_payload(decode=True) or b""
                    body_parts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
        else:
            payload=msg.get_payload(decode=True) or b""
            body_parts.append(payload.decode(msg.get_content_charset() or "utf-8", "replace"))
    except Exception:
        pass
    text=(subject+"\n"+"\n".join(body_parts)).lower()
    evidence=[]; identity=0; intent=0; technical=0
    # Display-name deception / address-as-display-name
    if display and "@" in display:
        evidence.append({"signal":"Email address used in display name","severity":"high","detail":display[:160]}); identity+=25
    if display and from_addr and display.lower().strip('<> ') == from_addr.lower():
        evidence.append({"signal":"Display name mirrors sender address","severity":"medium","detail":display[:160]}); identity+=8
    if reply_addr and from_addr and reply_addr.lower()!=from_addr.lower():
        sev="high" if reply_domain and from_domain and reply_domain!=from_domain else "medium"
        evidence.append({"signal":"From / Reply-To mismatch","severity":sev,"detail":f"From {from_addr}; Reply-To {reply_addr}"}); identity+=20 if sev=="high" else 10
    # Simple look-alike cues without claiming a known-good domain
    if from_domain and ("xn--" in from_domain or re.search(r"\d", from_domain.split('.')[0]) or from_domain.count('-')>=2):
        evidence.append({"signal":"Domain resembles a look-alike / obfuscated identity pattern","severity":"medium","detail":from_domain}); identity+=12
    received=" ".join(str(x) for x in msg.get_all("Received",[]) if x).lower()
    shared=next((h for h in SHARED_INFRA_HINTS if h in received), None)
    if shared:
        evidence.append({"signal":"Shared mail infrastructure","severity":"info","detail":shared+" — contextual evidence only; not a spam verdict"})
    financial=[x for x in FINANCIAL_LURES if x in text]
    if financial:
        evidence.append({"signal":"Financial / payment lure language","severity":"high","detail":", ".join(financial[:6])}); intent+=min(45,15+5*len(financial))
    urgent=[x for x in URGENCY_LURES if x in text]
    if urgent:
        evidence.append({"signal":"Urgency / secrecy language","severity":"medium","detail":", ".join(urgent[:6])}); intent+=min(25,8+4*len(urgent))
    # URL mismatches / risky URL density (evidence only)
    domains=[]
    for u in urls or []:
        try:
            d=(urlsplit(u).hostname or "").lower()
            if d: domains.append(d)
        except Exception: pass
    if len(set(domains))>=5:
        evidence.append({"signal":"Many external URL domains","severity":"medium","detail":f"{len(set(domains))} distinct URL domains"}); intent+=8
    auth=" ".join(str(x) for x in msg.get_all("Authentication-Results",[]) if x).lower()
    if "spf=pass" in auth: technical+=1
    if "dkim=pass" in auth: technical+=1
    if "dmarc=pass" in auth: technical+=1
    score=min(100, identity+intent)
    if score>=70: level="CRITICAL"
    elif score>=45: level="HIGH"
    elif score>=20: level="MEDIUM"
    else: level="LOW"
    if level in ("CRITICAL","HIGH"): action="VERIFY OUT-OF-BAND"
    elif level=="MEDIUM": action="RETAIN FOR REVIEW"
    else: action="NO STRONG BEC SIGNALS DETECTED"
    return {
        "overall_suspicion": level,
        "suspicion_score": score,
        "technical_authentication_passes": technical,
        "authentication_interpretation": "IDENTITY ONLY — PASS is neutral for HAM/SPAM intent",
        "identity_risk_score": min(100,identity),
        "intent_risk_score": min(100,intent),
        "recommended_action": action,
        "evidence": evidence,
        "note":"SPF/DKIM/DMARC PASS proves authentication/alignment only. It adds no HAM trust weight; authenticated UCE, phishing and compromised-account mail can still be SPAM."
    }

def analyze_raw(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    auth = " ".join(str(x) for x in msg.get_all("Authentication-Results", []) if x).lower()
    spf_header = " ".join(str(x) for x in msg.get_all("Received-SPF", []) if x).lower()
    combined = (auth + " " + spf_header).replace(" ", "")
    if "spf=pass" in combined or spf_header.startswith("pass"):
        spf = "pass"
    elif "softfail" in combined:
        spf = "softfail"
    elif "spf=fail" in combined or spf_header.startswith("fail"):
        spf = "fail"
    else:
        spf = "none"
    dkim = "pass" if "dkim=pass" in auth else ("fail" if "dkim=fail" in auth else "none")
    if "dmarc=pass" in auth:
        dmarc = "pass"
    elif "dmarc=fail" in auth:
        dmarc = "fail"
    elif "dmarc=temperror" in auth:
        dmarc = "temperror"
    elif "dmarc=permerror" in auth:
        dmarc = "permerror"
    else:
        dmarc = "none"

    spam_status = str(msg.get("X-Spam-Status", "") or "")
    tests_match = re.search(r"tests=\[(.*?)\]", spam_status, re.I | re.S)
    required_match = re.search(r"required=([-+]?\d+(?:\.\d+)?)", spam_status, re.I)
    score_raw = str(msg.get("X-Spam-Score", "0.0") or "0.0")
    required = required_match.group(1) if required_match else "5.0"
    prefix = spam_status.split(",", 1)[0].strip().lower()
    if prefix.startswith("yes"):
        verdict = "SPAM"
    elif prefix.startswith("no"):
        verdict = "HAM"
    else:
        try:
            verdict = "SPAM" if float(score_raw) >= float(required) else "HAM"
        except ValueError:
            verdict = "UNKNOWN"
    distribution = tests_match.group(1) if tests_match else ""
    rules = _rules(distribution)
    positives = sorted([x for x in rules if isinstance(x.get("score"), (int, float)) and x["score"] > 0], key=lambda x: x["score"], reverse=True)
    negatives = sorted([x for x in rules if isinstance(x.get("score"), (int, float)) and x["score"] < 0], key=lambda x: x["score"])
    header_text = "\n".join(f"Received: {value}" for value in msg.get_all("Received", []) if value)
    attachments, urls = _message_content(msg)
    bec = _bec_intelligence(msg, urls)
    return {
        "from": str(msg.get("From", "") or ""),
        "to": str(msg.get("To", "") or ""),
        "cc": str(msg.get("Cc", "") or ""),
        "reply_to": str(msg.get("Reply-To", "") or ""),
        "subject": str(msg.get("Subject", "") or ""),
        "message_id": str(msg.get("Message-ID", "") or ""),
        "date": str(msg.get("Date", "") or ""),
        "authentication": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "spamassassin": {
            "score": score_raw,
            "required_score": required,
            "verdict": verdict,
            "top_positive": positives[:5],
            "top_negative": negatives[:3],
            "all_rules": rules,
        },
        "geoip": enrich_header(header_text),
        "attachments": attachments,
        "urls": urls,
        "bec": bec,
        "persisted": False,
        "network_lookup": False,
    }



def _msg_to_rfc822(raw: bytes) -> bytes:
    """Convert an Outlook .msg container to a conservative RFC822 representation.

    The temporary file exists only while extract-msg parses the compound document.
    Original transport headers are preserved when extract-msg exposes them; otherwise
    standard message metadata is synthesized. Attachments are never executed.
    """
    if not raw.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
        raise ValueError("The selected .msg file is not a valid Outlook Compound File Binary message")
    try:
        import extract_msg
    except Exception as exc:  # pragma: no cover - dependency/runtime failure
        raise RuntimeError("Outlook MSG support is unavailable (extract-msg is not installed)") from exc

    fd, path = tempfile.mkstemp(prefix="pdd-email-analysis-", suffix=".msg")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        msg = extract_msg.Message(path)
        try:
            header_obj = getattr(msg, "header", None)
            if header_obj is None:
                header_text = ""
            elif isinstance(header_obj, bytes):
                header_text = header_obj.decode("utf-8", "replace")
            elif hasattr(header_obj, "as_string"):
                header_text = header_obj.as_string()
            else:
                header_text = str(header_obj)

            # Retain native Internet headers where present, then fill missing
            # presentation fields from the MSG properties.
            lines = [header_text.rstrip("\r\n")] if header_text.strip() else []
            lower = header_text.lower()
            fields = (
                ("From", getattr(msg, "sender", "")),
                ("To", getattr(msg, "to", "")),
                ("Cc", getattr(msg, "cc", "")),
                ("Reply-To", getattr(msg, "replyTo", "")),
                ("Subject", getattr(msg, "subject", "")),
                ("Date", getattr(msg, "date", "")),
            )
            for name, value in fields:
                value = str(value or "").strip()
                if value and f"{name.lower()}:" not in lower:
                    lines.append(f"{name}: {value}")

            body = getattr(msg, "body", None)
            if body is None:
                html = getattr(msg, "htmlBody", None)
                if isinstance(html, bytes):
                    body = html.decode("utf-8", "replace")
                else:
                    body = str(html or "")
            body = str(body or "")
            normalized = "\r\n".join(x for x in lines if x) + "\r\n\r\n" + body
            return normalized.encode("utf-8", "replace")
        finally:
            try:
                msg.close()
            except Exception:
                pass
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def analyze_upload(filename: str, raw: bytes) -> dict:
    """Analyze an uploaded .eml/RFC822 or Outlook .msg message without persisting it."""
    name = (filename or "").strip().lower()
    if name.endswith(".msg"):
        result = analyze_raw(_msg_to_rfc822(raw))
        result["source_format"] = "MSG"
        return result
    result = analyze_raw(raw)
    result["source_format"] = "RFC822/EML"
    return result


def normalize_upload(filename: str, raw: bytes) -> bytes:
    """Return RFC822 bytes for downstream shadow analysis without persistence."""
    if (filename or "").strip().lower().endswith(".msg"):
        return _msg_to_rfc822(raw)
    return raw
