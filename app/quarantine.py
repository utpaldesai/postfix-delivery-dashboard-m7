import datetime
import gzip
import hashlib
import json
import os
import re
import subprocess
import threading
import time
from collections import Counter
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/host-amavis/virusmails"))
STATE_DIR = Path(os.getenv("QUARANTINE_STATE_DIR", "/data/amavis-mgr"))
AUDIT_LOG = STATE_DIR / "quarantine_audit.log"
AUDIT_JSONL = STATE_DIR / "quarantine_audit.jsonl"
RELEASED_DB = STATE_DIR / "released_ids.db"
SPAM_DB = STATE_DIR / "spam_ids.db"
LEARN_SPAM_DB = STATE_DIR / "learn_spam_ids.db"
LEARN_HAM_DB = STATE_DIR / "learn_ham_ids.db"
RELEASE_STATUS_DB = STATE_DIR / "release_status.jsonl"

AMAVIS_PDP_SERVER = os.getenv("AMAVIS_PDP_SERVER", "127.0.0.1:9998")
AMAVIS_RELEASE_CMD = os.getenv("AMAVIS_RELEASE_CMD", "/usr/local/bin/amavisd-release-wrapper")
AMAVIS_RELEASE_TIMEOUT = int(os.getenv("AMAVIS_RELEASE_TIMEOUT", "20"))
SA_LEARN_CMD = os.getenv("SA_LEARN_CMD", "/usr/bin/sa-learn")
SA_LEARN_TIMEOUT = int(os.getenv("SA_LEARN_TIMEOUT", "90"))
SA_LEARN_MAX_SIZE = os.getenv("SA_LEARN_MAX_SIZE", "0").strip() or "0"
SA_LEARN_ENABLED = os.getenv("SA_LEARN_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
SA_LEARN_USER = os.getenv("SA_LEARN_USER", "amavis").strip() or "amavis"
SA_LEARN_ON_MARK_SPAM = os.getenv("SA_LEARN_ON_MARK_SPAM", "true").strip().lower() in {"1", "true", "yes", "on"}
HOME_DOMAINS = [d.strip().lower().lstrip("@") for d in os.getenv("HOME_DOMAINS", "").split(",") if d.strip()]

ITEMS_PER_PAGE = int(os.getenv("QUARANTINE_ITEMS_PER_PAGE", "20"))
CACHE_REFRESH_INTERVAL = int(os.getenv("QUARANTINE_CACHE_REFRESH", "300"))
LOOKBACK_DAYS = int(os.getenv("QUARANTINE_LOOKBACK_DAYS", "6"))

# SAFETY / RETENTION RULE:
# This module never deletes, unlinks, moves, renames, truncates, or overwrites
# any object under QUARANTINE_DIR. Release and Spam actions only update the
# management state files and invoke amavisd-release / SpamAssassin learning only when requested.

cache = {"data": [], "last_updated": "Never", "error": "", "scan_stats": {"parsed": 0, "reused": 0}}
_file_cache = {}
_cache_lock = threading.RLock()
_action_lock = threading.Lock()
_worker_started = False


def ensure_state_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _get_flagged_ids(path: Path):
    if not path.exists():
        return set()
    try:
        return {
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        }
    except OSError:
        return set()


def _mark_id(path: Path, pdp_id: str):
    ensure_state_dir()
    if pdp_id in _get_flagged_ids(path):
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{pdp_id}\n")




def _unmark_id(path: Path, pdp_id: str):
    """Remove one dashboard compatibility flag without touching quarantine content."""
    ensure_state_dir()
    current = [x for x in _get_flagged_ids(path) if x != pdp_id]
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        for value in sorted(current):
            handle.write(value + "\n")
    tmp.replace(path)


def _release_status_map():
    result = {}
    if not RELEASE_STATUS_DB.exists():
        return result
    try:
        for line in RELEASE_STATUS_DB.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            pdp_id = str(row.get("pdp_id") or "")
            if pdp_id:
                result[pdp_id] = row
    except OSError:
        pass
    return result


def release_status_for(pdp_id: str):
    return dict(_release_status_map().get(str(pdp_id), {}))


def _append_release_status(pdp_id: str, queue_id: str, status: str, username: str, detail: str = ""):
    ensure_state_dir()
    row = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "pdp_id": str(pdp_id),
        "queue_id": str(queue_id or ""),
        "status": str(status or ""),
        "username": str(username or ""),
        "detail": str(detail or "")[:1000],
    }
    with RELEASE_STATUS_DB.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n")
    return row


def _extract_release_queue_id(text: str):
    text = str(text or "")
    patterns = (
        r"queued\s+as\s+([A-Za-z0-9]{5,})",
        r"queue(?:[- ]?id)?\s*[:=]\s*([A-Za-z0-9]{5,})",
        r"\b([A-Fa-f0-9]{8,20})\b(?=.*(?:queued|postfix))",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
    return ""

def _learning_for(pdp_id: str):
    if pdp_id in _get_flagged_ids(LEARN_SPAM_DB):
        return "spam"
    if pdp_id in _get_flagged_ids(LEARN_HAM_DB):
        return "ham"
    return ""


def item_for(pdp_id: str):
    """Return a copy of the cached quarantine item without modifying state."""
    with _cache_lock:
        for item in cache["data"]:
            if item.get("pdp_id") == pdp_id:
                return dict(item)
    return None


def _record_learning_history_best_effort(**kwargs):
    """Optional host-maildb history; never changes the existing learning path."""
    try:
        from .quarantine_intelligence import record_learning_best_effort
        return record_learning_best_effort(**kwargs)
    except Exception:
        return False


def sa_learn_ready():
    return bool(SA_LEARN_ENABLED and Path(SA_LEARN_CMD).is_file() and os.access(SA_LEARN_CMD, os.X_OK))


def _sa_learn(pdp_id: str, mode: str, remote_addr: str, username: str = ""):
    if mode not in {"spam", "ham"}:
        raise ValueError("Invalid learning mode")
    if not SA_LEARN_ENABLED:
        raise RuntimeError("SpamAssassin learning is disabled")
    command = Path(SA_LEARN_CMD)
    if not command.is_file() or not os.access(command, os.X_OK):
        raise RuntimeError(f"sa-learn not available at {SA_LEARN_CMD}")

    source = _safe_path(pdp_id)
    previous = _learning_for(pdp_id)
    if previous:
        if previous == mode:
            return {"ok": True, "message": f"Already learned as {mode}", "learning": mode, "already_learned": True}
        raise RuntimeError(f"Message already learned as {previous}; automatic opposite-class relearning is blocked")

    args = [SA_LEARN_CMD, f"--{mode}", "--no-sync", "--max-size", SA_LEARN_MAX_SIZE, "-u", SA_LEARN_USER, str(source)]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=SA_LEARN_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"sa-learn timed out after {SA_LEARN_TIMEOUT} seconds") from exc

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise RuntimeError(stderr or stdout or f"sa-learn exited with code {proc.returncode}")

    _mark_id(LEARN_SPAM_DB if mode == "spam" else LEARN_HAM_DB, pdp_id)

    # Additive Milestone 6 R4 history: SpamAssassin remains the owner of its
    # Bayes tables.  Failure to write dashboard history never changes the
    # existing learning result or flat-file compatibility state.
    snapshot = _item_snapshot(pdp_id)
    examined_match = re.search(r"(\d+)\s+message\(s\)\s+examined", stdout, re.IGNORECASE)
    learned_match = re.search(r"Learned tokens from\s+(\d+)\s+message\(s\)", stdout, re.IGNORECASE)
    try:
        source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    except Exception:
        source_sha256 = ""
    _record_learning_history_best_effort(
        pdp_id=pdp_id,
        message_id=snapshot.get("message_id", ""),
        sender=snapshot.get("sender", ""),
        recipient=snapshot.get("recipient", ""),
        mode=mode,
        username=username,
        client_ip=remote_addr,
        sa_learn_rc=proc.returncode,
        examined_count=int(examined_match.group(1)) if examined_match else None,
        learned_count=int(learned_match.group(1)) if learned_match else None,
        source_sha256=source_sha256,
        sa_learn_output=stdout or stderr,
    )

    # R1.1.52 provenance boundary: SpamAssassin/Bayes learning remains completely
    # separate from AI Set-2 Ground Truth. Do not mirror sa-learn outcomes into
    # the AI trainer; production Bayes behavior and audit history are unchanged.

    write_audit("LEARN_SPAM" if mode == "spam" else "LEARN_HAM", pdp_id, remote_addr, username, detail=(stdout or "learning complete")[:1000])
    with _cache_lock:
        for item in cache["data"]:
            if item.get("pdp_id") == pdp_id:
                item["learning"] = mode
                break
    return {"ok": True, "message": stdout or f"Learned {mode} {pdp_id}", "learning": mode}


def learn_spam(pdp_id: str, remote_addr: str, username: str = ""):
    with _action_lock:
        return _sa_learn(pdp_id, "spam", remote_addr, username)


def learn_ham(pdp_id: str, remote_addr: str, username: str = ""):
    with _action_lock:
        return _sa_learn(pdp_id, "ham", remote_addr, username)


def correct_learning(pdp_id: str, new_mode: str, remote_addr: str, username: str = ""):
    """Correct a previous human HAM/SPAM decision for the same retained message.

    SpamAssassin is asked to forget the prior learned fingerprint before the
    opposite class is learned. Dashboard state is switched only after the new
    learn succeeds. If the new learn fails, a best-effort restore of the old
    class is attempted and the failure is audited.
    """
    new_mode = str(new_mode or "").strip().lower()
    if new_mode not in {"ham", "spam"}:
        raise ValueError("Invalid correction mode")
    with _action_lock:
        if not SA_LEARN_ENABLED:
            raise RuntimeError("SpamAssassin learning is disabled")
        command = Path(SA_LEARN_CMD)
        if not command.is_file() or not os.access(command, os.X_OK):
            raise RuntimeError(f"sa-learn not available at {SA_LEARN_CMD}")
        source = _safe_path(pdp_id)
        previous = _learning_for(pdp_id)
        if not previous:
            raise RuntimeError("Message has no previous dashboard HAM/SPAM learning decision to correct")
        if previous == new_mode:
            return {"ok": True, "message": f"Already learned as {new_mode}", "learning": new_mode, "already_learned": True}

        common = ["--no-sync", "--max-size", SA_LEARN_MAX_SIZE, "-u", SA_LEARN_USER, str(source)]
        forget = subprocess.run([SA_LEARN_CMD, "--forget", *common], capture_output=True, text=True, timeout=SA_LEARN_TIMEOUT, check=False)
        if forget.returncode != 0:
            raise RuntimeError((forget.stderr or forget.stdout or "sa-learn --forget failed").strip())

        learned = subprocess.run([SA_LEARN_CMD, f"--{new_mode}", *common], capture_output=True, text=True, timeout=SA_LEARN_TIMEOUT, check=False)
        if learned.returncode != 0:
            # Best-effort restoration of the previous class so a failed correction
            # does not silently leave production Bayes in an unintended state.
            restore = subprocess.run([SA_LEARN_CMD, f"--{previous}", *common], capture_output=True, text=True, timeout=SA_LEARN_TIMEOUT, check=False)
            detail = (learned.stderr or learned.stdout or "opposite-class learning failed").strip()
            write_audit("LEARNING_CORRECTION_FAILED", pdp_id, remote_addr, username, detail=(detail + f"; restore_rc={restore.returncode}")[:1000])
            raise RuntimeError(detail)

        old_db = LEARN_SPAM_DB if previous == "spam" else LEARN_HAM_DB
        new_db = LEARN_SPAM_DB if new_mode == "spam" else LEARN_HAM_DB
        _unmark_id(old_db, pdp_id)
        _mark_id(new_db, pdp_id)
        if previous == "spam" and new_mode == "ham":
            _unmark_id(SPAM_DB, pdp_id)
        elif new_mode == "spam":
            _mark_id(SPAM_DB, pdp_id)

        snapshot = _item_snapshot(pdp_id)
        try:
            source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        except Exception:
            source_sha256 = ""
        output = (learned.stdout or learned.stderr or "learning correction complete").strip()
        _record_learning_history_best_effort(
            pdp_id=pdp_id, message_id=snapshot.get("message_id", ""), sender=snapshot.get("sender", ""),
            recipient=snapshot.get("recipient", ""), mode=new_mode, username=username, client_ip=remote_addr,
            sa_learn_rc=learned.returncode, examined_count=None, learned_count=None, source_sha256=source_sha256,
            sa_learn_output=f"CORRECTED {previous.upper()} -> {new_mode.upper()}: {output}",
        )
        # AI Set-2 is intentionally not updated from sa-learn correction state.
        # Any AI label change must be submitted separately through Mail Admin
        # Ground Truth so provenance remains explicit and auditable.

        write_audit("CORRECT_TO_HAM" if new_mode == "ham" else "CORRECT_TO_SPAM", pdp_id, remote_addr, username, detail=f"Previous={previous.upper()} New={new_mode.upper()}; {output}"[:1000])
        with _cache_lock:
            for item in cache["data"]:
                if item.get("pdp_id") == pdp_id:
                    item["learning"] = new_mode
                    item["is_manual_spam"] = bool(new_mode == "spam")
                    break
        return {"ok": True, "learning": new_mode, "previous_learning": previous, "message": output}



def _decision_for(pdp_id: str):
    """Return RELEASED, SPAM, or empty for an undecided quarantine object."""
    if pdp_id in _get_flagged_ids(RELEASED_DB):
        return "RELEASED"
    if pdp_id in _get_flagged_ids(SPAM_DB):
        return "SPAM"
    return ""


def _assert_undecided(pdp_id: str):
    decision = _decision_for(pdp_id)
    if decision:
        raise RuntimeError(
            f"Quarantine object already finalized as {decision}; "
            "no further action is permitted"
        )


def _item_snapshot(pdp_id: str):
    with _cache_lock:
        for item in cache["data"]:
            if item.get("pdp_id") == pdp_id:
                return {
                    "from": item.get("from", ""),
                    "to": item.get("to", ""),
                    "subject": item.get("subject", ""),
                    "category": item.get("category", ""),
                    "score": item.get("score", ""),
                    "message_id": item.get("message_id", ""),
                    "sender": item.get("from", ""),
                    "recipient": item.get("display_to", ""),
                }
    return {
        "from": "",
        "to": "",
        "subject": "",
        "category": "",
        "score": "",
        "message_id": "",
        "sender": "",
        "recipient": "",
    }


def write_audit(
    action: str,
    pdp_id: str,
    remote_addr: str,
    username: str = "",
    detail: str = "",
):
    """Append an immutable audit event without altering quarantine objects."""
    ensure_state_dir()
    now = datetime.datetime.now()
    ts = now.strftime("%Y-%m-%d %H:%M:%S")

    # LOGIN events do not have a quarantine object. Release/Spam events do.
    snapshot = (
        _item_snapshot(pdp_id)
        if pdp_id
        else {
            "from": "",
            "to": "",
            "subject": "",
            "category": "",
            "score": "",
        }
    )

    action = (action or "UNKNOWN").strip().upper()
    username = (username or "").strip()
    remote_addr = (remote_addr or "").strip()
    pdp_id = (pdp_id or "").strip()

    # Human-readable append-only audit retained for compatibility.
    with AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(
            f"[{ts}] {action:<10} | USER: {username or '-':<16} "
            f"| IP: {remote_addr or '-':<15} | ID: {pdp_id or '-'}\n"
        )

    # Structured append-only audit used by the Audit tab.
    record = {
        "timestamp": ts,
        "action": action,
        "user": username,
        "ip": remote_addr,
        "pdp_id": pdp_id,
        "from": snapshot["from"],
        "to": snapshot["to"],
        "subject": snapshot["subject"],
        "category": snapshot["category"],
        "score": snapshot["score"],
        "detail": str(detail or ""),
    }
    with AUDIT_JSONL.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )

    # Mirror the append-only audit event into MariaDB for indexed reporting.
    # JSONL remains the immutable secondary copy.
    try:
        from .db import audit_insert
        audit_insert(
            timestamp=ts,
            action=action,
            username=username,
            client_ip=remote_addr,
            pdp_id=pdp_id,
            sender=snapshot["from"],
            recipient=snapshot["to"],
            subject=snapshot["subject"],
            category=snapshot["category"],
            score=snapshot["score"],
            detail=str(detail or ""),
        )
    except Exception:
        # Audit DB failure must not block the primary mail/quarantine action.
        pass


def _safe_path(pdp_id: str) -> Path:
    if not pdp_id:
        raise ValueError("Empty quarantine ID")
    base = QUARANTINE_DIR.resolve()
    candidate = (base / pdp_id).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError("Invalid quarantine path") from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"Quarantine object not found: {pdp_id}")
    return candidate



def _clean_mailbox_values(values):
    """Normalize RFC mailbox headers and remove duplicate recipients."""
    rendered = []
    seen = set()

    for raw_value in values:
        raw = str(raw_value or "").strip()
        if not raw:
            continue

        # Some headers arrive with duplicated quote characters after
        # previous transport/formatting layers. Collapse them first.
        while '""' in raw:
            raw = raw.replace('""', '"')

        pairs = getaddresses([raw])
        useful = [(name, addr) for name, addr in pairs if (name or addr)]

        # Fallback for malformed headers that email.utils cannot parse:
        # retain unique email addresses rather than showing duplicated junk.
        if not useful:
            useful = [("", addr) for addr in re.findall(
                r'(?i)([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})',
                raw,
            )]

        for display_name, address in useful:
            address = (address or "").strip().strip('"').strip()
            display_name = re.sub(
                r'\s+',
                ' ',
                (display_name or "").strip().strip('"'),
            ).strip()

            key = address.lower() if address else display_name.lower()
            if not key or key in seen:
                continue
            seen.add(key)

            if address:
                if display_name and display_name.lower() != address.lower():
                    rendered.append(f"{display_name} <{address}>")
                else:
                    rendered.append(address)
            elif display_name:
                rendered.append(display_name)

    return ", ".join(rendered)



def _extract_address_domain(value: str):
    match = re.search(r"@([\w.-]+)", value or "")
    return match.group(1).lower().rstrip(".") if match else ""


def _home_domain_recipients(values):
    """Return unique recipients belonging to configured home domains only."""
    rendered = []
    seen = set()
    for raw in values:
        for display_name, address in getaddresses([str(raw or "")]):
            address = (address or "").strip().strip('"')
            if not address or "@" not in address:
                continue
            domain = address.rsplit("@", 1)[1].lower().rstrip(".")
            if HOME_DOMAINS and not any(domain == home or domain.endswith("." + home) for home in HOME_DOMAINS):
                continue
            key = address.lower()
            if key in seen:
                continue
            seen.add(key)
            name = re.sub(r"\s+", " ", (display_name or "").strip().strip('"')).strip()
            if name and name.lower() != address.lower():
                rendered.append(f"{name} <{address}>")
            else:
                rendered.append(address)
    return ", ".join(rendered)


def _raw_header_text(raw: bytes):
    """Preserve the original RFC header block without exposing the message body."""
    for separator in (b"\r\n\r\n", b"\n\n"):
        if separator in raw:
            header = raw.split(separator, 1)[0]
            return header.decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _parse_sa_rules(distribution: str):
    rules = []
    for part in (distribution or "").split(","):
        token = part.strip()
        if not token:
            continue
        if "=" in token:
            name, value = token.split("=", 1)
        else:
            name, value = token, ""
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        try:
            numeric = float(value) if value else None
        except ValueError:
            numeric = None
        rules.append({"name": name, "value": value, "score": numeric})
    return rules


def _parse_file(full_path, rel_path, filename, mtime, released_ids, spam_ids):
    opener = gzip.open if filename.endswith(".gz") else open
    with opener(full_path, "rb") as handle:
        raw = handle.read(65536)

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    recipient_sources = [
        msg.get("To", ""),
        msg.get("Cc", ""),
        msg.get("Bcc", ""),
        msg.get("X-Envelope-To", ""),
        msg.get("X-Original-To", ""),
        msg.get("Delivered-To", ""),
    ]
    recips = _clean_mailbox_values(recipient_sources) or "Unknown"
    home_recips = _home_domain_recipients(recipient_sources)

    auth = str(msg.get("Authentication-Results", "")).lower()
    spf_header = str(msg.get("Received-SPF", "")).lower()
    combined = (auth + spf_header).replace(" ", "")

    if "spf=pass" in combined or spf_header.startswith("pass"):
        spf = "pass"
    elif "softfail" in combined:
        spf = "softfail"
    elif "spf=fail" in combined or spf_header.startswith("fail"):
        spf = "fail"
    else:
        spf = "none"

    if "dkim=pass" in auth:
        dkim = "pass"
    elif "dkim=fail" in auth:
        dkim = "fail"
    else:
        dkim = "none"

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

    spam_status = str(msg.get("X-Spam-Status", ""))
    tests = re.search(r"tests=\[(.*?)\]", spam_status, re.IGNORECASE)
    required_match = re.search(r"required=([-+]?\d+(?:\.\d+)?)", spam_status, re.IGNORECASE)
    required_score = required_match.group(1) if required_match else os.getenv("SPAMASSASSIN_REQUIRED_SCORE", "5.0")
    status_prefix = spam_status.split(",", 1)[0].strip().lower()
    if status_prefix.startswith("yes"):
        spam_verdict = "SPAM"
    elif status_prefix.startswith("no"):
        spam_verdict = "HAM"
    else:
        try:
            spam_verdict = "SPAM" if float(str(msg.get("X-Spam-Score", "0.0"))) >= float(required_score) else "HAM"
        except (TypeError, ValueError):
            spam_verdict = "UNKNOWN"

    category = (
        "Virus" if filename.startswith("virus-")
        else "Banned" if filename.startswith("banned-")
        else "Spam"
    )

    from_value = _clean_mailbox_values([msg.get("From", "")]) or "Unknown"
    dt = datetime.datetime.fromtimestamp(mtime)

    return {
        "pdp_id": rel_path,
        "category": category,
        "from": from_value,
        "from_domain": _extract_address_domain(from_value),
        "to": recips,
        "display_to": home_recips or "No home-domain recipient found",
        "header": _raw_header_text(raw),
        "subject": str(msg.get("Subject", "(No Subject)")),
        "message_id": str(msg.get("Message-ID", "") or ""),
        "score": str(msg.get("X-Spam-Score", "0.0")),
        "required_score": required_score,
        "spam_verdict": spam_verdict,
        "distribution": tests.group(1) if tests else "No details",
        "triggered_rules": _parse_sa_rules(tests.group(1) if tests else ""),
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "timestamp": dt.strftime("%Y-%m-%d %H:%M"),
        "date": dt.strftime("%Y-%m-%d"),
        "is_released": rel_path in released_ids,
        "is_manual_spam": rel_path in spam_ids,
        "learning": "spam" if rel_path in _get_flagged_ids(LEARN_SPAM_DB) else ("ham" if rel_path in _get_flagged_ids(LEARN_HAM_DB) else ""),
    }


def refresh_cache():
    """Incrementally scan recent quarantine files using (mtime_ns, size) signatures."""
    global _file_cache
    ensure_state_dir()
    released_ids = _get_flagged_ids(RELEASED_DB)
    spam_ids = _get_flagged_ids(SPAM_DB)
    learn_spam_ids = _get_flagged_ids(LEARN_SPAM_DB)
    learn_ham_ids = _get_flagged_ids(LEARN_HAM_DB)
    limit = time.time() - (LOOKBACK_DAYS * 24 * 60 * 60)

    if not QUARANTINE_DIR.exists():
        raise FileNotFoundError(f"Quarantine directory not found: {QUARANTINE_DIR}")

    all_files = []
    for root, _, files in os.walk(QUARANTINE_DIR):
        for filename in files:
            if not filename.startswith(("spam-", "banned-", "virus-")):
                continue
            full_path = Path(root) / filename
            try:
                stat = full_path.stat()
            except OSError:
                continue
            if stat.st_mtime <= limit:
                continue
            rel_path = str(full_path.relative_to(QUARANTINE_DIR))
            signature = (stat.st_mtime_ns, stat.st_size)
            all_files.append(
                (full_path, rel_path, filename, stat.st_mtime, signature)
            )

    all_files.sort(key=lambda x: x[3], reverse=True)

    with _cache_lock:
        old_file_cache = dict(_file_cache)

    current_ids = set()
    next_file_cache = {}
    new_items = []
    parsed = 0
    reused = 0

    for full_path, rel_path, filename, mtime, signature in all_files:
        current_ids.add(rel_path)
        cached = old_file_cache.get(rel_path)
        if cached and cached.get("signature") == signature:
            item = dict(cached["item"])
            item["is_released"] = rel_path in released_ids
            item["is_manual_spam"] = rel_path in spam_ids
            item["learning"] = "spam" if rel_path in learn_spam_ids else ("ham" if rel_path in learn_ham_ids else "")
            reused += 1
        else:
            try:
                item = _parse_file(
                    full_path,
                    rel_path,
                    filename,
                    mtime,
                    released_ids,
                    spam_ids,
                )
                parsed += 1
            except Exception:
                continue
        next_file_cache[rel_path] = {
            "signature": signature,
            "item": dict(item),
        }
        new_items.append(item)

    with _cache_lock:
        _file_cache = next_file_cache
        cache.update(
            {
                "data": new_items,
                "last_updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": "",
                "scan_stats": {"parsed": parsed, "reused": reused},
            }
        )


def _worker():
    while True:
        try:
            refresh_cache()
        except Exception as exc:
            with _cache_lock:
                cache["error"] = str(exc)
        time.sleep(CACHE_REFRESH_INTERVAL)


def start_worker():
    global _worker_started
    if _worker_started:
        return
    _worker_started = True
    threading.Thread(
        target=_worker,
        daemon=True,
        name="amavis-quarantine-cache",
    ).start()


TEXT_FILTER_OPERATORS = {
    "equals",
    "not_equal",
    "begins_with",
    "ends_with",
    "contains",
    "does_not_contain",
}


def _text_filter_match(values, needle, operator):
    operator = str(operator or "contains").strip().lower()
    if operator not in TEXT_FILTER_OPERATORS:
        raise ValueError("Invalid text filter operator")

    needle = str(needle or "").strip().lower()
    haystacks = [str(value or "").lower() for value in values]

    if not needle:
        return True
    if operator == "equals":
        return any(value == needle for value in haystacks)
    if operator == "not_equal":
        return all(value != needle for value in haystacks)
    if operator == "begins_with":
        return any(value.startswith(needle) for value in haystacks)
    if operator == "ends_with":
        return any(value.endswith(needle) for value in haystacks)
    if operator == "does_not_contain":
        return all(needle not in value for value in haystacks)
    return any(needle in value for value in haystacks)


def query_items(q="", q_field="all", q_operator="contains", date="", category="all", page=1, page_size=None, admin_decision="all", decided_pdp_ids=None):
    q = (q or "").strip()
    q_field = (q_field or "all").strip().lower()
    if q_field not in {"all", "from", "to"}:
        raise ValueError("Invalid quarantine search field")
    q_operator = (q_operator or "contains").strip().lower()
    if q_operator not in TEXT_FILTER_OPERATORS:
        raise ValueError("Invalid text filter operator")
    date = (date or "").strip()
    category = (category or "all").strip()
    admin_decision = (admin_decision or "all").strip().lower()
    if admin_decision not in {"all", "required", "completed"}:
        raise ValueError("Invalid Admin Decision filter")
    decided_pdp_ids = {str(x or "").strip() for x in (decided_pdp_ids or set()) if str(x or "").strip()}

    with _cache_lock:
        source = list(cache["data"])
        last_updated = cache["last_updated"]
        error = cache["error"]
        scan_stats = dict(cache.get("scan_stats", {}))

    filtered = []
    for item in source:
        if q:
            if q_field == "from":
                search_values = (item["from"],)
            elif q_field == "to":
                search_values = (item["to"],)
            else:
                search_values = (
                    item["from"],
                    item["to"],
                    item["subject"],
                    item["pdp_id"],
                )
            if not _text_filter_match(search_values, q, q_operator):
                continue
        if date and item["date"] != date:
            continue
        if category.lower() != "all" and item["category"].lower() != category.lower():
            continue
        has_admin_decision = str(item.get("pdp_id") or "") in decided_pdp_ids
        if admin_decision == "required" and has_admin_decision:
            continue
        if admin_decision == "completed" and not has_admin_decision:
            continue
        row = dict(item)
        row["admin_decision_required"] = not has_admin_decision
        row["admin_decision_status"] = "REQUIRED" if not has_admin_decision else "COMPLETED"
        filtered.append(row)

    top_domains = Counter(
        item["from_domain"] for item in filtered if item["from_domain"]
    ).most_common(10)

    # Review Queue counters intentionally reflect all currently cached quarantine
    # items, independent of the Admin Decision filter currently selected.
    review_required = sum(1 for item in source if str(item.get("pdp_id") or "") not in decided_pdp_ids)
    review_completed = max(0, len(source) - review_required)

    total_items = len(filtered)
    effective_page_size = ITEMS_PER_PAGE if page_size in (None, "") else max(10, min(200, int(page_size)))
    total_pages = max(1, (total_items + effective_page_size - 1) // effective_page_size)
    page = min(max(1, int(page)), total_pages)
    start = (page - 1) * effective_page_size
    counts = Counter(item["category"] for item in filtered)

    page_items = [dict(item) for item in filtered[start:start + effective_page_size]]
    release_map = _release_status_map()
    for item in page_items:
        if item.get("is_released"):
            item["release_status"] = release_map.get(item.get("pdp_id"), {"status": "RELEASED_LEGACY", "queue_id": ""})

    return {
        "items": page_items,
        "page": page,
        "total_pages": total_pages,
        "total_items": total_items,
        "last_updated": last_updated,
        "error": error,
        "scan_stats": scan_stats,
        "top_domains": [
            {"domain": domain, "count": count}
            for domain, count in top_domains
        ],
        "counts": {
            "spam": counts.get("Spam", 0),
            "virus": counts.get("Virus", 0),
            "banned": counts.get("Banned", 0),
        },
        "review_queue": {
            "required": review_required,
            "completed": review_completed,
            "total": len(source),
            "filter": admin_decision,
        },
    }


def audit_tail(limit=10):
    if not AUDIT_LOG.exists():
        return []
    try:
        return AUDIT_LOG.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()[-max(1, int(limit)):]
    except OSError:
        return []


def audit_records(
    q="",
    action="all",
    date_from="",
    date_to="",
    page=1,
    page_size=50,
):
    q = (q or "").strip().lower()
    action = (action or "all").strip().upper()
    date_from = (date_from or "").strip()
    date_to = (date_to or "").strip()

    records = []
    if AUDIT_JSONL.exists():
        try:
            for line in AUDIT_JSONL.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ts = str(record.get("timestamp", ""))
                rec_action = str(record.get("action", "")).upper()

                if action != "ALL" and rec_action != action:
                    continue
                if date_from and ts[:10] < date_from:
                    continue
                if date_to and ts[:10] > date_to:
                    continue

                if q:
                    haystack = " ".join(
                        str(record.get(key, ""))
                        for key in (
                            "action",
                            "user",
                            "ip",
                            "pdp_id",
                            "from",
                            "to",
                            "subject",
                            "category",
                            "score",
                        )
                    ).lower()
                    if q not in haystack:
                        continue

                records.append(record)
        except OSError:
            records = []

    records.sort(
        key=lambda item: item.get("timestamp", ""),
        reverse=True,
    )

    page_size = min(max(10, int(page_size)), 500)
    total = len(records)
    total_pages = max(
        1,
        (total + page_size - 1) // page_size,
    )
    page = min(max(1, int(page)), total_pages)
    start = (page - 1) * page_size

    return {
        "rows": records[start:start + page_size],
        "total": total,
        "page": page,
        "total_pages": total_pages,
    }



def release(pdp_id: str, remote_addr: str, username: str = ""):
    with _action_lock:
        _safe_path(pdp_id)
        _assert_undecided(pdp_id)
        ensure_state_dir()

        release_cmd = Path(AMAVIS_RELEASE_CMD)
        if not release_cmd.is_file():
            raise RuntimeError(
                f"amavisd-release wrapper not found at {AMAVIS_RELEASE_CMD}"
            )

        env = os.environ.copy()
        env["AMAVIS_PDP_SERVER"] = AMAVIS_PDP_SERVER

        try:
            proc = subprocess.run(
                [AMAVIS_RELEASE_CMD, pdp_id],
                env=env,
                capture_output=True,
                text=True,
                timeout=AMAVIS_RELEASE_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"amavisd-release timed out after {AMAVIS_RELEASE_TIMEOUT} seconds"
            ) from exc

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0:
            raise RuntimeError(
                stderr or stdout or f"amavisd-release exited with code {proc.returncode}"
            )

        queue_id = _extract_release_queue_id("\n".join(x for x in (stdout, stderr) if x))
        release_status = "QUEUE_ACCEPTED" if queue_id else "RELEASED_UNVERIFIED"
        release_row = _append_release_status(pdp_id, queue_id, release_status, username, stdout or stderr)
        _mark_id(RELEASED_DB, pdp_id)
        write_audit("RELEASE", pdp_id, remote_addr, username, detail=(f"queue_id={queue_id or 'NOT_CAPTURED'} status={release_status}; " + (stdout or stderr))[:1000])

        with _cache_lock:
            for item in cache["data"]:
                if item.get("pdp_id") == pdp_id:
                    item["is_released"] = True
                    item["release_status"] = release_row
                    break

        return {"ok": True, "message": stdout or f"Released {pdp_id}", "queue_id": queue_id, "release_status": release_status}


def mark_spam(pdp_id: str, remote_addr: str, username: str = ""):
    with _action_lock:
        _safe_path(pdp_id)
        _assert_undecided(pdp_id)
        if SA_LEARN_ON_MARK_SPAM:
            _sa_learn(pdp_id, "spam", remote_addr, username)
        _mark_id(SPAM_DB, pdp_id)
        write_audit("SPAM_FLG", pdp_id, remote_addr, username, detail="Spam classification finalized" + (" after sa-learn" if SA_LEARN_ON_MARK_SPAM else ""))

        with _cache_lock:
            for item in cache["data"]:
                if item.get("pdp_id") == pdp_id:
                    item["is_manual_spam"] = True
                    break

        return {"ok": True, "message": f"Marked spam {pdp_id}"}

