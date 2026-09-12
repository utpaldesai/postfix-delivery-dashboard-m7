import os
import tempfile
import secrets
import socket
import threading
import time
import logging
import json
import ipaddress
import hashlib
import re
from urllib.parse import urlparse
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, RedirectResponse, FileResponse

class _SuppressHealthLiveAccess(logging.Filter):
    """Keep Docker liveness checks active without flooding access logs."""
    def filter(self, record):
        try:
            return "/health/live" not in record.getMessage()
        except Exception:
            return True


logging.getLogger("uvicorn.access").addFilter(_SuppressHealthLiveAccess())

from .db import (
    cleanup,
    grouped,
    init,
    report,
    stats,
    upsert_delivery,
    upsert_metadata,
    purge_internal_reinjection_rows,
    direction_summary,
    released_quarantine_count,
    daily_domain_summary,
    bounced_domain_details,
    audit_records as db_audit_records,
    audit_import_jsonl,
    db_ready,
    queue_timeline,
    ensure_bootstrap_user,
    authenticate_dashboard_user,
    dashboard_user_access,
    list_dashboard_users,
    create_dashboard_user,
    update_dashboard_user,
    delete_dashboard_user,
    ACL_LEVELS,
    TEXT_FILTER_OPERATORS,
    create_config_snapshot,
    list_config_snapshots,
    store_amavis_evidence,
    find_amavis_evidence,
    get_amavis_ingest_state,
    set_amavis_ingest_state,
    store_amavis_events_batch,
    find_continuous_amavis_evidence,
    find_current_amavis_trace,
    find_current_amavis_attachment_history,
    backfill_amavis_attachment_history,
    ensure_r1129_indexes,
    fraud_repo_status,
    ai_ti_status,
    record_ai_ground_truth_calibration,
    ai_ground_truth_current,
    ai_ground_truth_current_pdp_ids,
    get_postfix_ingest_state,
    set_postfix_ingest_state,
    store_postfix_raw_events_batch,
    postfix_delivery_projection_has_rows,
)
from .parser import ALLOWED, parse_line
from .spam_lists import (
    SPAM_PREFS,
    list_entries as spam_list_entries,
    create_entry as spam_create_entry,
    update_entry as spam_update_entry,
    delete_entry as spam_delete_entry,
    bulk_delete_entries as spam_bulk_delete_entries,
    preview_import as spam_preview_import,
    import_entries as spam_import_entries,
    export_entries as spam_export_entries,
    db_ready as spam_pref_db_ready,
    conflict_summary as spam_conflict_summary,
)
from .quarantine import (
    audit_tail as quarantine_audit_tail,
    write_audit as quarantine_write_audit,
    audit_records as quarantine_audit_records_read,
    mark_spam as quarantine_mark_spam,
    learn_spam as quarantine_learn_spam,
    learn_ham as quarantine_learn_ham,
    correct_learning as quarantine_correct_learning,
    sa_learn_ready as quarantine_sa_learn_ready,
    query_items as quarantine_query_items,
    refresh_cache as quarantine_refresh_cache,
    release as quarantine_release,
    start_worker as quarantine_start_worker,
    ensure_state_dir as quarantine_ensure_state_dir,
    item_for as quarantine_item_for,
    _safe_path as quarantine_source_path,
    _get_flagged_ids as quarantine_flagged_ids,
    LEARN_SPAM_DB as quarantine_learn_spam_db,
    LEARN_HAM_DB as quarantine_learn_ham_db,
    AUDIT_JSONL as quarantine_audit_jsonl,
    QUARANTINE_DIR as quarantine_dir_path,
    STATE_DIR as quarantine_state_dir,
    AMAVIS_PDP_SERVER as amavis_pdp_server,
)
from .quarantine_intelligence import get_intelligence as quarantine_get_intelligence
from .geoip_intelligence import enrich_header as geoip_enrich_header, status as geoip_status
from .email_analysis import analyze_raw as analyze_email_raw, analyze_upload as analyze_email_upload, normalize_upload as normalize_email_upload
from .amavis_dry_run import analyze_bytes as amavis_dry_run_bytes, status as amavis_dry_run_status
from .fraud_intelligence import analyze_file as fraud_analyze_file, analyze_bytes as fraud_analyze_bytes
from .ai_threat_intelligence import analyze_file as ti_analyze_file, analyze_bytes as ti_analyze_bytes
from .monitor import (dovecot_pop3_logins, roundcube_logins, sync_login_events, login_summary, login_user_history, monitor_db_stats)
from .ai_trainer import (
    status as ai_trainer_status,
    train_candidate as ai_train_candidate,
    promote_candidate as ai_promote_candidate,
    predict_file as ai_predict_file,
    predict_shadow_candidate_file as ai_predict_shadow_candidate_file,
    record_human_label as ai_record_human_label,
)

from .session_auth import (
    COOKIE_NAME as SESSION_COOKIE_NAME,
    COOKIE_SECURE as SESSION_COOKIE_SECURE,
    IDLE_TIMEOUT_MINUTES as SESSION_IDLE_TIMEOUT_MINUTES,
    IDLE_TIMEOUT_SECONDS as SESSION_IDLE_TIMEOUT_SECONDS,
    ABSOLUTE_TIMEOUT_HOURS as SESSION_ABSOLUTE_TIMEOUT_HOURS,
    ABSOLUTE_TIMEOUT_SECONDS as SESSION_ABSOLUTE_TIMEOUT_SECONDS,
    store as session_store,
)

LOG = Path(os.getenv("LOG_FILE", "/host-logs/mail.log"))
AMAVIS_LOG = Path(os.getenv("AMAVIS_LOG", "/host-amavis/logs/amavis.log"))
AMAVIS_INGEST_SOURCE_KEY = os.getenv("AMAVIS_INGEST_SOURCE_KEY", "production-amavis-log").strip() or "production-amavis-log"
AMAVIS_INGEST_BATCH_LINES = max(25, int(os.getenv("AMAVIS_INGEST_BATCH_LINES", "250")))
AMAVIS_INGEST_POLL_SECONDS = max(0.25, float(os.getenv("AMAVIS_INGEST_POLL_SECONDS", "1")))
POSTFIX_INGEST_SOURCE_KEY = os.getenv("POSTFIX_INGEST_SOURCE_KEY", "production-postfix-log").strip() or "production-postfix-log"
POSTFIX_INGEST_BATCH_LINES = max(25, int(os.getenv("POSTFIX_INGEST_BATCH_LINES", "250")))
POSTFIX_INGEST_POLL_SECONDS = max(0.25, float(os.getenv("POSTFIX_INGEST_POLL_SECONDS", "0.5")))
IMPORT = int(os.getenv("INITIAL_IMPORT_LINES", "50000"))
INGEST_CHECKPOINT_FILE = Path(
    os.getenv(
        "INGEST_CHECKPOINT_FILE",
        "/data/reader/mail-log-checkpoint.json",
    )
)
CHECKPOINT_FLUSH_SECONDS = max(
    1.0,
    float(os.getenv("INGEST_CHECKPOINT_FLUSH_SECONDS", "2")),
)
CHECKPOINT_FLUSH_LINES = max(
    1,
    int(os.getenv("INGEST_CHECKPOINT_FLUSH_LINES", "100")),
)
RETENTION = int(os.getenv("RETENTION_DAYS", "90"))
MONITOR_SYNC_SECONDS = max(15, int(os.getenv("MONITOR_SYNC_SECONDS", "30")))
USERNAME = os.getenv("WEB_USERNAME", "admin")
PASSWORD = os.getenv("WEB_PASSWORD", "")
MAIL_SIZE_API_URL = os.getenv(
    "MAIL_SIZE_API_URL",
    "http://127.0.0.1/mail-size-api.php",
).strip()
MAIL_SIZE_API_KEY = os.getenv("MAIL_SIZE_API_KEY", "").strip()
MAIL_SIZE_API_TIMEOUT = max(
    2.0,
    float(os.getenv("MAIL_SIZE_API_TIMEOUT", "10")),
)
HOME_DOMAINS = [d.strip() for d in os.getenv("HOME_DOMAINS", "").split(",") if d.strip()]
TRUSTED_PROXY_IPS = {ip.strip() for ip in os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",") if ip.strip()}
if not HOME_DOMAINS:
    raise RuntimeError("HOME_DOMAINS is required; no production fallback is permitted")

LOGIN_RATE_LIMIT_ATTEMPTS = max(1, int(os.getenv("LOGIN_RATE_LIMIT_ATTEMPTS", "5")))
LOGIN_RATE_LIMIT_WINDOW_SECONDS = max(10, int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "60")))
LOGIN_RATE_LIMIT_LOCKOUT_SECONDS = max(30, int(os.getenv("LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", "300")))

logger = logging.getLogger("postfix-dashboard.security")
_login_attempts = {}
_login_attempts_lock = threading.RLock()

app = FastAPI(docs_url=None, redoc_url=None)

reader_state = {
    "running": False,
    "error": "",
    "updated": 0,
    "metadata_updated": 0,
    "discarded": 0,
    "purged_internal_reinjections": 0,
    "checkpoint_mode": "uninitialized",
    "checkpoint_offset": 0,
    "checkpoint_inode": 0,
    "checkpoint_device": 0,
    "checkpoint_updated_at": "",
}


amavis_ingest_state = {
    "running": False,
    "error": "",
    "source_readable": False,
    "checkpoint_mode": "uninitialized",
    "checkpoint_offset": 0,
    "source_size": 0,
    "events_stored": 0,
    "lines_processed": 0,
    "updated_at": "",
}

def _client_ip(request: Request) -> str:
    """Resolve the audit client safely. Forwarded headers are trusted only from configured proxies."""
    peer = request.client.host if request.client else "unknown"
    if peer not in TRUSTED_PROXY_IPS:
        return peer
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    real_ip = (request.headers.get("x-real-ip") or "").strip()
    for candidate in (forwarded, real_ip):
        if not candidate:
            continue
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return peer


def _login_rate_status(client_ip: str):
    now = time.time()
    with _login_attempts_lock:
        state = _login_attempts.get(client_ip)
        if not state:
            return False, 0
        locked_until = float(state.get("locked_until", 0))
        if locked_until > now:
            return True, max(1, int(locked_until - now))
        failures = [
            ts for ts in state.get("failures", [])
            if now - ts <= LOGIN_RATE_LIMIT_WINDOW_SECONDS
        ]
        if failures:
            state["failures"] = failures
            state["locked_until"] = 0
        else:
            _login_attempts.pop(client_ip, None)
        return False, 0


def _record_login_failure(client_ip: str):
    now = time.time()
    with _login_attempts_lock:
        state = _login_attempts.setdefault(
            client_ip, {"failures": [], "locked_until": 0}
        )
        failures = [
            ts for ts in state.get("failures", [])
            if now - ts <= LOGIN_RATE_LIMIT_WINDOW_SECONDS
        ]
        failures.append(now)
        state["failures"] = failures
        if len(failures) >= LOGIN_RATE_LIMIT_ATTEMPTS:
            state["locked_until"] = now + LOGIN_RATE_LIMIT_LOCKOUT_SECONDS


def _clear_login_failures(client_ip: str):
    with _login_attempts_lock:
        _login_attempts.pop(client_ip, None)


def _same_origin(request: Request) -> bool:
    expected_host = request.headers.get("host", "").strip().lower()
    if not expected_host:
        return False

    for header_name in ("origin", "referer"):
        value = request.headers.get(header_name, "").strip()
        if not value:
            continue
        try:
            parsed = urlparse(value)
            if parsed.netloc.lower() == expected_host:
                return True
        except Exception:
            return False
    return False


@app.middleware("http")
async def csrf_origin_guard(request: Request, call_next):
    if (
        request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        and request.url.path != "/api/login"
        and request.cookies.get(SESSION_COOKIE_NAME)
    ):
        dashboard_header = request.headers.get("x-postfix-dashboard", "")
        if dashboard_header != "1" and not _same_origin(request):
            return JSONResponse(
                {"detail": "Invalid request origin"},
                status_code=403,
            )
    return await call_next(request)


def require_session(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    session = session_store.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired or login required")
    access = dashboard_user_access(session.username)
    if not access:
        session_store.destroy(token)
        raise HTTPException(status_code=401, detail="User disabled or removed")
    return session.username


def require_permission(area: str, minimum: str = "view"):
    required_rank = ACL_LEVELS[minimum]

    def dependency(request: Request):
        username = require_session(request)
        access = dashboard_user_access(username)
        if not access:
            raise HTTPException(status_code=401, detail="User disabled or removed")
        if access.get("is_admin"):
            return username
        level = access.get("permissions", {}).get(area, "none")
        if ACL_LEVELS.get(level, 0) < required_rank:
            raise HTTPException(status_code=403, detail="Access denied")
        return username

    return dependency


def require_acl_admin(request: Request):
    username = require_session(request)
    access = dashboard_user_access(username)
    if not access or not access.get("is_admin"):
        raise HTTPException(status_code=403, detail="Administrator access required")
    return username


def store(line: str) -> None:
    event = parse_line(line)

    if event is None:
        reader_state["discarded"] += 1
        return

    if event["kind"] == "metadata":
        upsert_metadata(event)
        reader_state["metadata_updated"] += 1
        return

    if upsert_delivery(event):
        reader_state["updated"] += 1

def _load_ingest_checkpoint():
    try:
        raw = INGEST_CHECKPOINT_FILE.read_text(
            encoding="utf-8",
            errors="strict",
        )
        data = json.loads(raw)
        return {
            "device": int(data.get("device", 0)),
            "inode": int(data.get("inode", 0)),
            "offset": max(0, int(data.get("offset", 0))),
            "updated_at": str(data.get("updated_at", "")),
        }
    except FileNotFoundError:
        return None
    except Exception as exc:
        logger.warning("Unable to read ingestion checkpoint: %s", exc)
        return None


def _write_ingest_checkpoint(stat_result, offset):
    INGEST_CHECKPOINT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    payload = {
        "version": 1,
        "log_path": str(LOG),
        "device": int(stat_result.st_dev),
        "inode": int(stat_result.st_ino),
        "offset": max(0, int(offset)),
        "updated_at": time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(),
        ),
    }
    tmp = INGEST_CHECKPOINT_FILE.with_suffix(
        INGEST_CHECKPOINT_FILE.suffix + ".tmp"
    )
    tmp.write_text(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    os.replace(tmp, INGEST_CHECKPOINT_FILE)

    reader_state["checkpoint_offset"] = payload["offset"]
    reader_state["checkpoint_inode"] = payload["inode"]
    reader_state["checkpoint_device"] = payload["device"]
    reader_state["checkpoint_updated_at"] = payload["updated_at"]


def _bootstrap_without_checkpoint(handle, stat_result):
    """
    Compatibility bootstrap for an installation that predates durable
    checkpoints. Re-read the configured historical tail, then checkpoint EOF.

    Duplicate delivery events are safe because storage is idempotent/upserted.
    """
    lines = handle.readlines()
    for line in lines[-IMPORT:]:
        store(line)
    offset = handle.tell()
    _write_ingest_checkpoint(stat_result, offset)
    reader_state["checkpoint_mode"] = "bootstrap_tail"
    return offset


def _position_from_checkpoint(handle, stat_result, checkpoint):
    if checkpoint is None:
        return _bootstrap_without_checkpoint(handle, stat_result)

    same_file = (
        checkpoint["device"] == int(stat_result.st_dev)
        and checkpoint["inode"] == int(stat_result.st_ino)
    )

    if same_file and checkpoint["offset"] <= int(stat_result.st_size):
        handle.seek(checkpoint["offset"])
        reader_state["checkpoint_mode"] = "resumed"
        reader_state["checkpoint_offset"] = checkpoint["offset"]
        reader_state["checkpoint_inode"] = checkpoint["inode"]
        reader_state["checkpoint_device"] = checkpoint["device"]
        reader_state["checkpoint_updated_at"] = checkpoint["updated_at"]
        return checkpoint["offset"]

    # File rotated/replaced, or the active file was truncated. Start at byte 0
    # so no new active-file records are skipped.
    handle.seek(0)
    reader_state["checkpoint_mode"] = (
        "rotated"
        if not same_file
        else "truncated"
    )
    _write_ingest_checkpoint(stat_result, 0)
    return 0


def _tail_postfix_lines(path: Path, limit: int, chunk_size: int = 65536):
    """Read only the tail needed for first bootstrap and preserve byte offsets.

    Unlike the previous implementation this does not scan the complete active
    Postfix log or build an all-lines list in memory.  It seeks backwards from
    EOF in bounded chunks until enough newline boundaries are available.
    """
    limit = max(0, int(limit))
    if limit == 0:
        return [], int(path.stat().st_size)

    file_size = int(path.stat().st_size)
    if file_size <= 0:
        return [], 0

    with path.open('rb') as raw:
        pos = file_size
        data = b''
        # Need one extra newline to know the first retained line starts cleanly.
        while pos > 0 and data.count(b'\n') <= limit:
            take = min(int(chunk_size), pos)
            pos -= take
            raw.seek(pos)
            data = raw.read(take) + data

    lines = data.splitlines(keepends=True)
    entries = []
    absolute = pos
    for idx, line in enumerate(lines):
        start = absolute
        absolute += len(line)
        # If we stopped before BOF, the first element can be a partial line.
        if pos > 0 and idx == 0:
            continue
        entries.append((start, line.decode('utf-8', errors='replace')))

    return entries[-limit:], file_size


def follow() -> None:
    """Continuously ingest the read-only Postfix log into MariaDB.

    MariaDB is the primary durable checkpoint and immutable event repository.
    Delivery projection updates remain idempotent, so a failed batch is safely
    replayed because the checkpoint advances only after the whole batch succeeds.
    """
    reader_state["running"] = True
    handle = None
    active_device = None
    active_inode = None
    batch = []
    last_cleanup = 0.0

    while True:
        try:
            if not LOG.exists():
                reader_state["error"] = f"Log file not found: {LOG}"
                time.sleep(3)
                continue

            st = LOG.stat()
            dev, ino, size = int(st.st_dev), int(st.st_ino), int(st.st_size)
            dbs = get_postfix_ingest_state(POSTFIX_INGEST_SOURCE_KEY) or {}

            if handle is None or active_device != dev or active_inode != ino:
                if handle:
                    handle.close()
                handle = LOG.open("r", encoding="utf-8", errors="replace")
                active_device, active_inode = dev, ino
                saved_dev = int(dbs.get("source_device") or 0)
                saved_ino = int(dbs.get("source_inode") or 0)
                saved_off = int(dbs.get("source_offset") or 0)
                same_file = saved_dev == dev and saved_ino == ino

                if same_file and saved_off <= size:
                    handle.seek(saved_off)
                    reader_state["checkpoint_mode"] = "db_resumed"
                elif dbs:
                    handle.seek(0)
                    reader_state["checkpoint_mode"] = "db_rotated" if not same_file else "db_truncated"
                else:
                    # R1.1.41 in-place upgrade fast adoption: if the historical
                    # delivery projection is already populated, do NOT replay tens
                    # of thousands of old log lines through one-row transactions.
                    # Adopt EOF as the durable checkpoint and ingest only new mail.
                    if postfix_delivery_projection_has_rows():
                        handle.seek(0, os.SEEK_END)
                        eof = handle.tell()
                        set_postfix_ingest_state(POSTFIX_INGEST_SOURCE_KEY,str(LOG),dev,ino,eof,size,'RUNNING','')
                        reader_state["checkpoint_mode"] = "db_adopt_existing_projection"
                        reader_state["checkpoint_offset"] = eof
                        batch=[]
                    else:
                        # Fresh installation: seek backwards and read only the
                        # configured bootstrap tail; never scan the entire log.
                        selected, eof = _tail_postfix_lines(LOG, IMPORT)
                        if selected:
                            store_postfix_raw_events_batch(POSTFIX_INGEST_SOURCE_KEY,str(LOG),dev,ino,selected)
                            for _,line in selected:
                                store(line)
                        handle.seek(0, os.SEEK_END)
                        eof = handle.tell()
                        set_postfix_ingest_state(POSTFIX_INGEST_SOURCE_KEY,str(LOG),dev,ino,eof,size,'RUNNING','')
                        reader_state["checkpoint_mode"] = "db_bootstrap_tail_bounded"
                        reader_state["checkpoint_offset"] = eof
                        batch=[]

                reader_state["checkpoint_device"] = dev
                reader_state["checkpoint_inode"] = ino
                reader_state["checkpoint_offset"] = handle.tell()
                reader_state["checkpoint_updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                reader_state["error"] = ""

            pos = handle.tell()
            line = handle.readline()
            if line:
                batch.append((pos,line))

            if batch and (len(batch) >= POSTFIX_INGEST_BATCH_LINES or not line):
                fst=os.fstat(handle.fileno())
                # Immutable evidence first; then update the fast final-state projection.
                store_postfix_raw_events_batch(POSTFIX_INGEST_SOURCE_KEY,str(LOG),int(fst.st_dev),int(fst.st_ino),batch)
                for _,raw in batch:
                    store(raw)
                committed_offset=handle.tell()
                set_postfix_ingest_state(POSTFIX_INGEST_SOURCE_KEY,str(LOG),int(fst.st_dev),int(fst.st_ino),committed_offset,int(fst.st_size),'RUNNING','')
                reader_state["checkpoint_offset"] = committed_offset
                reader_state["checkpoint_updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                batch=[]

            if not line:
                time.sleep(POSTFIX_INGEST_POLL_SECONDS)
                current=LOG.stat()
                if (int(current.st_dev) != active_device or int(current.st_ino) != active_inode or int(current.st_size) < handle.tell()):
                    handle.close(); handle=None; active_device=None; active_inode=None

            if time.time() - last_cleanup > 3600:
                cleanup(RETENTION)
                last_cleanup = time.time()

        except Exception as exc:
            reader_state["error"] = str(exc)
            # Never advance the MariaDB checkpoint from the exception path.
            try:
                dbs=get_postfix_ingest_state(POSTFIX_INGEST_SOURCE_KEY) or {}
                set_postfix_ingest_state(POSTFIX_INGEST_SOURCE_KEY,str(LOG),int(dbs.get('source_device') or 0),int(dbs.get('source_inode') or 0),int(dbs.get('source_offset') or 0),int(dbs.get('source_size') or 0),'ERROR',str(exc))
            except Exception:
                pass
            if handle:
                try: handle.close()
                except Exception: pass
            handle=None; active_device=None; active_inode=None; batch=[]
            time.sleep(3)


def _amavis_event_time(line):
    text=str(line or '')
    # ISO/syslog RFC3339 style first.
    m=re.match(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})', text)
    if m:
        return f"{m.group(1)} {m.group(2)}", m.group(0)
    m=re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', text)
    if not m:
        return None, ''
    try:
        now=time.localtime()
        months={name:i for i,name in enumerate(('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'),1)}
        month=months[m.group(1)]; day=int(m.group(2)); year=now.tm_year
        # Syslog has no year. Around New Year, a future-looking month is from the previous year.
        if month > now.tm_mon + 1:
            year -= 1
        return f"{year:04d}-{month:02d}-{day:02d} {m.group(3)}", m.group(0)
    except Exception:
        return None, m.group(0)

def _parse_amavis_event(line, source_stat, source_offset):
    raw=str(line or '').rstrip('\n')
    if not raw:
        return None
    # Retain every Amavis log record so MariaDB is the historical evidence repository,
    # not an on-demand cache. Parsed fields are best-effort indexes over the immutable raw line.
    q=re.search(r'Queue-ID:\s*([A-Za-z0-9]+)', raw, re.I)
    rq=re.search(r'queued as\s+([A-Za-z0-9]+)', raw, re.I)
    mid=re.search(r'Message-ID:\s*<([^>]+)>', raw, re.I)
    mail=re.search(r'\bmail_id:\s*([A-Za-z0-9_-]+)', raw, re.I)
    session=re.search(r'\((\d+-\d+(?:-\d+)?)\)', raw)
    score=re.search(r'(?:Hits:|score=)\s*([-+0-9.]+)', raw, re.I)
    quar=re.search(r'(?:quarantine:|mbx=)\s*([^, ]+)', raw, re.I)
    frm=re.search(r'(?:\bfrom|<)\s*<([^>]*)>', raw, re.I)
    if not frm:
        frm=re.search(r'\[\d+(?:\.\d+){3}\].*?<([^>]+)>\s*->', raw)
    recipients=re.findall(r'->\s*<([^>]*)>', raw)
    if not recipients:
        recipients=re.findall(r'\bto\s*<([^>]*)>', raw, re.I)
    upper=raw.upper(); verdict=''
    for candidate in ('VIRUS','BANNED','SPAM','CLEAN','PASSED','RELEASED','BLOCKED','DISCARDEDINBOUND','QUARANTINED'):
        if candidate in upper:
            verdict=candidate; break
    virus=''
    vm=re.search(r'(?:INFECTED|virus(?: name)?)[=: ]+([^,;]+)', raw, re.I)
    if vm: virus=vm.group(1).strip()[:512]
    banned=''
    bm=re.search(r'(?:BANNED|banned name)[=: ]+([^,;]+)', raw, re.I)
    if bm: banned=bm.group(1).strip()[:512]
    attachment=''
    # Preserve filenames/archive-member evidence Amavis exposes in the log; no
    # attachment is opened and no archive is extracted by the dashboard.
    names=[]
    for pattern in (
        r"(?:name|filename)=['\"]?([^,'\";]+)",
        r"(?:archive member|member name|part name)[:=]\s*['\"]?([^,'\";]+)",
        r"(?:BANNED name|banned name)[:=]\s*['\"]?([^,'\";]+)",
    ):
        names.extend(re.findall(pattern, raw, re.I))
    if names: attachment=' | '.join(dict.fromkeys(x.strip() for x in names if x.strip()))[:4000]
    event_time,timestamp_text=_amavis_event_time(raw)
    coord=f"{int(source_stat.st_dev)}:{int(source_stat.st_ino)}:{int(source_offset)}:{raw}"
    return {
        'source_path':str(AMAVIS_LOG),'source_device':int(source_stat.st_dev),'source_inode':int(source_stat.st_ino),
        'source_offset':int(source_offset),'event_hash':hashlib.sha256(coord.encode('utf-8','replace')).hexdigest(),
        'event_time':event_time,'timestamp_text':timestamp_text,'session_id':session.group(1) if session else '',
        'queue_id':q.group(1) if q else '','release_queue_id':rq.group(1) if rq else '',
        'message_id':mid.group(1) if mid else '','mail_id':mail.group(1) if mail else '',
        'sender':frm.group(1) if frm else '','recipient':','.join(dict.fromkeys(recipients)),
        'verdict':verdict,'spam_score':score.group(1) if score else '',
        'quarantine_file':quar.group(1) if quar else '','virus_name':virus,'banned_name':banned,
        'attachment_evidence':attachment,'raw_log':raw,
    }

def amavis_evidence_follow():
    """Continuously ingest the read-only Amavis log into MariaDB with DB-backed checkpoints."""
    amavis_ingest_state['running']=True
    handle=None; active_device=None; active_inode=None
    batch=[]; processed_since_checkpoint=0
    while True:
        try:
            if not AMAVIS_LOG.is_file():
                amavis_ingest_state.update(error=f'Log file not found: {AMAVIS_LOG}',source_readable=False)
                time.sleep(3); continue
            if not os.access(AMAVIS_LOG, os.R_OK):
                amavis_ingest_state.update(error=f'Log file not readable: {AMAVIS_LOG}',source_readable=False)
                time.sleep(3); continue
            amavis_ingest_state['source_readable']=True
            st=AMAVIS_LOG.stat(); dev=int(st.st_dev); ino=int(st.st_ino)
            if handle is None or dev != active_device or ino != active_inode:
                if handle:
                    try: handle.close()
                    except Exception: pass
                handle=AMAVIS_LOG.open('r',encoding='utf-8',errors='replace')
                dbs=get_amavis_ingest_state(AMAVIS_INGEST_SOURCE_KEY)
                if dbs and int(dbs.get('source_device') or 0)==dev and int(dbs.get('source_inode') or 0)==ino and int(dbs.get('source_offset') or 0)<=int(st.st_size):
                    offset=int(dbs.get('source_offset') or 0); handle.seek(offset); mode='resumed'
                else:
                    # First deployment imports the complete currently retained active log.
                    # A rotated/truncated replacement begins at byte 0.
                    offset=0; handle.seek(0); mode='initial_full_import' if not dbs else ('rotated' if dbs and int(dbs.get('source_inode') or 0)!=ino else 'truncated')
                active_device=dev; active_inode=ino; batch=[]; processed_since_checkpoint=0
                amavis_ingest_state.update(checkpoint_mode=mode,checkpoint_offset=offset,source_size=int(st.st_size),error='')
                set_amavis_ingest_state(AMAVIS_INGEST_SOURCE_KEY,str(AMAVIS_LOG),dev,ino,offset,int(st.st_size),'RUNNING','')
            line_offset=handle.tell(); line=handle.readline()
            if line:
                ev=_parse_amavis_event(line, os.fstat(handle.fileno()), line_offset)
                if ev: batch.append(ev)
                processed_since_checkpoint += 1
                amavis_ingest_state['lines_processed'] += 1
                if len(batch)>=AMAVIS_INGEST_BATCH_LINES or processed_since_checkpoint>=AMAVIS_INGEST_BATCH_LINES:
                    inserted=store_amavis_events_batch(batch) if batch else 0
                    pos=handle.tell(); fst=os.fstat(handle.fileno())
                    set_amavis_ingest_state(AMAVIS_INGEST_SOURCE_KEY,str(AMAVIS_LOG),int(fst.st_dev),int(fst.st_ino),pos,int(fst.st_size),'RUNNING','')
                    amavis_ingest_state['events_stored'] += inserted
                    amavis_ingest_state.update(checkpoint_offset=pos,source_size=int(fst.st_size),updated_at=time.strftime('%Y-%m-%dT%H:%M:%S'))
                    batch=[]; processed_since_checkpoint=0
            else:
                if batch or processed_since_checkpoint:
                    inserted=store_amavis_events_batch(batch) if batch else 0
                    pos=handle.tell(); fst=os.fstat(handle.fileno())
                    set_amavis_ingest_state(AMAVIS_INGEST_SOURCE_KEY,str(AMAVIS_LOG),int(fst.st_dev),int(fst.st_ino),pos,int(fst.st_size),'IDLE','')
                    amavis_ingest_state['events_stored'] += inserted
                    amavis_ingest_state.update(checkpoint_offset=pos,source_size=int(fst.st_size),updated_at=time.strftime('%Y-%m-%dT%H:%M:%S'))
                    batch=[]; processed_since_checkpoint=0
                time.sleep(AMAVIS_INGEST_POLL_SECONDS)
                current=AMAVIS_LOG.stat()
                if int(current.st_dev)!=active_device or int(current.st_ino)!=active_inode or int(current.st_size)<handle.tell():
                    handle.close(); handle=None; active_device=None; active_inode=None
        except Exception as exc:
            amavis_ingest_state['error']=str(exc)
            try:
                if handle: handle.close()
            except Exception: pass
            handle=None; active_device=None; active_inode=None; batch=[]; processed_since_checkpoint=0
            # Do not advance the MariaDB checkpoint after a failed batch.
            try:
                dbs=get_amavis_ingest_state(AMAVIS_INGEST_SOURCE_KEY) or {}
                set_amavis_ingest_state(AMAVIS_INGEST_SOURCE_KEY,str(AMAVIS_LOG),int(dbs.get('source_device') or 0),int(dbs.get('source_inode') or 0),int(dbs.get('source_offset') or 0),int(dbs.get('source_size') or 0),'ERROR',str(exc))
            except Exception:
                pass
            time.sleep(3)

def truncate(value, width):
    text = str(value or "-")
    return text if len(text) <= width else text[:width - 3] + "..."

def build_text(rows):
    separator = "=" * 198
    divider = "-" * 198

    output = [
        separator,
        (
            f"{'TIMESTAMP':<23} "
            f"{'QUEUE ID':<17} "
            f"{'SIZE (MB)':<12} "
            f"{'STATUS':<13} "
            f"{'SENDER':<42} "
            f"{'RECIPIENT':<40} "
            f"DELIVERY TARGET / STATUS DETAIL"
        ),
        divider,
    ]

    for row in rows:
        size_mb = (
            "-"
            if row["message_size_bytes"] is None
            else f"{row['message_size_bytes'] / 1048576:.2f}"
        )

        output.append(
            f"{truncate(row['timestamp'], 23):<23} "
            f"{truncate(row['queue_id'], 17):<17} "
            f"{size_mb:<12} "
            f"{row['final_status']:<13} "
            f"{truncate(row['sender'], 42):<42} "
            f"{truncate(row['recipient'], 40):<40} "
            f"{row['delivery_target'] or '-'} / "
            f"{row['status_detail'] or '-'}"
        )

    output.append(separator)
    return "\n".join(output)

def monitor_follow():
    while True:
        try:
            result = sync_login_events()
            reader_state["monitor_ingest_error"] = ""
            reader_state["monitor_ingest_last"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            reader_state["monitor_last_batch_inserted"] = int(result.get("inserted", 0))
            reader_state["monitor_sources"] = result.get("sources", {})
            reader_state["monitor_ingest_inserted"] = int(reader_state.get("monitor_ingest_inserted", 0)) + int(result.get("inserted", 0))
        except Exception as exc:
            reader_state["monitor_ingest_error"] = str(exc)
        time.sleep(MONITOR_SYNC_SECONDS)


@app.on_event("startup")
def start():
    init()
    # R1.1.29: additive/idempotent secondary-index tuning only.
    try:
        reader_state["r1129_indexes_applied"] = ensure_r1129_indexes()
        reader_state["r1129_index_error"] = ""
    except Exception as exc:
        reader_state["r1129_indexes_applied"] = []
        reader_state["r1129_index_error"] = str(exc)[:500]
    ensure_bootstrap_user(USERNAME, PASSWORD)
    reader_state["purged_internal_reinjections"] = (
        purge_internal_reinjection_rows()
    )
    threading.Thread(target=follow, daemon=True).start()
    # R1.1.27: continuously retain the read-only Amavis log in MariaDB.
    threading.Thread(target=amavis_evidence_follow, daemon=True).start()
    # R1.1.31: forward-only historical attachment-content backfill.  Run in the
    # background so dashboard startup is never held up by retained Amavis history.
    threading.Thread(target=lambda: backfill_amavis_attachment_history(5000), daemon=True).start()
    quarantine_ensure_state_dir()
    quarantine_start_worker()
    # Forward-only Monitor ingestion: source logs remain read-only; only the new dashboard table is populated.
    try:
        monitor_sync = sync_login_events()
        reader_state["monitor_last_batch_inserted"] = int(monitor_sync.get("inserted", 0))
        reader_state["monitor_sources"] = monitor_sync.get("sources", {})
        reader_state["monitor_ingest_last"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception as exc:
        reader_state["monitor_ingest_error"] = str(exc)
    threading.Thread(target=monitor_follow, daemon=True).start()
    try:
        audit_import_jsonl(quarantine_audit_jsonl)
    except Exception as exc:
        reader_state["audit_migration_error"] = str(exc)

@app.get("/health/live")
def live():
    return {
        "status": "ok",
        "service": "postfix-final-dashboard",
    }

@app.get("/health")
def health(_: str = Depends(require_permission("system", "view"))):
    current_stats = stats()

    return {
        "status": (
            "ok"
            if not reader_state["error"]
            else "degraded"
        ),
        "database": "connected",
        "reader_running": reader_state["running"],
        "reader_error": reader_state["error"],
        "allowed_statuses": sorted(ALLOWED),
        "ingestion": {
            "delivery_rows_updated": reader_state["updated"],
            "queue_metadata_updated": (
                reader_state["metadata_updated"]
            ),
            "discarded_intermediate_events": (
                reader_state["discarded"]
            ),
            "purged_internal_reinjections": (
                reader_state["purged_internal_reinjections"]
            ),
            "checkpoint": {
                "mode": reader_state["checkpoint_mode"],
                "offset": reader_state["checkpoint_offset"],
                "inode": reader_state["checkpoint_inode"],
                "device": reader_state["checkpoint_device"],
                "updated_at": reader_state["checkpoint_updated_at"],
                "storage": "MariaDB",
                "source_key": POSTFIX_INGEST_SOURCE_KEY,
            },
        },
        "stored_delivery_states": current_stats["total"],
    }

@app.get("/api/statistics")
def statistics(_: str = Depends(require_permission("delivery", "view"))):
    return stats()

@app.get("/api/deliveries")
def deliveries(
    _: str = Depends(require_permission("delivery", "view")),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=500),
    status_filter: str = "all",
    search: str = "",
    search_field: str = "all",
    search_operator: str = "contains",
    date_from: str = "",
    date_to: str = "",
    include_total: bool = Query(True),
):
    if (
        status_filter != "all"
        and status_filter not in ALLOWED
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid status",
        )
    if search_field.strip().lower() not in {"all", "from", "to"}:
        raise HTTPException(status_code=400, detail="Invalid delivery search field")
    if search_operator.strip().lower() not in TEXT_FILTER_OPERATORS:
        raise HTTPException(status_code=400, detail="Invalid text filter operator")

    result = grouped(
        page,
        page_size,
        status_filter,
        search.strip(),
        search_operator.strip().lower(),
        search_field.strip().lower(),
        date_from.strip(),
        date_to.strip(),
        include_total=include_total,
    )

    payload = {**result, "page": page}
    if result["total"] is not None:
        payload["total_pages"] = max(
            1, (result["total"] + page_size - 1) // page_size
        )
    else:
        payload["total_pages"] = None
    return payload

@app.get(
    "/api/reports/delivery.txt",
    response_class=PlainTextResponse,
)
def text_report(
    _: str = Depends(require_permission("delivery", "view")),
    limit: int = Query(1000, ge=1, le=10000),
    status_filter: str = "all",
    search: str = "",
    search_field: str = "all",
    search_operator: str = "contains",
    date_from: str = "",
    date_to: str = "",
):
    if search_field.strip().lower() not in {"all", "from", "to"}:
        raise HTTPException(status_code=400, detail="Invalid delivery search field")
    if search_operator.strip().lower() not in TEXT_FILTER_OPERATORS:
        raise HTTPException(status_code=400, detail="Invalid text filter operator")
    return PlainTextResponse(
        build_text(
            report(
                limit,
                status_filter,
                search.strip(),
                search_operator.strip().lower(),
                search_field.strip().lower(),
                date_from.strip(),
                date_to.strip(),
            )
        ),
        headers={
            "Content-Disposition":
                'attachment; filename="postfix-final-delivery-report.txt"'
        },
    )

@app.get("/api/summary")
def summary(
    _: str = Depends(require_permission("summary", "view")),
    date_from: str = "",
    date_to: str = "",
):
    return direction_summary(
        HOME_DOMAINS,
        date_from.strip(),
        date_to.strip(),
    )


@app.get("/api/summary/domains")
def summary_domains(
    _: str = Depends(require_permission("summary", "view")),
    date_from: str = "",
    date_to: str = "",
):
    return {
        "bounced": daily_domain_summary(
            HOME_DOMAINS,
            date_from.strip(),
            date_to.strip(),
            "BOUNCED",
        ),
    }


@app.get("/api/summary/bounces/detail")
def summary_bounce_detail(
    _: str = Depends(require_permission("summary", "view")),
    date: str = "",
    domain: str = "",
    direction: str = "",
):
    try:
        rows = bounced_domain_details(
            HOME_DOMAINS,
            date.strip(),
            domain.strip(),
            direction.strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")

    return {
        "date": date.strip(),
        "domain": domain.strip().lower(),
        "direction": direction.strip().lower(),
        "rows": rows,
        "total": len(rows),
        "subject_available": False,
        "subject_note": (
            "Subject is not present in standard Postfix final-delivery logs. "
            "It is shown as Not captured until a trusted message-header source "
            "is added to ingestion."
        ),
    }


def _mail_size_api_request(method="GET", payload=None, client_ip="", username=""):
    if not MAIL_SIZE_API_URL:
        raise HTTPException(
            status_code=503,
            detail="Mail Size API URL is not configured",
        )
    if not MAIL_SIZE_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Mail Size API key is not configured",
        )

    body = None
    headers = {
        "Accept": "application/json",
        "X-Mail-Size-Key": MAIL_SIZE_API_KEY,
    }
    if client_ip:
        headers["X-Dashboard-Client-IP"] = str(client_ip)[:64]
    if username:
        headers["X-Dashboard-Username"] = str(username)[:128]
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = UrlRequest(
        MAIL_SIZE_API_URL,
        data=body,
        headers=headers,
        method=method.upper(),
    )
    try:
        with urlopen(req, timeout=MAIL_SIZE_API_TIMEOUT) as response:
            raw = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw or "{}")
    except HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
            detail = json.loads(raw or "{}").get("error", "")
        except Exception:
            detail = ""
        raise HTTPException(
            status_code=502,
            detail=detail or "Mail Size host helper rejected the request",
        )
    except (URLError, TimeoutError, OSError):
        logger.exception("Mail Size host helper unavailable")
        raise HTTPException(
            status_code=503,
            detail="Mail Size host helper unavailable",
        )
    except (ValueError, json.JSONDecodeError):
        logger.exception("Invalid Mail Size helper response")
        raise HTTPException(
            status_code=502,
            detail="Invalid response from Mail Size host helper",
        )

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=502,
            detail="Invalid response from Mail Size host helper",
        )
    return data







@app.get("/api/mail-size/status")
def mail_size_status(
    request: Request,
    username: str = Depends(require_permission("mail_size", "admin")),
):
    return _mail_size_api_request(
        "GET",
        client_ip=_client_ip(request),
        username=username,
    )


@app.post("/api/mail-size/limit")
def mail_size_limit(
    request: Request,
    payload: dict,
    username: str = Depends(require_permission("mail_size", "admin")),
):
    profile = str(payload.get("profile", "")).strip().lower()
    if profile not in {"outlook", "webmail"}:
        raise HTTPException(status_code=400, detail="Invalid Mail Size profile")
    try:
        mb = int(payload.get("mb"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid size")
    if mb < 1 or mb > 99:
        raise HTTPException(
            status_code=400,
            detail="Mail Size must be between 1 and 99 MB",
        )
    return _mail_size_api_request(
        "POST",
        {
            "action": "save",
            "profile": profile,
            "mb": mb,
        },
        client_ip=_client_ip(request),
        username=username,
    )


@app.post("/api/mail-size/revert")
def mail_size_revert(
    request: Request,
    payload: dict,
    username: str = Depends(require_permission("mail_size", "admin")),
):
    backup_file = str(payload.get("backup_file", "")).strip()
    if (
        not backup_file
        or backup_file != Path(backup_file).name
        or len(backup_file) > 255
    ):
        raise HTTPException(status_code=400, detail="Invalid backup file")
    return _mail_size_api_request(
        "POST",
        {
            "action": "revert",
            "backup_file": backup_file,
        },
        client_ip=_client_ip(request),
        username=username,
    )






@app.get("/api/quarantine/released-count")
def quarantine_released_count(
    _: str = Depends(require_permission("quarantine", "view")),
):
    return {"released": released_quarantine_count()}


@app.get("/api/spam-lists")
def spam_lists_get(
    _: str = Depends(require_permission("spam_lists", "view")),
    search: str = "",
    preference: str = "all",
    scope: str = "all",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
):
    try:
        result = spam_list_entries(
            search=search,
            preference=preference,
            scope=scope,
            page=page,
            page_size=page_size,
        )
        result["db_ready"] = True
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    except Exception:
        logger.exception("SpamAssassin preference database query failed")
        raise HTTPException(
            status_code=503,
            detail="SpamAssassin preference database unavailable",
        )


@app.post("/api/spam-lists")
def spam_lists_create(
    request: Request,
    payload: dict,
    username: str = Depends(require_permission("spam_lists", "admin")),
):
    try:
        row = spam_create_entry(
            payload.get("scope"),
            payload.get("principal"),
            payload.get("preference"),
            payload.get("value"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    except Exception:
        logger.exception("SpamAssassin preference create failed")
        raise HTTPException(
            status_code=503,
            detail="Unable to create SpamAssassin preference",
        )

    quarantine_write_audit(
        "SPAMLIST_CREATE",
        str(row["prefid"]),
        request.client.host if request.client else "",
        username,
        detail=(
            f'{row["username"]} {row["preference"]} {row["value"]}'
        ),
    )
    return {"ok": True, "entry": row}


@app.get("/api/spam-lists/conflicts")
def spam_lists_conflicts(
    request: Request,
    username: str = Depends(require_permission("spam_lists", "view")),
    limit: int = Query(500, ge=1, le=2000),
):
    try:
        result = spam_conflict_summary(limit=limit)
    except Exception:
        logger.exception("SpamAssassin conflict scan failed")
        raise HTTPException(status_code=503, detail="Unable to check SpamAssassin list conflicts")
    quarantine_write_audit(
        "SPAMLIST_CONFLICT_CHECK",
        f'conflicts:{result.get("total", 0)}',
        request.client.host if request.client else "",
        username,
        detail=f'conflicts={result.get("total", 0)} limit={limit}',
    )
    return {"ok": True, **result}

@app.post("/api/spam-lists/{prefid}")
def spam_lists_update(
    prefid: int,
    request: Request,
    payload: dict,
    username: str = Depends(require_permission("spam_lists", "admin")),
):
    try:
        row = spam_update_entry(
            prefid,
            payload.get("scope"),
            payload.get("principal"),
            payload.get("preference"),
            payload.get("value"),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc).strip("'"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    except Exception:
        logger.exception("SpamAssassin preference update failed")
        raise HTTPException(
            status_code=503,
            detail="Unable to update SpamAssassin preference",
        )

    quarantine_write_audit(
        "SPAMLIST_UPDATE",
        str(prefid),
        request.client.host if request.client else "",
        username,
        detail=(
            f'{row["username"]} {row["preference"]} {row["value"]}'
        ),
    )
    return {"ok": True, "entry": row}


@app.delete("/api/spam-lists/{prefid}")
def spam_lists_delete(
    prefid: int,
    request: Request,
    username: str = Depends(require_permission("spam_lists", "admin")),
):
    try:
        row = spam_delete_entry(prefid)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc).strip("'"))
    except Exception:
        logger.exception("SpamAssassin preference delete failed")
        raise HTTPException(
            status_code=503,
            detail="Unable to delete SpamAssassin preference",
        )

    quarantine_write_audit(
        "SPAMLIST_DELETE",
        str(prefid),
        request.client.host if request.client else "",
        username,
        detail=(
            f'{row["username"]} {row["preference"]} {row["value"]}'
        ),
    )
    return {"ok": True}


@app.post("/api/spam-lists/bulk/delete")
def spam_lists_bulk_delete(
    request: Request,
    payload: dict,
    username: str = Depends(require_permission("spam_lists", "admin")),
):
    prefids = payload.get("prefids", [])
    try:
        rows = spam_bulk_delete_entries(prefids)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc).strip("'"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    except Exception:
        logger.exception("SpamAssassin preference bulk delete failed")
        raise HTTPException(
            status_code=503,
            detail="Unable to bulk delete SpamAssassin preferences",
        )

    detail = "; ".join(
        f'{row["prefid"]}:{row["preference"]} {row["value"]}'
        for row in rows
    )[:3000]
    quarantine_write_audit(
        "SPAMLIST_BULK_DELETE",
        f"bulk:{len(rows)}",
        request.client.host if request.client else "",
        username,
        detail=detail,
    )
    return {
        "ok": True,
        "deleted": len(rows),
        "prefids": [int(row["prefid"]) for row in rows],
    }


@app.post("/api/spam-lists/bulk/import")
def spam_lists_import(
    request: Request,
    payload: dict,
    username: str = Depends(require_permission("spam_lists", "admin")),
):
    text = str(payload.get("text", ""))
    scope = str(payload.get("scope", "global"))
    principal = str(payload.get("principal", ""))
    commit = bool(payload.get("commit", False))

    try:
        result = (
            spam_import_entries(text, scope, principal)
            if commit
            else spam_preview_import(text, scope, principal)
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    except Exception:
        logger.exception("SpamAssassin preference import failed")
        raise HTTPException(
            status_code=503,
            detail="Unable to import SpamAssassin preferences",
        )

    if commit:
        quarantine_write_audit(
            "SPAMLIST_IMPORT",
            f'import:{result.get("username", "")}',
            request.client.host if request.client else "",
            username,
            detail=(
                f'scope={result.get("scope")} added={result.get("added", 0)} '
                f'duplicates={result.get("duplicates", 0)} '
                f'invalid={result.get("invalid", 0)} skipped={result.get("skipped", 0)}'
            ),
        )
    return {"ok": True, "committed": commit, **result}


@app.get("/api/spam-lists/export", response_class=PlainTextResponse)
def spam_lists_export(
    request: Request,
    username: str = Depends(require_permission("spam_lists", "view")),
    search: str = "",
    preference: str = "all",
    scope: str = "all",
):
    try:
        content, count = spam_export_entries(
            search=search,
            preference=preference,
            scope=scope,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    except Exception:
        logger.exception("SpamAssassin preference export failed")
        raise HTTPException(
            status_code=503,
            detail="Unable to export SpamAssassin preferences",
        )

    quarantine_write_audit(
        "SPAMLIST_EXPORT",
        f"export:{count}",
        request.client.host if request.client else "",
        username,
        detail=f"search={search[:120]} preference={preference} scope={scope} rows={count}",
    )
    filename = f"spamassassin-lists-{time.strftime('%Y%m%d-%H%M%S')}.cf"
    return PlainTextResponse(
        content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _quarantine_acl(request: Request):
    # Dashboard access is controlled by authenticated session + User ACL.
    # Client IP is retained only for quarantine action/audit attribution.
    return request.client.host if request.client else ""


@app.get("/api/quarantine")
def quarantine_list(
    request: Request,
    _: str = Depends(require_permission("quarantine", "view")),
    q: str = "",
    q_field: str = "all",
    q_operator: str = "contains",
    date: str = "",
    category: str = "all",
    admin_decision: str = "all",
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=10, le=200),
):
    _quarantine_acl(request)
    if q_field.strip().lower() not in {"all", "from", "to"}:
        raise HTTPException(status_code=400, detail="Invalid quarantine search field")
    if q_operator.strip().lower() not in TEXT_FILTER_OPERATORS:
        raise HTTPException(status_code=400, detail="Invalid text filter operator")
    admin_decision = str(admin_decision or "all").strip().lower()
    if admin_decision not in {"all", "required", "completed"}:
        raise HTTPException(status_code=400, detail="Invalid Admin Decision filter")
    try:
        decided_pdp_ids = ai_ground_truth_current_pdp_ids()
        result = quarantine_query_items(
            q=q,
            q_field=q_field.strip().lower(),
            q_operator=q_operator.strip().lower(),
            date=date,
            category=category,
            admin_decision=admin_decision,
            decided_pdp_ids=decided_pdp_ids,
            page=page,
            page_size=page_size,
        )
        # Release verification is read-only: when a release queue ID was captured,
        # follow the existing Postfix delivery DB so Release Status reflects
        # QUEUED/DELIVERED/DEFERRED/BOUNCED rather than command success alone.
        for item in result.get("items", []):
            status = item.get("release_status") or {}
            queue_id = str(status.get("queue_id") or "").strip()
            if not queue_id:
                continue
            try:
                timeline = queue_timeline_with_log_fallback(queue_id)
                events = timeline.get("events") or []
                finals = [str(e.get("status") or "").upper() for e in events if e.get("status")]
                terminal = next((x for x in reversed(finals) if x in {"DELIVERED","DEFERRED","BOUNCED","REJECTED","UNDELIVERED","BLOCKED"}), "")
                status["delivery_status"] = terminal or ("QUEUED" if events else "QUEUE_ACCEPTED")
                item["release_status"] = status
            except Exception:
                status["delivery_status"] = status.get("status") or "QUEUE_ACCEPTED"
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")


@app.get("/api/quarantine/audit")
def quarantine_audit(
    request: Request,
    _: str = Depends(require_permission("audit", "view")),
    limit: int = Query(10, ge=1, le=100),
):
    _quarantine_acl(request)
    return {"lines": quarantine_audit_tail(limit)}



@app.get("/api/quarantine/audit/records")
def quarantine_audit_records_endpoint(
    request: Request,
    _: str = Depends(require_permission("audit", "view")),
    q: str = "",
    q_operator: str = "contains",
    action: str = "all",
    date_from: str = "",
    date_to: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=500),
):
    _quarantine_acl(request)
    if q_operator.strip().lower() not in TEXT_FILTER_OPERATORS:
        raise HTTPException(status_code=400, detail="Invalid text filter operator")
    return db_audit_records(
        q=q,
        q_operator=q_operator.strip().lower(),
        action=action,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
    )


@app.post("/api/quarantine/refresh")
def quarantine_refresh(
    request: Request,
    _: str = Depends(require_permission("quarantine", "admin")),
):
    _quarantine_acl(request)
    try:
        quarantine_refresh_cache()
        return {"ok": True}
    except Exception:
        logger.exception("Quarantine refresh failed")
        raise HTTPException(
            status_code=500,
            detail="Quarantine refresh failed; see server logs for details",
        )



@app.get("/api/quarantine/intelligence")
def quarantine_intelligence(
    request: Request,
    _: str = Depends(require_permission("quarantine", "view")),
    pdp_id: str = Query(...),
):
    _quarantine_acl(request)
    item = quarantine_item_for(pdp_id)
    if not item:
        raise HTTPException(status_code=404, detail="Quarantine item not found in current cache")
    try:
        result = quarantine_get_intelligence(
            pdp_id=pdp_id,
            message_id=item.get("message_id", ""),
            sender=item.get("from", ""),
            recipient=item.get("display_to", ""),
        )
    except Exception:
        logger.exception("Quarantine intelligence lookup failed")
        raise HTTPException(status_code=503, detail="Quarantine intelligence data source is unavailable")
    # Offline Geo-IP enrichment is best-effort and never blocks intelligence.
    try:
        result["geoip"] = geoip_enrich_header(item.get("header", ""))
    except Exception as exc:
        result["geoip"] = {"available": False, "reason": str(exc)[:200], "network_lookup": False}

    # Read-only Amavis log intelligence. This does not inspect mailbox content.
    result["message_identity"] = {
        "pdp_id": pdp_id,
        "mail_id": _mail_id_from_quarantine_path(pdp_id),
        "message_id": item.get("message_id", ""),
        "sender": item.get("from", ""),
        "recipient": item.get("display_to", ""),
        "subject": item.get("subject", ""),
        "time": item.get("time", item.get("timestamp", "")),
        "category": item.get("category", ""),
        "final_status": ("RELEASED" if item.get("is_released") else ("MARKED SPAM" if item.get("is_manual_spam") else "QUARANTINED")),
        "size": item.get("size", ""),
    }

    try:
        result["amavis_log"] = amavis_log_intelligence(
            message_id=item.get("message_id", ""),
            quarantine_file=pdp_id,
            mail_id=_mail_id_from_quarantine_path(pdp_id),
        )
    except Exception as exc:
        result["amavis_log"] = {"available": False, "matched": False, "reason": str(exc)[:200], "read_only": True}

    # AI branch is strictly additive and shadow-only. Prediction failure must
    # never hide the existing SpamAssassin / host-maildb intelligence.
    try:
        source_path = quarantine_source_path(pdp_id)
        result["ai"] = ai_predict_file(source_path, item)
        result["ai_candidate_proposal"] = ai_predict_shadow_candidate_file(source_path, item)
        result["ai_trainer"] = ai_trainer_status()
        result["fraud_intelligence"] = fraud_analyze_file(source_path)
        result["threat_intelligence"] = ti_analyze_file(
            source_path, message_ai=result["ai_candidate_proposal"], source_kind="quarantine",
            source_id=pdp_id, record_observation=True,
        )
    except Exception as exc:
        result["ai"] = {"enabled": True, "shadow_only": True, "available": False, "reason": str(exc)[:200]}
        result.setdefault("fraud_intelligence", {"enabled": True, "shadow_only": True, "available": False, "reason": "Fraud intelligence unavailable"})
        result.setdefault("threat_intelligence", {"enabled": True, "shadow_only": True, "available": False, "reason": "Three-tier intelligence unavailable"})

    # Restore authoritative Set-2 administrator ground truth independently of
    # prediction/fraud/threat-intelligence availability.  A failure in any
    # shadow analysis must never hide a previously stored Admin Decision.
    result["admin_ground_truth"] = {}
    try:
        gt_source_path = quarantine_source_path(pdp_id)
        source_sha256 = hashlib.sha256(gt_source_path.read_bytes()).hexdigest()
        result["admin_ground_truth"] = ai_ground_truth_current(source_sha256, pdp_id=pdp_id) or {}
    except Exception as exc:
        result["admin_ground_truth_error"] = str(exc)[:200]
    return result


@app.post("/api/email-analysis")
def email_analysis(
    request: Request,
    payload: dict,
    _: str = Depends(require_permission("quarantine", "view")),
):
    import base64
    raw = str(payload.get("raw", "") or "")
    filename = str(payload.get("filename", "") or "")
    data_b64 = str(payload.get("data_b64", "") or "")
    max_bytes = max(65536, int(os.getenv("EMAIL_ANALYSIS_MAX_BYTES", "10485760")))
    if data_b64:
        try:
            encoded = base64.b64decode(data_b64, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="Uploaded email data is not valid base64")
    else:
        encoded = raw.encode("utf-8", "replace")
    if not encoded or (not data_b64 and not raw.strip()):
        raise HTTPException(status_code=400, detail="Paste RFC822/EML source or select an .eml/.msg file first")
    if len(encoded) > max_bytes:
        raise HTTPException(status_code=413, detail=f"Message exceeds manual analysis limit of {max_bytes} bytes")
    try:
        result = analyze_email_upload(filename, encoded) if filename else analyze_email_raw(encoded)
        result["amavis_log"] = amavis_log_intelligence(message_id=result.get("message_id", ""))
        result["geoip_status"] = geoip_status()
        try:
            normalized_for_fraud = normalize_email_upload(filename, encoded) if filename else encoded
            result["fraud_intelligence"] = fraud_analyze_bytes(normalized_for_fraud)
        except Exception:
            result["fraud_intelligence"] = {"enabled": True, "shadow_only": True, "available": False, "reason": "Fraud intelligence unavailable"}
        # Manual Email Analysis is calibrated to the AI Trainer: it may inspect
        # the current-generation candidate in SHADOW ONLY mode. It never creates
        # a training label and never modifies Postfix/Amavis mail flow.
        try:
            normalized = normalize_email_upload(filename, encoded) if filename else encoded
            fd, ai_path = tempfile.mkstemp(prefix="pdd-email-ai-", suffix=".eml")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(normalized)
                result["ai"] = ai_predict_shadow_candidate_file(Path(ai_path), result)
                result["ai_trainer"] = ai_trainer_status()
            finally:
                try:
                    os.unlink(ai_path)
                except FileNotFoundError:
                    pass
        except Exception as ai_exc:
            result["ai"] = {"enabled": True, "shadow_only": True, "available": False, "reason": str(ai_exc)[:200]}
        try:
            normalized_ti = normalize_email_upload(filename, encoded) if filename else encoded
            result["threat_intelligence"] = ti_analyze_bytes(
                normalized_ti, message_ai=result.get("ai") or {}, source_kind="manual",
                source_id=filename or "manual-rfc822", record_observation=False,
            )
        except Exception as ti_exc:
            result["threat_intelligence"] = {"enabled": True, "shadow_only": True, "available": False, "reason": str(ti_exc)[:200]}
        return result
    except Exception:
        logger.exception("Manual email analysis failed")
        raise HTTPException(status_code=400, detail="Unable to parse the supplied email")


@app.post("/api/email-analysis/amavis-dry-run")
def email_analysis_amavis_dry_run(
    payload: dict,
    _: str = Depends(require_permission("quarantine", "view")),
):
    """Analysis-only adapter for an explicitly configured safe Amavis helper.

    This endpoint intentionally never submits to production Amavis SMTP port 10024.
    The helper must be a dedicated analysis-only service and must attest
    ``analysis_only=true`` in its response.
    """
    import base64
    raw = str(payload.get("raw", "") or "")
    filename = str(payload.get("filename", "") or "")
    data_b64 = str(payload.get("data_b64", "") or "")
    max_bytes = max(65536, int(os.getenv("EMAIL_ANALYSIS_MAX_BYTES", "10485760")))
    if data_b64:
        try:
            encoded = base64.b64decode(data_b64, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="Uploaded email data is not valid base64")
    else:
        encoded = raw.encode("utf-8", "replace")
    if not encoded or (not data_b64 and not raw.strip()):
        raise HTTPException(status_code=400, detail="Paste RFC822/EML source or select an .eml/.msg file first")
    if len(encoded) > max_bytes:
        raise HTTPException(status_code=413, detail=f"Message exceeds manual analysis limit of {max_bytes} bytes")
    try:
        normalized = normalize_email_upload(filename, encoded) if filename else encoded
        return amavis_dry_run_bytes(normalized, filename=filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Amavis dry-run is unavailable or not safely configured")
    except Exception:
        logger.exception("Amavis dry-run analysis failed")
        raise HTTPException(status_code=502, detail="Amavis dry-run helper failed")


@app.get("/api/email-analysis/amavis-dry-run/status")
def email_analysis_amavis_dry_run_status(
    _: str = Depends(require_permission("quarantine", "view")),
):
    return amavis_dry_run_status()


@app.get("/api/fraud-intelligence/status")
def fraud_intelligence_status_api(
    _: str = Depends(require_permission("quarantine", "view")),
):
    status=fraud_repo_status()
    status.update({"shadow_only":True,"training_authority":False})
    return status


@app.get("/api/ai-intelligence/status")
def ai_intelligence_status_api(
    _: str = Depends(require_permission("quarantine", "view")),
):
    status=ai_ti_status()
    status.update({"message_ai":"OPERATIONAL_SCHEMA_V4","infrastructure_ai":"OPERATIONAL_LOCAL_EVIDENCE","campaign_ai":"OPERATIONAL_LOCAL_CORRELATION","correlation_engine":"SHADOW_EXPLAINABLE_V1"})
    return status


@app.get("/api/ai-trainer/status")
def ai_trainer_status_api(
    _: str = Depends(require_permission("quarantine", "view")),
):
    return ai_trainer_status()


@app.post("/api/ai-trainer/backfill")
def ai_trainer_backfill_api(
    request: Request,
    username: str = Depends(require_permission("quarantine", "admin")),
):
    """R1.1.52: legacy sa-learn backfill is deliberately disabled.

    Existing rows remain preserved for audit, but SpamAssassin/Bayes state is no
    longer permitted to create Set-2 AI training labels.
    """
    remote_addr = _quarantine_acl(request)
    result = {
        "ok": True, "disabled": True, "imported": 0, "duplicates": 0,
        "missing_files": 0, "failed": 0,
        "reason": "sa-learn/Bayes labels are audit-only and are not AI training authority in R1.1.52",
    }
    quarantine_write_audit("AI_LABEL_BACKFILL_BLOCKED", "ai-trainer", remote_addr, username, detail=json.dumps(result)[:1000])
    return result


@app.post("/api/ai-trainer/ground-truth")
async def ai_trainer_ground_truth_api(
    request: Request,
    username: str = Depends(require_permission("quarantine", "admin")),
):
    remote_addr=_quarantine_acl(request)
    payload=await request.json()
    pdp_id=str(payload.get("pdp_id") or "").strip()
    label=str(payload.get("label") or "").strip().upper()
    classification=str(payload.get("classification") or "").strip().upper()
    review_reason=str(payload.get("review_reason") or "").strip()[:512]
    admin_notes=str(payload.get("admin_notes") or "").strip()[:1000]
    if label not in {"HAM","SPAM"}:
        raise HTTPException(status_code=400, detail="Ground truth must be HAM or SPAM")
    item=quarantine_item_for(pdp_id)
    if not item:
        raise HTTPException(status_code=404, detail="Quarantine item not found in current cache")
    try:
        source_path=quarantine_source_path(pdp_id)
        proposal=ai_predict_shadow_candidate_file(source_path,item)
        fraud=fraud_analyze_file(source_path)
        proposed_label=str(proposal.get("verdict") or "").upper() if proposal.get("available") else str(fraud.get("suggested_label") or "").upper()
        proposed_classification=str(fraud.get("suggested_classification") or "").upper() if proposed_label=="SPAM" else ("OTHER_HAM" if proposed_label=="HAM" else "")
        acknowledged=bool(proposed_label and label==proposed_label and classification==proposed_classification)
        result=ai_record_human_label(
            pdp_id=pdp_id, label=label, source_path=source_path, item=item,
            username=username, source=("admin-ai-acknowledged" if acknowledged else "admin-ground-truth-ui"), classification=classification, review_reason=review_reason, admin_notes=admin_notes,
        )
        calibration_id=record_ai_ground_truth_calibration(
            source_sha256=result.get("source_sha256",""), pdp_id=pdp_id, ai_proposed_label=proposed_label,
            ai_proposed_classification=proposed_classification, ai_confidence=proposal.get("confidence") if proposal.get("available") else None,
            admin_final_label=label, admin_final_classification=classification, admin_acknowledged_ai=acknowledged, reviewer=username,
            generation_id=str(proposal.get("generation_id") or ""), candidate_version=str(proposal.get("model_version") or ""),
            fraud_repo_version=str(fraud.get("repo_version") or ""),
        )
        # Read-after-write verification: the UI may report success only when the
        # authoritative MariaDB CURRENT row can be read back with the exact admin
        # decision/classification that was submitted.
        persisted=ai_ground_truth_current(result.get("source_sha256", ""), pdp_id=pdp_id) or {}
        if str(persisted.get("label") or "").upper()!=label or str(persisted.get("classification") or "").upper()!=classification:
            raise RuntimeError("Admin Ground Truth persistence verification failed")
        result.update({
            "calibration_id":calibration_id,"ai_proposed_label":proposed_label,
            "ai_proposed_classification":proposed_classification,"admin_acknowledged_ai":acknowledged,
            "admin_ground_truth":persisted,"reviewer":username,
        })
        quarantine_write_audit("AI_GROUND_TRUTH", pdp_id, remote_addr, username, detail=json.dumps({"label":label,"classification":classification,"ai_proposed_label":proposed_label,"ai_proposed_classification":proposed_classification,"acknowledged":acknowledged,"reversal":result.get("reversal"),"conflict_investigation_id":result.get("conflict_investigation_id"),"calibration_id":calibration_id,"admin_notes":admin_notes})[:1000])
        return result
    except ValueError:
        logger.warning("AI ground-truth request rejected due to invalid input")
        raise HTTPException(status_code=400, detail="Invalid AI ground-truth request")
    except Exception:
        logger.exception("AI ground-truth capture failed")
        raise HTTPException(status_code=500, detail="AI ground-truth capture failed")


@app.post("/api/ai-trainer/train")
def ai_trainer_train_api(
    request: Request,
    username: str = Depends(require_permission("quarantine", "admin")),
):
    _quarantine_acl(request)
    try:
        result = ai_train_candidate(username=username)
        quarantine_write_audit("AI_CANDIDATE_TRAIN", "ai-trainer", request.client.host if request.client else "", username, detail=json.dumps(result)[:1000])
        return {"ok": True, "candidate": result}
    except Exception as exc:
        quarantine_write_audit("AI_CANDIDATE_TRAIN_FAILED", "ai-trainer", request.client.host if request.client else "", username, detail=(str(exc)[:1000]))
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")


@app.post("/api/ai-trainer/promote")
def ai_trainer_promote_api(
    request: Request,
    username: str = Depends(require_permission("quarantine", "admin")),
):
    _quarantine_acl(request)
    try:
        result = ai_promote_candidate(username=username)
        quarantine_write_audit("AI_MODEL_PROMOTE", "ai-trainer", request.client.host if request.client else "", username, detail=json.dumps(result)[:1000])
        return result
    except Exception as exc:
        quarantine_write_audit("AI_MODEL_PROMOTE_FAILED", "ai-trainer", request.client.host if request.client else "", username, detail=(str(exc)[:1000]))
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")


@app.get("/api/ai-trainer/predict")
def ai_trainer_predict_api(
    request: Request,
    _: str = Depends(require_permission("quarantine", "view")),
    pdp_id: str = Query(...),
):
    _quarantine_acl(request)
    item = quarantine_item_for(pdp_id)
    if not item:
        raise HTTPException(status_code=404, detail="Quarantine item not found in current cache")
    try:
        return ai_predict_file(quarantine_source_path(pdp_id), item)
    except Exception:
        logger.exception("AI shadow prediction failed")
        raise HTTPException(status_code=500, detail="AI shadow prediction failed")


@app.post("/api/quarantine/release-learn-ham")
def quarantine_release_learn_ham(
    request: Request,
    username: str = Depends(require_permission("quarantine", "admin")),
    pdp_id: str = Query(...),
):
    remote_addr = _quarantine_acl(request)
    # This is additive: the existing Release and Learn HAM functions are called
    # unchanged and remain available independently.
    release_result = quarantine_release(pdp_id, remote_addr, username)
    try:
        learn_result = quarantine_learn_ham(pdp_id, remote_addr, username)
        quarantine_write_audit(
            "RELEASE_LEARN_HAM",
            pdp_id,
            remote_addr,
            username,
            detail="Release succeeded and message learned as HAM",
        )
        return {
            "ok": True,
            "released": True,
            "learned_ham": True,
            "release": release_result,
            "learning": learn_result,
        }
    except Exception as exc:
        # Never roll back or hide a successful release.  The operator is told
        # explicitly that only the optional HAM learning step failed.
        try:
            quarantine_write_audit(
                "RELEASE_LEARN_HAM_PARTIAL",
                pdp_id,
                remote_addr,
                username,
                detail=("Released successfully; HAM learning failed: " + str(exc))[:1000],
            )
        except Exception:
            pass
        return {
            "ok": False,
            "released": True,
            "learned_ham": False,
            "release": release_result,
            "error": "Message was released, but HAM learning failed; see Audit",
        }


@app.post("/api/quarantine/learn")
def quarantine_learn(
    request: Request,
    username: str = Depends(require_permission("quarantine", "admin")),
    mode: str = Query(...),
    pdp_id: str = Query(...),
):
    remote_addr = _quarantine_acl(request)
    try:
        if mode == "spam":
            return quarantine_learn_spam(pdp_id, remote_addr, username)
        if mode == "ham":
            return quarantine_learn_ham(pdp_id, remote_addr, username)
        raise HTTPException(status_code=400, detail="Invalid learning action")
    except HTTPException:
        raise
    except Exception as exc:
        try:
            quarantine_write_audit(
                "LEARN_SPAM_FAILED" if mode == "spam" else "LEARN_HAM_FAILED",
                pdp_id, remote_addr, username, detail=(str(exc)[:1000]),
            )
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="SpamAssassin learning failed; see Audit for details")


@app.post("/api/quarantine/correct-learning")
def quarantine_correct_learning_api(
    request: Request,
    username: str = Depends(require_permission("quarantine", "admin")),
    mode: str = Query(...),
    pdp_id: str = Query(...),
):
    remote_addr = _quarantine_acl(request)
    try:
        if mode not in {"ham", "spam"}:
            raise HTTPException(status_code=400, detail="Invalid correction action")
        return quarantine_correct_learning(pdp_id, mode, remote_addr, username)
    except HTTPException:
        raise
    except Exception as exc:
        try:
            quarantine_write_audit("LEARNING_CORRECTION_FAILED", pdp_id, remote_addr, username, detail=str(exc)[:1000])
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Classification correction failed; see Audit for details")


@app.post("/api/quarantine/bulk-action")
def quarantine_bulk_action(
    request: Request,
    payload: dict,
    username: str = Depends(require_permission("quarantine", "admin")),
):
    remote_addr = _quarantine_acl(request)
    mode = str(payload.get("mode", "")).strip().lower()
    raw_ids = payload.get("pdp_ids", [])

    if mode not in {"release", "spam"}:
        raise HTTPException(status_code=400, detail="Invalid action")
    if not isinstance(raw_ids, list):
        raise HTTPException(status_code=400, detail="pdp_ids must be a list")

    # De-duplicate while preserving selection order.
    pdp_ids = []
    seen = set()
    for value in raw_ids:
        pdp_id = str(value or "").strip()
        if not pdp_id or pdp_id in seen:
            continue
        seen.add(pdp_id)
        pdp_ids.append(pdp_id)

    if not pdp_ids:
        raise HTTPException(status_code=400, detail="No quarantine items selected")
    if len(pdp_ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 items per bulk action")

    results = []
    success = 0
    failed = 0

    for pdp_id in pdp_ids:
        try:
            if mode == "release":
                quarantine_release(pdp_id, remote_addr, username)
            else:
                quarantine_mark_spam(pdp_id, remote_addr, username)
            success += 1
            results.append({"pdp_id": pdp_id, "ok": True})
        except Exception as exc:
            failed += 1
            failure_action = "RELEASE_FAILED" if mode == "release" else "SPAM_MARK_FAILED"
            try:
                quarantine_write_audit(
                    failure_action,
                    pdp_id,
                    remote_addr,
                    username,
                    detail=(str(exc)[:1000]),
                )
            except Exception:
                pass
            results.append({
                "pdp_id": pdp_id,
                "ok": False,
                "error": "Action failed; see Audit for details",
            })

    return {
        "ok": failed == 0,
        "mode": mode,
        "selected": len(pdp_ids),
        "success": success,
        "failed": failed,
        "results": results,
    }


@app.post("/api/quarantine/action")
def quarantine_action(
    request: Request,
    username: str = Depends(require_permission("quarantine", "admin")),
    mode: str = Query(...),
    pdp_id: str = Query(...),
):
    remote_addr = _quarantine_acl(request)
    try:
        if mode == "release":
            return quarantine_release(pdp_id, remote_addr, username)
        if mode == "spam":
            return quarantine_mark_spam(pdp_id, remote_addr, username)
        raise HTTPException(status_code=400, detail="Invalid action")
    except HTTPException:
        raise
    except Exception as exc:
        failure_action = "RELEASE_FAILED" if mode == "release" else "SPAM_MARK_FAILED"
        try:
            quarantine_write_audit(failure_action, pdp_id, remote_addr, username, detail=(str(exc)[:1000]))
        except Exception:
            pass
        raise HTTPException(
            status_code=500,
            detail="Quarantine action failed; see Audit for details",
        )



def _tail_matching_lines(path: Path, needles, max_bytes: int = 16777216, max_matches: int = 120):
    """Best-effort read-only reverse-tail search without shelling out.

    Reads only the newest max_bytes so intelligence lookups cannot scan an
    unbounded production log on every request.
    """
    needles = [str(x).strip() for x in (needles or []) if str(x).strip()]
    if not needles or not path.is_file():
        return []
    try:
        size = path.stat().st_size
        start = max(0, size - max_bytes)
        with path.open("rb") as handle:
            handle.seek(start)
            data = handle.read(max_bytes)
        decoded = data.decode("utf-8", "replace")
        lines = decoded.splitlines()
        matches = [line for line in lines if any(n in line for n in needles)]
        return matches[-max_matches:]
    except Exception:
        logger.exception("Read-only log intelligence lookup failed for %s", path)
        return []


def _postfix_log_event(queue_id: str, line: str):
    lower = line.lower()
    status = ""
    stage = "POSTFIX_LOG"
    detail = line
    recipient = ""
    sender = ""
    target = ""
    if "status=sent" in lower:
        status = "DELIVERED"
    elif "status=deferred" in lower:
        status = "DEFERRED"
    elif "status=bounced" in lower:
        status = "BOUNCED"
    elif "reject:" in lower or "status=reject" in lower:
        status = "REJECTED"
    elif "queue active" in lower:
        status = "QUEUED"
    elif re.search(r"\bremoved\s*$", lower):
        status = "REMOVED"
    elif "client=" in lower:
        status = "QUEUE_ACCEPTED"
    service_match = re.search(r"postfix/([^\[]+)", line)
    if service_match:
        stage = service_match.group(1).strip().upper()
    to_match = re.search(r"\bto=<([^>]*)>", line)
    if to_match:
        recipient = to_match.group(1)
    from_match = re.search(r"\bfrom=<([^>]*)>", line)
    if from_match:
        sender = from_match.group(1)
    relay_match = re.search(r"\brelay=([^,]+)", line)
    if relay_match:
        target = relay_match.group(1)
    ts_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)", line)
    return {
        "stage": stage,
        "timestamp": ts_match.group(1) if ts_match else "",
        "status": status or "LOG_EVENT",
        "sender": sender,
        "recipient": recipient,
        "target": target,
        "detail": detail,
        "raw_log": line,
        "source": "postfix_log",
    }


def _amavis_log_event(queue_id: str, line: str):
    lower = line.lower()
    status = "QUEUE_ACCEPTED" if "queued as " + queue_id.lower() in lower else "AMAVIS_EVENT"
    sender = ""
    recipient = ""
    frm = re.search(r"\bfrom <([^>]*)>", line, re.I)
    if frm:
        sender = frm.group(1)
    to = re.search(r"-> <([^>]*)>", line)
    if to:
        recipient = to.group(1)
    ts_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)", line)
    return {
        "stage": "AMAVIS_RELEASE",
        "timestamp": ts_match.group(1) if ts_match else "",
        "status": status,
        "sender": sender,
        "recipient": recipient,
        "target": "Postfix reinjection",
        "detail": line,
        "raw_log": line,
        "source": "amavis_log",
    }


def queue_timeline_with_log_fallback(queue_id: str):
    queue_id = str(queue_id or "").strip()
    result = queue_timeline(queue_id)
    events = list(result.get("events") or [])
    sources = ["dashboard_db"] if events else []
    # Always enrich release-generated IDs with log evidence; DB indexing may lag
    # or intentionally omit localhost reinjection records.
    postfix_lines = _tail_matching_lines(LOG, [queue_id])
    if postfix_lines:
        sources.append("postfix_log")
        seen = {str(e.get("raw_log") or "") for e in events}
        for line in postfix_lines:
            if line not in seen:
                events.append(_postfix_log_event(queue_id, line))
                seen.add(line)
    amavis_lines = _tail_matching_lines(AMAVIS_LOG, [queue_id])
    if amavis_lines:
        sources.append("amavis_log")
        seen = {str(e.get("raw_log") or "") for e in events}
        for line in amavis_lines:
            if line not in seen:
                events.append(_amavis_log_event(queue_id, line))
                seen.add(line)
    result["events"] = events
    result["sources"] = list(dict.fromkeys(sources))
    result["live_log_fallback"] = bool(postfix_lines or amavis_lines)
    return result


def _parse_and_store_amavis_lines(lines):
    """Persist matched Amavis evidence without modifying the source log."""
    for line in lines:
        q=re.search(r"Queue-ID:\s*([A-Za-z0-9]+)", line, re.I)
        rq=re.search(r"queued as\s+([A-Za-z0-9]+)", line, re.I)
        mid=re.search(r"Message-ID:\s*<([^>]+)>", line, re.I)
        mail=re.search(r"(?:mail_id:\s*|\()([A-Za-z0-9_-]{8,})(?:\)|,)", line, re.I)
        score=re.search(r"(?:Hits:|score=)\s*([-+0-9.]+)", line, re.I)
        quar=re.search(r"(?:quarantine:|mbx=)[ ]*([^, ]+)", line, re.I)
        verdict=''
        upper=line.upper()
        for candidate in ('VIRUS','BANNED','SPAM','CLEAN','PASSED','FWD','RELEASED','BLOCKED'):
            if candidate in upper: verdict=candidate; break
        try:
            store_amavis_evidence(line, queue_id=q.group(1) if q else '', release_queue_id=rq.group(1) if rq else '', message_id=mid.group(1) if mid else '', mail_id=mail.group(1) if mail else '', verdict=verdict, spam_score=score.group(1) if score else '', quarantine_file=quar.group(1) if quar else '')
        except Exception:
            pass

def _mail_id_from_quarantine_path(value: str):
    text=str(value or '')
    match=re.search(r'(?:spam|virus|banned)-([A-Za-z0-9]+)(?:\.gz)?$', text, re.I)
    return match.group(1) if match else ''

def amavis_log_intelligence(*tokens, mail_id='', queue_id='', release_queue_id='', message_id='', quarantine_file=''):
    """Current-message-only Amavis trace with MariaDB as authority.

    R1.1.29 deliberately avoids sender-only and broad raw-log correlation.
    Exact indexed identifiers are used in priority order, then the matching
    Amavis session is expanded. Legacy/live fallback is retained only when no
    current-repository row exists and only for explicit identifiers.
    """
    tokens = [str(t or "").strip().strip("<>") for t in tokens if str(t or "").strip()]
    exists = AMAVIS_LOG.is_file()
    readable = bool(exists and os.access(AMAVIS_LOG, os.R_OK))
    if not mail_id and quarantine_file:
        mail_id=_mail_id_from_quarantine_path(quarantine_file)
    if not message_id and tokens:
        message_id=tokens[-1] if '@' in tokens[-1] or tokens[-1].startswith('<') else ''
    trace={'rows': [], 'matched_by': ''}
    source='MariaDB continuous evidence'
    try:
        trace=find_current_amavis_trace(
            mail_id=mail_id, queue_id=queue_id, release_queue_id=release_queue_id,
            message_id=message_id, quarantine_file=quarantine_file, limit=80,
        )
    except Exception:
        trace={'rows': [], 'matched_by': ''}
    rows=list(trace.get('rows') or [])
    fallback_used=False
    explicit=[x for x in (mail_id,queue_id,release_queue_id,message_id,quarantine_file) if str(x or '').strip()]
    # Backward compatibility only: exact identifiers may search retained legacy evidence.
    if not rows and explicit:
        try:
            rows=find_amavis_evidence(explicit,40)
            if rows: source='MariaDB legacy retained evidence'
        except Exception:
            rows=[]
    # Emergency bootstrap fallback only for explicit current-message identifiers.
    if not rows and readable and explicit:
        live=_tail_matching_lines(AMAVIS_LOG,explicit,max_bytes=16777216,max_matches=40)
        if live:
            _parse_and_store_amavis_lines(live)
            fallback_used=True
            try:
                rows=find_amavis_evidence(explicit,40)
                if rows: source='MariaDB legacy evidence seeded from emergency live-log fallback'
            except Exception:
                rows=[]
    lines=[str(r.get('raw_log') or '') for r in rows]
    verdict=next((str(r.get('verdict') or '') for r in reversed(rows) if r.get('verdict')),'')
    queue_ids=[]
    for r in rows:
        for k in ('queue_id','release_queue_id'):
            v=str(r.get(k) or '')
            if v and v not in queue_ids: queue_ids.append(v)
    attachment_history=[]
    try:
        session_ids=list(dict.fromkeys(str(r.get('session_id') or '') for r in rows if str(r.get('session_id') or '')))
        attachment_history=find_current_amavis_attachment_history(
            session_ids=session_ids, mail_id=mail_id, queue_id=queue_id,
            release_queue_id=release_queue_id, message_id=message_id,
            quarantine_file=quarantine_file, limit=100,
        )
    except Exception:
        attachment_history=[]
    # If current rows came from a freshly seeded legacy fallback, the normalized
    # continuous attachment table may not yet contain them.  Preserve only the
    # current message's parsed log-derived content in the response.
    attachment_view=[]
    seen_attach=set()
    for a in attachment_history:
        key=(str(a.get('attachment_name') or ''),str(a.get('content_text') or ''))
        if key in seen_attach: continue
        seen_attach.add(key)
        attachment_view.append({
            'event_time': a.get('event_time'),
            'attachment_name': str(a.get('attachment_name') or '(log-derived attachment content)'),
            'evidence_type': str(a.get('evidence_type') or 'AMAVIS_LOG_CONTENT'),
            'content_text': str(a.get('content_text') or ''),
            'quarantine_file': str(a.get('quarantine_file') or ''),
        })
    dbs={}
    try: dbs=get_amavis_ingest_state(AMAVIS_INGEST_SOURCE_KEY) or {}
    except Exception: pass
    return {
        'available': bool(rows) or readable, 'exists': exists, 'readable': readable,
        'path': str(AMAVIS_LOG), 'storage': source,
        'scope': 'CURRENT_MESSAGE_ONLY', 'matched_by': trace.get('matched_by') or ('legacy-explicit-id' if rows else ''),
        'ingestion': {
            'running': bool(amavis_ingest_state.get('running')),
            'status': str(dbs.get('status') or ('RUNNING' if amavis_ingest_state.get('running') else 'UNKNOWN')),
            'checkpoint_offset': int(dbs.get('source_offset') or amavis_ingest_state.get('checkpoint_offset') or 0),
            'source_size': int(dbs.get('source_size') or amavis_ingest_state.get('source_size') or 0),
            'mode': str(amavis_ingest_state.get('checkpoint_mode') or ''),
            'error': str(dbs.get('last_error') or amavis_ingest_state.get('error') or ''),
        },
        'reason': ('' if (rows or readable) else ('Permission denied: container needs read access to the host adm group/GID' if exists else 'Amavis log file is not mounted')),
        'matched': bool(rows), 'match_count': len(rows), 'verdict_hint': verdict or '-',
        'queue_ids': queue_ids, 'recent_evidence': lines[-12:], 'read_only': True,
        'attachment_history': attachment_view,
        'attachment_history_count': len(attachment_view),
        'attachment_storage': 'MariaDB persistent log-derived history',
        'live_log_fallback': fallback_used,
    }


@app.get("/api/monitor/summary")
def monitor_login_summary(protocol: str = Query(..., pattern="^(POP3|WEBMAIL)$"), search: str = Query("", max_length=255), date_from: str = Query("", max_length=10), date_to: str = Query("", max_length=10), limit: int = Query(500, ge=1, le=2000), _: str = Depends(require_permission("monitor", "view"))):
    # R1.1.42: request handlers read MariaDB only. Log parsing remains in the
    # background monitor thread so summary rendering never waits on logfile IO.
    data = login_summary(protocol, search, date_from, date_to, limit)
    data["sync"] = {
        "inserted": int(reader_state.get("monitor_last_batch_inserted", 0)),
        "last_sync": reader_state.get("monitor_ingest_last", ""),
        "sources": reader_state.get("monitor_sources", {}),
    }
    return data

@app.get("/api/monitor/user-history")
def monitor_login_user_history(protocol: str = Query(..., pattern="^(POP3|WEBMAIL)$"), username: str = Query(..., max_length=320), date_from: str = Query("", max_length=10), date_to: str = Query("", max_length=10), limit: int = Query(500, ge=1, le=2000), _: str = Depends(require_permission("monitor", "view"))):
    return login_user_history(protocol, username, date_from, date_to, limit)

@app.get("/api/monitor/pop3-logins")
def monitor_pop3_logins(search: str = Query("", max_length=255), status: str = Query("all", pattern="^(all|SUCCESS|FAILED|INFO)$"), limit: int = Query(200, ge=1, le=500), _: str = Depends(require_permission("monitor", "view"))):
    return dovecot_pop3_logins(search=search,status=status,limit=limit)

@app.get("/api/monitor/roundcube-logins")
def monitor_roundcube_logins(search: str = Query("", max_length=255), status: str = Query("all", pattern="^(all|SUCCESS|FAILED|INFO)$"), limit: int = Query(200, ge=1, le=500), _: str = Depends(require_permission("monitor", "view"))):
    return roundcube_logins(search=search,status=status,limit=limit)


@app.get("/api/flow/{queue_id}")
def flow_detail(
    queue_id: str,
    _: str = Depends(require_permission("mail_flow", "view")),
):
    result = queue_timeline_with_log_fallback(queue_id.strip())
    if not result["events"]:
        raise HTTPException(status_code=404, detail="Queue ID not found")
    return result




@app.get("/api/mail-flow/approved-image")
def approved_mail_flow_image():
    image_path = Path(__file__).resolve().parent / "assets" / "mail-flow-approved-m7.png"
    if not image_path.is_file():
        raise HTTPException(status_code=404, detail="Approved mail flow image not found")
    return FileResponse(
        image_path,
        media_type="image/png",
        headers={"Cache-Control": "private, max-age=3600"},
    )


@app.get("/api/me")
def current_user_profile(username: str = Depends(require_session)):
    access = dashboard_user_access(username)
    return {
        "username": username,
        "is_admin": bool(access and access.get("is_admin")),
        "permissions": (access or {}).get("permissions", {}),
    }


@app.get("/api/admin/users")
def user_acl_list(_: str = Depends(require_acl_admin)):
    return {"users": list_dashboard_users()}


@app.post("/api/admin/users")
async def user_acl_create(
    request: Request,
    administrator: str = Depends(require_acl_admin),
):
    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    is_admin = bool(body.get("is_admin", False))
    permissions = body.get("permissions", {})
    active = bool(body.get("active", True))
    try:
        create_dashboard_user(
            username,
            password,
            is_admin=is_admin,
            permissions=permissions,
            active=active,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    except Exception as exc:
        if "Duplicate entry" in str(exc):
            raise HTTPException(status_code=409, detail="Username already exists")
        logger.exception("User ACL create failed")
        raise HTTPException(status_code=500, detail="Unable to create user")

    try:
        quarantine_write_audit(
            "ACL_USER_CREATE",
            "",
            _client_ip(request),
            administrator,
            detail=f"user={username}",
        )
    except Exception:
        pass
    return {"ok": True}


@app.post("/api/admin/users/{user_id}")
async def user_acl_update(
    user_id: int,
    request: Request,
    administrator: str = Depends(require_acl_admin),
):
    body = await request.json()
    users = list_dashboard_users()
    target = next((u for u in users if int(u["id"]) == int(user_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent the current administrator from accidentally locking themselves out.
    if target["username"] == administrator:
        if body.get("active") is False or body.get("is_admin") is False:
            raise HTTPException(
                status_code=400,
                detail="You cannot disable or remove your own administrator role",
            )

    password = body.get("password")
    if password is not None:
        password = str(password)
    try:
        update_dashboard_user(
            user_id,
            password=password,
            is_admin=body.get("is_admin") if "is_admin" in body else None,
            permissions=body.get("permissions") if "permissions" in body else None,
            active=body.get("active") if "active" in body else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    except Exception:
        logger.exception("User ACL update failed")
        raise HTTPException(status_code=500, detail="Unable to update user")

    try:
        quarantine_write_audit(
            "ACL_USER_UPDATE",
            "",
            _client_ip(request),
            administrator,
            detail=f"user={target['username']}",
        )
    except Exception:
        pass
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
def user_acl_delete(
    user_id: int,
    request: Request,
    administrator: str = Depends(require_acl_admin),
):
    users = list_dashboard_users()
    target = next((u for u in users if int(u["id"]) == int(user_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["username"] == administrator:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    if target.get("is_admin"):
        other_admins = [
            u for u in users
            if u.get("is_admin") and u.get("active") and int(u["id"]) != int(user_id)
        ]
        if not other_admins:
            raise HTTPException(status_code=400, detail="At least one active administrator is required")
    try:
        delete_dashboard_user(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="AI operation failed; see Audit for details")
    try:
        quarantine_write_audit(
            "ACL_USER_DELETE",
            "",
            _client_ip(request),
            administrator,
            detail=f"user={target['username']}",
        )
    except Exception:
        pass
    return {"ok": True}


def _readiness_payload():
    checks = {}
    try:
        checks["database"] = bool(db_ready())
    except Exception:
        checks["database"] = False
        checks["database_error"] = "unavailable"

    checks["mail_log"] = LOG.is_file() and os.access(LOG, os.R_OK)
    checks["quarantine_dir"] = (
        quarantine_dir_path.is_dir()
        and os.access(quarantine_dir_path, os.R_OK)
    )
    checks["state_dir"] = (
        quarantine_state_dir.is_dir()
        and os.access(quarantine_state_dir, os.W_OK)
    )
    checks["sa_learn"] = quarantine_sa_learn_ready()

    amavis_ok = False
    try:
        host, port_text = amavis_pdp_server.rsplit(":", 1)
        with socket.create_connection((host, int(port_text)), timeout=2):
            amavis_ok = True
    except Exception:
        pass
    checks["amavis_pdp"] = amavis_ok

    ok = all(
        bool(checks.get(k))
        for k in (
            "database",
            "mail_log",
            "quarantine_dir",
            "state_dir",
            "amavis_pdp",
        )
    )
    return ok, {
        "status": "ready" if ok else "not_ready",
        "checks": checks,
        "reader": {
            "running": reader_state.get("running", False),
            "error": reader_state.get("error", ""),
        },
        "active_sessions": session_store.active_count(),
    }


@app.get("/health/ready")
def ready_public():
    ok, _ = _readiness_payload()
    return JSONResponse(
        {"status": "ready" if ok else "not_ready"},
        status_code=200 if ok else 503,
    )


@app.get("/api/system/ready")
def ready_detail(_: str = Depends(require_permission("system", "view"))):
    ok, payload = _readiness_payload()
    payload["feature_checks"] = {
        "spam_pref_db": {
            "ok": bool(spam_pref_db_ready()),
            "label": "SpamAssassin preference DB",
            "impact": "Whitelist / blacklist management is unavailable if this dependency fails.",
            "critical": False,
        },
        "reader_running": {
            "ok": bool(reader_state.get("running", False)),
            "label": "Mail log reader",
            "impact": "New delivery events stop updating while the reader is not running.",
            "critical": True,
        },
        "checkpoint_state": {
            "ok": not bool(reader_state.get("checkpoint_error", "")),
            "label": "Reader checkpoint",
            "impact": "Restart resume safety can be affected if checkpoint persistence fails.",
            "critical": True,
        },
    }
    payload["reader"]["checkpoint_storage"] = "MariaDB"
    payload["reader"]["checkpoint_source_key"] = POSTFIX_INGEST_SOURCE_KEY
    payload["reader"]["checkpoint_error"] = reader_state.get("checkpoint_error", "")
    return JSONResponse(payload, status_code=200 if ok else 503)


def _safe_dashboard_config():
    config = {
        "home_domains": list(HOME_DOMAINS),
        "retention_days": RETENTION,
        "log_file": str(LOG),
        "initial_import_lines": IMPORT,
        "checkpoint_storage": "MariaDB",
        "checkpoint_source_key": POSTFIX_INGEST_SOURCE_KEY,
        "postfix_ingest_batch_lines": POSTFIX_INGEST_BATCH_LINES,
        "postfix_ingest_poll_seconds": POSTFIX_INGEST_POLL_SECONDS,
        "legacy_checkpoint_file": str(INGEST_CHECKPOINT_FILE),
        "spam_pref_db": {
            "host": os.getenv("SPAM_PREF_DB_HOST", "127.0.0.1"),
            "port": int(os.getenv("SPAM_PREF_DB_PORT", "3306")),
            "database": os.getenv("SPAM_PREF_DB_NAME", "maildb"),
            "user": os.getenv("SPAM_PREF_DB_USER", "spam"),
            "password_configured": bool(os.getenv("SPAM_PREF_DB_PASSWORD", "")),
        },
        "mail_size_api": {
            "url": MAIL_SIZE_API_URL,
            "key_configured": bool(MAIL_SIZE_API_KEY),
            "timeout_seconds": MAIL_SIZE_API_TIMEOUT,
        },
        "amavis": {
            "quarantine_dir": str(quarantine_dir_path),
            "state_dir": str(quarantine_state_dir),
            "pdp_server": str(amavis_pdp_server),
        },
        "session": {
            "idle_timeout_minutes": SESSION_IDLE_TIMEOUT_MINUTES,
            "absolute_timeout_hours": SESSION_ABSOLUTE_TIMEOUT_HOURS,
            "cookie_secure": bool(SESSION_COOKIE_SECURE),
        },
    }
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return config, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _config_diff(current, previous):
    keys = sorted(set(current) | set(previous))
    changed=[]
    for key in keys:
        if current.get(key) != previous.get(key):
            changed.append(key)
    return changed


@app.get("/api/system/operations")
def system_operations(
    _: str = Depends(require_permission("system", "admin")),
):
    current, fingerprint = _safe_dashboard_config()
    snapshots = list_config_snapshots(20)
    for row in snapshots:
        row["changed_sections"] = _config_diff(current, row.get("config", {}))
        row["matches_current"] = row.get("fingerprint") == fingerprint

    try:
        conflicts = spam_conflict_summary(limit=50)
        conflict_state = {
            "ok": True,
            "total": conflicts.get("total", 0),
            "items": conflicts.get("items", []),
            "truncated": conflicts.get("truncated", False),
        }
    except Exception:
        logger.exception("SpamAssassin conflict scan failed")
        conflict_state = {"ok": False, "total": 0, "items": [], "truncated": False}

    mail_size = {"available": False, "backup_count": 0, "latest_backup": None}
    try:
        helper = _mail_size_api_request("GET")
        backups = helper.get("backups", []) if isinstance(helper, dict) else []
        mail_size = {
            "available": True,
            "backup_count": len(backups),
            "latest_backup": backups[0] if backups else None,
        }
    except Exception:
        pass

    return {
        "config": current,
        "config_fingerprint": fingerprint,
        "snapshots": snapshots,
        "spam_conflicts": conflict_state,
        "mail_size_backups": mail_size,
    }


@app.post("/api/system/config-snapshots")
def system_config_snapshot(
    request: Request,
    payload: dict,
    username: str = Depends(require_permission("system", "admin")),
):
    label = str(payload.get("label", "Manual snapshot")).strip()[:255]
    current, fingerprint = _safe_dashboard_config()
    result = create_config_snapshot(username, label, current)
    quarantine_write_audit(
        "CONFIG_SNAPSHOT_CREATE",
        f'config:{result["id"]}',
        request.client.host if request.client else "",
        username,
        detail=f'label={label} fingerprint={fingerprint}',
    )
    return {"ok": True, **result, "current_fingerprint": fingerprint}




HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Postfix Delivery Dashboard</title>
<style>
:root{--bg:#f5f7fb;--panel:#fff;--text:#0f172a;--muted:#64748b;--line:#e2e8f0;--nav:#0f172a;--accent:#2563eb;--radius:12px;--shadow:0 8px 24px rgba(15,23,42,.06)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:linear-gradient(135deg,#0f172a,#1e293b);color:#fff;padding:20px 28px;box-shadow:0 4px 14px rgba(15,23,42,.18)}header h2{margin:0;font-size:22px}
main{padding:22px;max-width:1800px;margin:auto}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px;background:#fff;padding:8px;border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}
.tabbtn{border:0;background:transparent;color:#475569;padding:10px 16px;font-weight:600;border-radius:8px;cursor:pointer}.tabbtn.active{background:var(--nav);color:#fff}.tabpane{display:none}.tabpane.active{display:block}
.cards,.summary-grid,.qcards{display:grid;gap:12px}.cards{grid-template-columns:repeat(8,minmax(120px,1fr))}.summary-grid{grid-template-columns:repeat(6,minmax(150px,1fr))}.qcards{grid-template-columns:repeat(4,minmax(150px,1fr));margin:12px 0}
.card,.summary-card,.qcard,.summary-note,.qdomains,.qmail{background:#fff;border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}
.card,.summary-card,.qcard{padding:14px 16px}.card{cursor:pointer}.card.active{outline:2px solid var(--accent)}.card b,.summary-card b,.qcard b{display:block;margin-top:5px;font-size:24px}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:14px 0;padding:12px;background:#fff;border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}
input,select,button,a{min-height:38px;padding:9px 11px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;color:var(--text);text-decoration:none;font:inherit}input{flex:1;min-width:240px}button,a{font-weight:600;cursor:pointer}button:disabled{opacity:.45;cursor:not-allowed}
.wrap,.summary-table-wrap,.audit-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}.wrap{max-height:72vh}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13px}th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{position:sticky;top:0;background:#f8fafc;color:#334155;font-size:12px;z-index:2}tbody tr:hover{background:#f8fafc}
.delivery-compact{min-width:1040px}.delivery-host{max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.delivery-detail{max-width:300px;overflow:hidden;text-overflow:ellipsis}.delivery-meta{border-bottom:1px dotted #94a3b8;cursor:help}
.rc{position:relative}.more{padding:2px 7px;border-radius:999px;background:#e2e8f0;font-size:11px}.tip{display:none;position:absolute;z-index:30;left:0;top:22px;min-width:420px;max-width:700px;background:#0f172a;color:#e2e8f0;border-radius:10px;padding:10px}.rc:hover .tip{display:block}
.pager{display:flex;justify-content:center;align-items:center;gap:10px;margin-top:14px}.summary-note,.qdomains{padding:13px 15px}.summary-section{margin-top:18px}.summary-table td.num{text-align:right}.summary-table tr.total-row td{font-weight:700;background:#f8fafc}
.qmail-list{display:grid;gap:12px}.qmail{padding:15px 16px}.qmail-top{display:flex;justify-content:space-between;gap:12px}.qmail-type{font-weight:700}.qmail-time{color:var(--muted);font-size:12px}.qmail-line{margin:5px 0}.qmail-subject{font-weight:700;margin:9px 0}.qmail-bottom{display:flex;gap:10px 14px;align-items:center;flex-wrap:wrap}
.qrelease-status{margin-top:7px;display:grid;gap:2px;font-size:11px;line-height:1.35;color:#475569}.qrelease-status b{color:#0f172a;font-size:11px;text-transform:uppercase;letter-spacing:.04em}.qcorrect{margin-top:6px;white-space:nowrap}
.qauth,.qscore,.qstate{display:inline-flex;padding:4px 8px;border-radius:999px;font-size:12px;font-weight:700}.qauth{background:#f1f5f9}.qscore{background:#eff6ff;color:#1d4ed8}.qstate{background:#f1f5f9}.qstate.released{background:#dcfce7;color:#15803d}.qstate.flagged{background:#fef3c7;color:#b45309}
.audit-table{min-width:1050px}.audit-action,.audit-ip{font-weight:700}#msg,#qMessage,#auditMessage{margin:8px 0 10px;color:var(--muted);font-size:13px}
@media(max-width:1200px){.cards{grid-template-columns:repeat(4,minmax(120px,1fr))}.summary-grid{grid-template-columns:repeat(3,minmax(150px,1fr))}}
@media(max-width:760px){main{padding:14px}.cards,.summary-grid,.qcards{grid-template-columns:repeat(2,minmax(130px,1fr))}.controls{align-items:stretch}input,select,button,a{width:100%}.qmail-top{flex-direction:column}}

.qnote{margin-bottom:14px;border-left:4px solid #2563eb}
.qcard:nth-child(1){background:linear-gradient(180deg,#ffffff 0%,#f8fafc 100%)}
.qcard:nth-child(2){background:linear-gradient(180deg,#fffaf0 0%,#fffbeb 100%);border-color:#fcd34d}
.qcard:nth-child(3){background:linear-gradient(180deg,#fff5f5 0%,#fef2f2 100%);border-color:#fca5a5}
.qcard:nth-child(4){background:linear-gradient(180deg,#faf5ff 0%,#f5f3ff 100%);border-color:#c4b5fd}
.qmail{position:relative}
.qmail.spam-card{border-left:5px solid #f59e0b;background:linear-gradient(180deg,#ffffff 0%,#fffbeb 100%)}
.qmail.virus-card{border-left:5px solid #dc2626;background:linear-gradient(180deg,#ffffff 0%,#fef2f2 100%)}
.qmail.banned-card{border-left:5px solid #7c3aed;background:linear-gradient(180deg,#ffffff 0%,#f5f3ff 100%)}
.qmail-header{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.qmail-type{display:inline-flex;align-items:center;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700}
.qmail-type.spam-card{background:#fef3c7;color:#92400e}
.qmail-type.virus-card{background:#fee2e2;color:#991b1b}
.qmail-type.banned-card{background:#ede9fe;color:#5b21b6}
.qid{font-size:11px;color:#64748b;margin-top:4px;word-break:break-all}
.qgrid{display:grid;grid-template-columns:1fr;gap:8px;margin:10px 0}
.qfield{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px}
.qlabel{display:block;font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:#64748b;font-weight:700;margin-bottom:4px}
.qsubject{font-weight:700;font-size:14px;line-height:1.45;margin:6px 0}
.qauth.pass{background:#dcfce7;color:#166534}
.qauth.fail{background:#fee2e2;color:#991b1b}
.qauth.softfail{background:#fef3c7;color:#92400e}
.qauth.none{background:#e2e8f0;color:#334155}
.qscore.low{background:#eff6ff;color:#1d4ed8}
.qscore.medium{background:#fef3c7;color:#92400e}
.qscore.high{background:#fee2e2;color:#991b1b}
.qactions button:first-child{background:#166534;color:#fff;border-color:#166534}
.qactions button:first-child:hover{background:#15803d}
.qactions button:last-child{background:#b45309;color:#fff;border-color:#b45309}
.qactions button:last-child:hover{background:#c2410c}
.qactions button:disabled{background:#e2e8f0;color:#64748b;border-color:#cbd5e1}


/* v9.8.8 compact professional quarantine */
#quarantineTab .qnote{margin:0 0 14px;padding:11px 14px;border-left:4px solid #2563eb;background:#eff6ff;color:#1e3a8a}
#quarantineTab .qmail-list{display:grid;gap:8px}
#quarantineTab .qmail{display:grid;grid-template-columns:44px 180px minmax(360px,1fr) 150px 130px 180px;gap:0;align-items:stretch;min-height:126px;padding:0;overflow:hidden;border:1px solid #dbe3ee;border-radius:0;background:#fff;box-shadow:none}
#quarantineTab .qside{display:flex;flex-direction:column;justify-content:center;align-items:center;gap:5px;padding:12px 8px;text-align:center;border-right:1px solid #e2e8f0}
#quarantineTab .qside.spam-card{background:#fff7ed;color:#c2410c}
#quarantineTab .qside.virus-card{background:#fef2f2;color:#b91c1c}
#quarantineTab .qside.banned-card{background:#f5f3ff;color:#6d28d9}
#quarantineTab .qcat{font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.04em}
#quarantineTab .qmail-main{min-width:0;padding:12px 14px;border-right:1px solid #e2e8f0}
#quarantineTab .qsubject{margin:0 0 7px;font-size:14px;font-weight:750;line-height:1.3;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
#quarantineTab .qmeta{display:grid;gap:3px;color:#475569;font-size:12px}
#quarantineTab .qmeta-row{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
#quarantineTab .qid{margin-top:5px;font-size:10px;color:#94a3b8;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
#quarantineTab .qauthbox,#quarantineTab .qscorebox,#quarantineTab .qactionbox{display:flex;flex-direction:column;justify-content:center;gap:7px;padding:10px 12px;border-right:1px solid #e2e8f0}
#quarantineTab .qactionbox{border-right:0}
#quarantineTab .qauthline{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:11px;color:#475569}
#quarantineTab .qauth{min-width:58px;justify-content:center;padding:3px 7px}
#quarantineTab .qscorebox{
  align-items:center;
  text-align:center;
  justify-content:center;
  background:#f8fafc;
  min-width:0;
}
#quarantineTab .qscorelabel{
  display:block;
  white-space:nowrap;
  font-weight:800;
}
#quarantineTab .qscore{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-width:64px;
}
#quarantineTab .qscorelabel{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.04em}
#quarantineTab .qscore{font-size:16px;padding:5px 9px}
#quarantineTab .qactions{display:grid;grid-template-columns:1fr;gap:7px}
#quarantineTab .qactions button{width:100%;min-height:34px;padding:7px 9px;font-size:11px}
#quarantineTab .qactions button:first-child{background:#166534;color:#fff;border-color:#166534}
#quarantineTab .qactions button:last-child{background:#b45309;color:#fff;border-color:#b45309}
@media(max-width:900px){
  #quarantineTab .qmail{grid-template-columns:90px 1fr}
  #quarantineTab .qauthbox,#quarantineTab .qscorebox,#quarantineTab .qactionbox{grid-column:2;border-right:0;border-top:1px solid #e2e8f0;flex-direction:row;align-items:center}
  #quarantineTab .qactions{grid-template-columns:1fr 1fr;width:100%}
}

/* v9.8.9 reference-inspired enterprise UI */
body{background:#eef3f8}
.app-shell{display:flex;min-height:100vh}
.sidebar{
  width:270px;position:fixed;inset:0 auto 0 0;
  background:linear-gradient(180deg,#0f213d 0%,#102c50 100%);
  color:#fff;display:flex;flex-direction:column;z-index:100;
  box-shadow:8px 0 26px rgba(15,23,42,.12)
}
.brand{display:flex;align-items:center;gap:14px;padding:20px 18px;border-bottom:1px solid rgba(255,255,255,.13)}
.brand-mark{
  width:46px;height:46px;border:2px solid #dbeafe;border-radius:12px;
  display:grid;place-items:center;font-size:23px;color:#fff
}
.brand-title{font-weight:750;font-size:17px}.brand-subtitle{font-size:12px;color:#cbd5e1;margin-top:3px}
.side-nav{padding:18px 10px;display:grid;gap:7px}
.side-nav .tabbtn{
  width:100%;display:flex;align-items:center;gap:13px;
  background:transparent;color:#e5edf8;border:0;text-align:left;
  padding:13px 15px;border-radius:9px;font-weight:600
}
.side-nav .tabbtn:hover{background:rgba(255,255,255,.07);color:#fff}
.side-nav .tabbtn.active{
  background:linear-gradient(90deg,#2563eb,#7c3aed);
  color:#fff;box-shadow:0 8px 22px rgba(37,99,235,.28)
}
.nav-icon{width:24px;text-align:center;font-size:20px}
.sidebar-foot{margin-top:auto;padding:18px;color:#dbeafe;font-size:12px}
.side-status{color:#86efac;font-weight:700;margin-bottom:8px}
.content-shell{margin-left:270px;width:calc(100% - 270px)}
.content-shell main{max-width:none;padding:0 28px 28px}
.page-head{
  min-height:92px;display:flex;justify-content:space-between;align-items:center;
  border-bottom:1px solid #dbe3ee;margin:0 -28px 22px;padding:0 28px;background:#fff
}
.page-head h2{margin:0;font-size:25px}.page-subtitle{color:#475569;margin-top:4px}
.page-head-actions{display:flex;align-items:center;gap:16px}
.icon-btn{border:0;background:transparent;font-size:25px;color:#475569}
.auto-pill{display:flex;align-items:center;gap:10px;color:#475569}
.auto-pill b{background:#16a34a;color:#fff;border-radius:999px;padding:6px 12px;font-size:11px}
.qhero{display:grid;grid-template-columns:repeat(4,minmax(155px,1fr)) 1.35fr;gap:18px;margin-bottom:18px}
.qmetric{
  min-height:110px;background:#fff;border:1px solid #dbe3ee;border-radius:10px;
  padding:18px;display:flex;align-items:center;gap:14px;box-shadow:0 4px 14px rgba(15,23,42,.035)
}
.qmetric.total{border-color:#93c5fd}.qmetric.spam{border-color:#fca5a5}.qmetric.virus{border-color:#fdba74}.qmetric.banned{border-color:#c4b5fd}
.metric-icon{
  width:50px;height:50px;border-radius:50%;display:grid;place-items:center;
  color:#fff;font-size:23px;font-weight:700;flex:0 0 auto
}
.qmetric.total .metric-icon{background:#2563eb}
.qmetric.spam .metric-icon{background:#ef4444}
.qmetric.virus .metric-icon{background:#f59e0b}
.qmetric.banned .metric-icon{background:#7c3aed}
.qmetric.updated .metric-icon{background:#fff;color:#2563eb;border:2px solid #bfdbfe}
.qmetric span{display:block;color:#475569;font-size:13px}
.qmetric b{display:block;font-size:27px;line-height:1.1;margin:3px 0;color:#0f172a}
.qmetric.updated b{font-size:14px;white-space:nowrap}
.qmetric small{display:block;color:#64748b;font-size:11px;line-height:1.35}
.qtoolbar{
  display:grid;grid-template-columns:minmax(320px,1fr) 180px auto auto;
  gap:14px;align-items:end;background:#fff;border:1px solid #dbe3ee;
  border-radius:10px;padding:16px 18px;margin-bottom:16px
}
.qsearch-wrap input{width:100%;min-width:0}
.filter-group{display:grid;gap:6px}.filter-group label{font-size:12px;color:#475569;font-weight:700}
.primary-btn{background:#2563eb;color:#fff;border-color:#2563eb}
.secondary-btn{background:#fff;color:#1d4ed8;border-color:#93c5fd}
.section-message{margin:0 0 10px;color:#64748b;font-size:12px}
#quarantineTab .qmail-list{display:grid;gap:8px}
#quarantineTab .qmail{
  display:grid;grid-template-columns:122px minmax(360px,1.8fr) 190px 170px 180px;
  min-height:126px;padding:0;border:1px solid #dbe3ee;border-radius:10px;
  background:#fff;overflow:hidden;box-shadow:none
}
#quarantineTab .qside{
  display:flex;flex-direction:column;justify-content:center;align-items:center;
  padding:12px 8px;border-right:1px solid #e2e8f0;text-align:center
}
#quarantineTab .qside.spam-card{background:#fff1f2;color:#e11d48}
#quarantineTab .qside.virus-card{background:#fff7ed;color:#f59e0b}
#quarantineTab .qside.banned-card{background:#f5f3ff;color:#7c3aed}
/* Security row distinction: BANNED and VIRUS retain separate visual states. */
#quarantineTab .qmail:has(.qside.banned-card){
  background:#fff7ed;
  border-color:#f59e0b;
  box-shadow:inset 5px 0 0 #d97706,0 1px 2px rgba(15,23,42,.08);
}
#quarantineTab .qmail:has(.qside.banned-card):hover{background:#ffedd5}
#quarantineTab .qmail:has(.qside.virus-card){
  background:#fef2f2;
  border-color:#ef4444;
  box-shadow:inset 5px 0 0 #b91c1c,0 1px 2px rgba(15,23,42,.08);
}
#quarantineTab .qmail:has(.qside.virus-card):hover{background:#fee2e2}
#quarantineTab .qmail:has(.qside.banned-card) .qmail-main,
#quarantineTab .qmail:has(.qside.banned-card) .qauthbox,
#quarantineTab .qmail:has(.qside.banned-card) .qscorebox,
#quarantineTab .qmail:has(.qside.banned-card) .qactionbox{background:transparent}
#quarantineTab .qmail:has(.qside.virus-card) .qmail-main,
#quarantineTab .qmail:has(.qside.virus-card) .qauthbox,
#quarantineTab .qmail:has(.qside.virus-card) .qscorebox,
#quarantineTab .qmail:has(.qside.virus-card) .qactionbox{background:transparent}
#quarantineTab .qcat{font-weight:800;font-size:13px;margin-bottom:6px}
#quarantineTab .qmail-time{font-size:11px;color:#475569;line-height:1.4}
#quarantineTab .qmail-main{padding:14px 18px;border-right:1px solid #e2e8f0;min-width:0}
#quarantineTab .qsubject{font-size:15px;font-weight:750;margin:0 0 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#quarantineTab .qmeta{display:grid;gap:4px;font-size:12px;color:#475569}
#quarantineTab .qmeta-row{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#quarantineTab .qid{display:inline-block;margin-top:7px;padding:3px 8px;border-radius:6px;background:#eef2f7;color:#475569;font-size:10px;max-width:100%;overflow:hidden;text-overflow:ellipsis}
#quarantineTab .qauthbox,#quarantineTab .qscorebox,#quarantineTab .qactionbox{
  display:flex;flex-direction:column;justify-content:center;gap:10px;padding:12px 14px;
  border-right:1px solid #e2e8f0
}
#quarantineTab .qactionbox{border-right:0}
#quarantineTab .qauthline{display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#475569}
#quarantineTab .qauth{min-width:54px;justify-content:center;border-radius:6px;padding:4px 7px}
#quarantineTab .qscorebox{align-items:center;text-align:center}
#quarantineTab .qscorelabel{font-size:11px;color:#64748b}
#quarantineTab .qscore{font-size:18px;font-weight:800;background:transparent;padding:0}
#quarantineTab .qscore.high{color:#dc2626}#quarantineTab .qscore.medium{color:#f59e0b}#quarantineTab .qscore.low{color:#2563eb}
#quarantineTab .qstate{font-size:10px;border-radius:999px;padding:4px 8px}
#quarantineTab .qactions{display:grid;gap:8px}
#quarantineTab .qactions button{min-height:38px;width:100%;font-size:11px;border-radius:7px}
#quarantineTab .qactions button:first-child{background:#fff;color:#16a34a;border:1px solid #86efac}
#quarantineTab .qactions button:last-child{background:#fff;color:#dc2626;border:1px solid #fca5a5}
.qfooterbar{display:flex;justify-content:space-between;align-items:center;margin:14px 0;color:#475569;font-size:12px}
.qfooterbar .pager{margin:0}
.info-note{
  display:flex;gap:12px;align-items:flex-start;background:#fff;border:1px solid #93c5fd;
  border-radius:10px;padding:14px 16px;color:#334155
}
.info-icon{width:22px;height:22px;border:1px solid #2563eb;color:#2563eb;border-radius:50%;display:grid;place-items:center;font-weight:700}
.info-note b{color:#1d4ed8}.info-note div div{font-size:12px;line-height:1.45}
.qdomains{margin-top:14px}
@media(max-width:1450px){
  .qhero{grid-template-columns:repeat(3,1fr)}
  .qmetric.updated{grid-column:span 2}
  .qtoolbar{grid-template-columns:1fr 170px 170px}
  .qtoolbar button{width:auto}
  #quarantineTab .qmail{grid-template-columns:110px minmax(300px,1fr) 160px 150px 160px}
}
@media(max-width:1050px){
  .sidebar{width:220px}.content-shell{margin-left:220px;width:calc(100% - 220px)}
  .brand-title{font-size:15px}
  #quarantineTab .qmail{grid-template-columns:100px 1fr}
  #quarantineTab .qauthbox,#quarantineTab .qscorebox,#quarantineTab .qactionbox{grid-column:2;border-top:1px solid #e2e8f0;border-right:0;flex-direction:row;align-items:center}
  #quarantineTab .qactions{grid-template-columns:1fr 1fr;width:100%}
}

/* v9.9.2 responsive sidebar + pin/unpin */
.sidebar{
  transition:width .22s ease,transform .22s ease;
}
.brand{position:relative}
.brand-copy{min-width:0;transition:opacity .18s ease,width .18s ease}
.sidebar-pin{
  margin-left:auto;
  width:34px;height:34px;min-height:34px;
  padding:0;border:1px solid rgba(255,255,255,.18);
  background:rgba(255,255,255,.08);
  color:#fff;border-radius:8px;
  display:grid;place-items:center;
  font-size:15px;cursor:pointer;flex:0 0 auto
}
.sidebar-pin:hover{background:rgba(255,255,255,.14)}
.content-shell{transition:margin-left .22s ease,width .22s ease}
.mobile-menu-btn{
  display:none;position:fixed;top:14px;left:14px;z-index:120;
  width:42px;height:42px;min-height:42px;padding:0;
  border:1px solid #cbd5e1;background:#fff;color:#0f172a;
  box-shadow:0 6px 18px rgba(15,23,42,.12)
}
.sidebar-backdrop{display:none}

/* desktop collapsed/unpinned rail */
body.sidebar-collapsed .sidebar{width:78px}
body.sidebar-collapsed .content-shell{
  margin-left:78px;
  width:calc(100% - 78px)
}
body.sidebar-collapsed .brand{justify-content:center;padding:18px 8px}
body.sidebar-collapsed .brand-mark{width:42px;height:42px}
body.sidebar-collapsed .brand-copy{display:none}
body.sidebar-collapsed .sidebar-pin{
  position:absolute;top:8px;right:-15px;
  width:30px;height:30px;min-height:30px;
  background:#2563eb;border-color:#93c5fd
}
body.sidebar-collapsed .side-nav{padding:18px 8px}
body.sidebar-collapsed .side-nav .tabbtn{
  justify-content:center;padding:13px 8px
}
body.sidebar-collapsed .side-nav .tabbtn span:last-child{display:none}
body.sidebar-collapsed .nav-icon{font-size:22px}
body.sidebar-collapsed .sidebar-foot{display:none}

/* better fluid content */
.content-shell main{width:100%;overflow-x:hidden}
.cards{grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}
.summary-grid{grid-template-columns:repeat(3,minmax(180px,260px));justify-content:start;align-items:stretch;gap:10px;max-width:800px}
#summaryTab .summary-card{padding:10px 12px;min-height:58px}
#summaryTab .summary-card b{font-size:20px;margin-top:3px}
#summaryTab .summary-note{max-width:800px;margin-top:10px;padding:9px 12px}
#summaryTab .summary-section{margin-top:12px}
@media(max-width:900px){.summary-grid{grid-template-columns:repeat(2,minmax(160px,1fr));max-width:none}}
@media(max-width:560px){.summary-grid{grid-template-columns:1fr}}
.qhero{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.qtoolbar{grid-template-columns:minmax(260px,1.5fr) minmax(150px,.6fr) auto auto}
.wrap,.summary-table-wrap,.audit-wrap{max-width:100%}
.delivery-compact{min-width:940px}
#quarantineTab .qmail{
  grid-template-columns:110px minmax(280px,1.7fr) minmax(140px,.75fr) minmax(125px,.65fr) minmax(145px,.75fr)
}

/* tablet */
@media(max-width:1180px){
  .qtoolbar{
    grid-template-columns:minmax(260px,1fr) 1fr 1fr;
  }
  .qtoolbar .primary-btn,
  .qtoolbar .secondary-btn{width:100%}
  #quarantineTab .qmail{
    grid-template-columns:100px minmax(250px,1fr) 150px 140px
  }
  #quarantineTab .qactionbox{
    grid-column:2 / -1;
    border-top:1px solid #e2e8f0;
    border-right:0
  }
  #quarantineTab .qactions{
    grid-template-columns:1fr 1fr
  }
}

/* mobile/tablet drawer behavior */
@media(max-width:820px){
  .sidebar{
    width:270px !important;
    transform:translateX(-100%);
    box-shadow:14px 0 35px rgba(15,23,42,.28)
  }
  body.sidebar-mobile-open .sidebar{transform:translateX(0)}
  body.sidebar-collapsed .sidebar{width:270px}
  .content-shell,
  body.sidebar-collapsed .content-shell{
    margin-left:0;
    width:100%
  }
  .mobile-menu-btn{display:grid;place-items:center}
  body.sidebar-mobile-open .sidebar-backdrop{
    display:block;position:fixed;inset:0;
    background:rgba(15,23,42,.46);z-index:90
  }
  .sidebar{z-index:110}
  .sidebar-pin{display:none}
  .brand-copy,
  body.sidebar-collapsed .brand-copy{display:block}
  .side-nav .tabbtn span:last-child,
  body.sidebar-collapsed .side-nav .tabbtn span:last-child{display:inline}
  .content-shell main{padding:66px 14px 18px}
  .page-head{
    margin:0 -14px 16px;
    padding:14px 14px 14px 64px;
    min-height:74px;
    align-items:flex-start;
    gap:10px
  }
  .page-head h2{font-size:20px}
  .page-head-actions{gap:8px}
  .auto-pill span{display:none}
  .qhero{grid-template-columns:repeat(2,minmax(140px,1fr));gap:10px}
  .qmetric{min-height:88px;padding:12px}
  .metric-icon{width:42px;height:42px;font-size:18px}
  .qtoolbar{grid-template-columns:1fr}
  #quarantineTab .qmail{
    grid-template-columns:84px 1fr
  }
  #quarantineTab .qauthbox,
  #quarantineTab .qscorebox,
  #quarantineTab .qactionbox{
    grid-column:2;
    border-right:0;
    border-top:1px solid #e2e8f0;
    flex-direction:row;
    align-items:center;
    justify-content:flex-start
  }
  #quarantineTab .qactions{
    width:100%;grid-template-columns:1fr 1fr
  }
  .qfooterbar{align-items:flex-start;gap:10px;flex-direction:column}
  .qfooterbar .pager{width:100%;justify-content:flex-start}
}

/* small phones */
@media(max-width:520px){
  .qhero{grid-template-columns:1fr}
  .qmetric.updated{grid-column:auto}
  #quarantineTab .qmail{
    display:block
  }
  #quarantineTab .qside{
    min-height:60px;border-right:0;border-bottom:1px solid #e2e8f0;
    flex-direction:row;justify-content:space-between;padding:10px 12px
  }
  #quarantineTab .qmail-main{border-right:0}
  #quarantineTab .qauthbox,
  #quarantineTab .qscorebox,
  #quarantineTab .qactionbox{
    display:flex;border-top:1px solid #e2e8f0;padding:10px 12px
  }
  #quarantineTab .qactions{grid-template-columns:1fr}
  .summary-grid,.cards{grid-template-columns:1fr 1fr}
  .delivery-compact{min-width:840px}
}

/* v9.9.3 quarantine KPI category filters */
.qmetric-static{cursor:default!important;user-select:text}
.qmetric-static:hover{transform:none!important;box-shadow:none!important}
.qmetric-filter{
  appearance:none;
  text-align:left;
  cursor:pointer;
  width:100%;
  min-height:110px;
  color:inherit;
  font:inherit;
  transition:transform .16s ease,box-shadow .16s ease,border-color .16s ease;
}
.qmetric-filter:hover{
  transform:translateY(-1px);
  box-shadow:0 8px 20px rgba(15,23,42,.08);
}
.qmetric-filter.active{
  box-shadow:0 0 0 3px rgba(37,99,235,.16),0 8px 20px rgba(15,23,42,.08);
}
.qmetric-filter.total.active{border-color:#2563eb}
.qmetric-filter.spam.active{border-color:#ef4444}
.qmetric-filter.virus.active{border-color:#f59e0b}
.qmetric-filter.banned.active{border-color:#7c3aed}

.queue-link{border:0;background:transparent;padding:0;min-height:0;color:#2563eb;font-weight:800;text-decoration:underline;cursor:pointer}
.status-grid{display:grid;grid-template-columns:repeat(3,minmax(180px,1fr));gap:12px}.status-card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:var(--shadow)}.status-card b{display:block;font-size:20px;margin-top:6px}.ok{color:#15803d}.bad{color:#b91c1c}
.flow-modal{display:none;position:fixed;inset:0;z-index:90;background:rgba(15,23,42,.45);padding:28px}.flow-modal.open{display:flex;justify-content:flex-end}.flow-panel{width:min(760px,100%);height:100%;overflow:auto;background:#fff;border-radius:14px;padding:20px;box-shadow:0 24px 60px rgba(15,23,42,.3)}.flow-head{display:flex;justify-content:space-between;align-items:center;gap:12px}.flow-event{border-left:4px solid #cbd5e1;padding:10px 12px;margin:12px 0;background:#f8fafc;border-radius:8px}.flow-event pre{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;padding:10px;border-radius:8px;font-size:11px}.logout-btn{width:100%;margin-top:8px;background:#1e293b;color:#fff;border-color:#334155}
@media(max-width:900px){.status-grid{grid-template-columns:1fr}.flow-modal{padding:0}.flow-panel{border-radius:0}}

/* Milestone 4 quarantine metadata + optional multi-select enhancement */
#quarantineTab .qmail-main{
  display:flex;
  flex-direction:column;
  justify-content:center;
}
#quarantineTab .qdetails{
  display:grid;
  grid-template-columns:58px minmax(0,1fr);
  column-gap:8px;
  row-gap:4px;
  font-size:12px;
  line-height:1.35;
}
#quarantineTab .qdetails-label{
  color:#64748b;
  font-weight:750;
}
#quarantineTab .qdetails-value{
  min-width:0;
  color:#334155;
  overflow-wrap:anywhere;
}
#quarantineTab .qdetails-subject{
  font-weight:650;
  color:#0f172a;
  display:-webkit-box;
  -webkit-line-clamp:2;
  -webkit-box-orient:vertical;
  overflow:hidden;
}
#quarantineTab .qdetails-id{
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:10px;
  color:#64748b;
}
#quarantineTab .qselect-wrap{
  display:flex;
  align-items:center;
  justify-content:center;
  gap:6px;
  margin-top:7px;
  padding:4px 6px;
  border:1px solid rgba(100,116,139,.28);
  border-radius:6px;
  background:rgba(255,255,255,.72);
  font-size:10px;
  font-weight:700;
  color:#475569;
  cursor:pointer;
}
#quarantineTab .qselect-item{
  width:16px;
  min-width:16px;
  height:16px;
  min-height:16px;
  flex:none;
  padding:0;
  margin:0;
  cursor:pointer;
  appearance:auto;
}
#quarantineTab .qselect-item:disabled{
  cursor:not-allowed;
  opacity:.45;
}
#quarantineTab .qbulkbar{
  display:flex;
  align-items:center;
  gap:12px;
  flex-wrap:wrap;
  padding:10px 12px;
  margin:0 0 10px;
  border:1px solid #dbe3ee;
  border-radius:10px;
  background:#fff;
}
#quarantineTab .qbulkselect{
  display:flex;
  align-items:center;
  gap:7px;
  font-size:12px;
  font-weight:650;
  color:#334155;
  white-space:nowrap;
}
#quarantineTab .qbulkselect input{
  width:16px;
  min-width:16px;
  height:16px;
  min-height:16px;
  flex:none;
  padding:0;
  margin:0;
  appearance:auto;
}
#quarantineTab .qselected-count{
  font-size:12px;
  color:#475569;
  min-width:78px;
}
#quarantineTab .qbulk-actions{
  display:flex;
  align-items:center;
  gap:8px;
}
#quarantineTab .qbulk-actions button{
  width:auto;
  min-height:32px;
  padding:7px 11px;
  font-size:11px;
}
#quarantineTab .qbulk-release{
  color:#166534;
  border-color:#86efac;
  background:#f0fdf4;
}
#quarantineTab .qbulk-spam{
  background:#b45309;
  border-color:#b45309;
}
#quarantineTab .qbulk-result{
  margin-left:auto;
  font-size:12px;
  color:#475569;
}
@media(max-width:900px){
  #quarantineTab .qbulk-actions{width:100%}
  #quarantineTab .qbulk-actions button{flex:1}
  #quarantineTab .qbulk-result{margin-left:0;width:100%}
}


/* Milestone 6 baseline: exact five-column quarantine alignment */
#quarantineTab .qlist-head{
  display:grid;
  grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px;
  align-items:center;
  min-height:44px;
  background:#0f2f52;
  color:#fff;
  border:1px solid #0f2f52;
  border-radius:9px 9px 0 0;
  font-size:12px;
  font-weight:800;
}
#quarantineTab .qlist-head>div{padding:12px 16px}
#quarantineTab .qmail-list{
  display:grid;
  gap:0;
  border-left:1px solid #dbe3ee;
  border-right:1px solid #dbe3ee;
}
#quarantineTab .qmail{
  display:grid !important;
  grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px !important;
  gap:0 !important;
  align-items:stretch;
  min-height:126px;
  padding:0 !important;
  overflow:hidden;
  border:0 !important;
  border-bottom:1px solid #dbe3ee !important;
  border-radius:0 !important;
  background:#fff;
  box-shadow:none !important;
}
#quarantineTab .qside{
  position:relative;
  display:flex;
  flex-direction:column;
  justify-content:flex-start;
  align-items:flex-start;
  gap:7px;
  padding:18px 16px 14px 48px;
  text-align:left;
  border-right:1px solid #e2e8f0;
  min-width:0;
}
#quarantineTab .qrow-select{
  position:absolute;
  left:18px;
  top:50%;
  transform:translateY(-50%);
  display:flex;
  align-items:center;
  justify-content:center;
  margin:0;
  padding:0;
}
#quarantineTab .qselect-item{
  width:16px !important;
  min-width:16px !important;
  height:16px !important;
  min-height:16px !important;
  padding:0 !important;
  margin:0 !important;
  flex:none !important;
  appearance:auto;
}
#quarantineTab .qcat{
  font-size:12px;
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:.04em;
}
#quarantineTab .qmail-time{
  font-size:11px;
  line-height:1.45;
  color:#475569;
}
#quarantineTab .qmail-main{
  min-width:0;
  display:flex;
  flex-direction:column;
  justify-content:center;
  padding:14px 18px;
  border-right:1px solid #e2e8f0;
}
#quarantineTab .qdetails{
  display:grid;
  grid-template-columns:72px minmax(0,1fr);
  column-gap:10px;
  row-gap:6px;
  font-size:12px;
  line-height:1.35;
  min-width:0;
}
#quarantineTab .qdetails-label{
  color:#0f172a;
  font-weight:800;
  white-space:nowrap;
}
#quarantineTab .qdetails-value{
  min-width:0;
  color:#0f172a;
}
#quarantineTab .qdetails-value:not(.qdetails-subject){
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
#quarantineTab .qdetails-subject{
  font-weight:700;
  color:#0f172a;
  display:-webkit-box;
  -webkit-line-clamp:2;
  -webkit-box-orient:vertical;
  overflow:hidden;
  line-height:1.4;
}
#quarantineTab .qdetails-id{
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:10px;
  color:#2563eb;
}
#quarantineTab .qheader-btn{
  width:max-content;
  max-width:100%;
  padding:3px 9px;
  min-height:26px;
  border:1px solid #bfdbfe;
  border-radius:6px;
  background:#eff6ff;
  color:#1d4ed8;
  font-size:11px;
  font-weight:700;
  cursor:pointer;
}
#quarantineTab .qheader-btn:hover{background:#dbeafe}
.qheader-modal{position:fixed;inset:0;z-index:31000;background:rgba(15,23,42,.68);display:none;align-items:center;justify-content:center;padding:3vh 3vw}
.qheader-modal.open{display:flex}
.qheader-panel{width:min(1100px,96vw);max-height:90vh;display:flex;flex-direction:column;background:#fff;border-radius:12px;box-shadow:0 24px 70px rgba(15,23,42,.35);overflow:hidden}
.qheader-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 18px;border-bottom:1px solid #dbe3ee}
.qheader-actions{display:flex;gap:8px}
.qheader-pre{margin:0;padding:18px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
#quarantineTab .qauthbox,
#quarantineTab .qscorebox,
#quarantineTab .qactionbox{
  min-width:0;
  display:flex;
  flex-direction:column;
  justify-content:center;
  gap:7px;
  padding:12px 14px;
  border-right:1px solid #e2e8f0;
}
#quarantineTab .qscorebox{
  align-items:center;
  text-align:center;
  background:#fff;
}
#quarantineTab .qactionbox{
  border-right:0;
}
#quarantineTab .qactions{
  display:grid;
  grid-template-columns:1fr;
  gap:8px;
  width:100%;
}
#quarantineTab .qactions button{
  width:100%;
  min-height:38px;
  padding:7px 9px;
  font-size:11px;
}
@media(max-width:900px){
  #quarantineTab .qlist-head{display:none}
  #quarantineTab .qmail{
    grid-template-columns:1fr !important;
    border:1px solid #dbe3ee !important;
    border-radius:9px !important;
    margin-bottom:8px;
  }
  #quarantineTab .qside,
  #quarantineTab .qmail-main,
  #quarantineTab .qauthbox,
  #quarantineTab .qscorebox,
  #quarantineTab .qactionbox{
    grid-column:1 !important;
    border-right:0;
    border-bottom:1px solid #e2e8f0;
  }
  #quarantineTab .qactionbox{border-bottom:0}
  #quarantineTab .qauthbox,
  #quarantineTab .qscorebox,
  #quarantineTab .qactionbox{
    flex-direction:row;
    align-items:center;
  }
  #quarantineTab .qactions{
    grid-template-columns:1fr 1fr;
  }
}


/* Milestone 5 Security Pack 1 R3 - Spam Score rule hover */
#quarantineTab .qscore-hover{
  position:relative;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  cursor:help;
  outline:none;
}
#quarantineTab .qscore-tooltip{
  display:none;
  position:absolute;
  z-index:120;
  right:calc(100% + 12px);
  top:50%;
  transform:translateY(-50%);
  width:max-content;
  min-width:420px;
  max-width:min(680px,70vw);
  overflow:hidden;
  border:1px solid #cbd5e1;
  border-radius:10px;
  background:#0f172a;
  color:#e2e8f0;
  box-shadow:0 18px 45px rgba(15,23,42,.28);
  text-align:left;
}
#quarantineTab .qscore-hover:hover .qscore-tooltip,
#quarantineTab .qscore-hover:focus .qscore-tooltip,
#quarantineTab .qscore-hover:focus-within .qscore-tooltip{
  display:block;
}
#quarantineTab .qscore-tooltip::after{
  content:"";
  position:absolute;
  left:100%;
  top:50%;
  transform:translateY(-50%);
  border:7px solid transparent;
  border-left-color:#0f172a;
}
#quarantineTab .qscore-tip-head{
  display:flex;
  justify-content:space-between;
  gap:18px;
  padding:10px 12px;
  border-bottom:1px solid #334155;
  background:#111827;
  font-size:11px;
  font-weight:800;
  white-space:nowrap;
}
#quarantineTab .qscore-tip-body{
  max-height:360px;
  overflow:auto;
  padding:8px 0;
}
#quarantineTab .qscore-tip-row{
  display:grid;
  grid-template-columns:minmax(250px,1fr) 18px minmax(60px,auto);
  align-items:baseline;
  column-gap:5px;
  padding:4px 12px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:12px;
  line-height:1.35;
  white-space:nowrap;
}
#quarantineTab .qscore-tip-row:hover{
  background:rgba(255,255,255,.07);
}
#quarantineTab .qscore-tip-rule{
  overflow:hidden;
  text-overflow:ellipsis;
  color:#f8fafc;
}
#quarantineTab .qscore-tip-eq{
  text-align:center;
  color:#94a3b8;
}
#quarantineTab .qscore-tip-value{
  text-align:right;
  color:#fde68a;
  font-variant-numeric:tabular-nums;
}
#quarantineTab .qscore-tooltip{width:min(520px,calc(100vw - 32px));max-height:70vh;overflow:auto;text-align:left}
#quarantineTab .qscore-intel-head{font-size:14px}
#quarantineTab .qscore-summary-grid{display:grid;grid-template-columns:1fr auto;gap:5px 18px;padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12px}
#quarantineTab .qscore-summary-grid span{color:#64748b}#quarantineTab .qscore-summary-grid b{color:#0f172a}
#quarantineTab .qscore-auth-row{display:flex;gap:7px;flex-wrap:wrap;padding:9px 12px;border-bottom:1px solid #e2e8f0}
#quarantineTab .qscore-auth{font-size:11px;padding:3px 6px;border-radius:999px;background:#f1f5f9;color:#334155}
#quarantineTab .qscore-section-title{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.04em;color:#475569;padding:9px 12px 4px}
#quarantineTab .qscore-all-tests{margin:8px 12px 12px;border-top:1px solid #e2e8f0;padding-top:8px}
#quarantineTab .qscore-all-tests summary{cursor:pointer;font-weight:700;font-size:12px;color:#1d4ed8}
#quarantineTab .qscore-all-tests[open] summary{margin-bottom:6px}
#quarantineTab .qscore-tip-empty{
  padding:12px;
  color:#cbd5e1;
  font-size:12px;
}
@media(max-width:900px){
  #quarantineTab .qscore-tooltip{
    position:fixed;
    left:16px;
    right:16px;
    top:50%;
    width:auto;
    min-width:0;
    max-width:none;
  }
  #quarantineTab .qscore-tooltip::after{display:none}
  #quarantineTab .qscore-tip-row{
    grid-template-columns:minmax(0,1fr) 18px minmax(55px,auto);
  }
}


/* Milestone 5 R4 - User ACL and Help */
.acl-note{
  margin:0 0 14px;
  padding:12px 14px;
  border:1px solid #bfdbfe;
  border-radius:10px;
  background:#eff6ff;
  color:#1e3a8a;
  font-size:13px;
}
.acl-table-wrap{
  overflow:auto;
  background:#fff;
  border:1px solid #dbe3ee;
  border-radius:10px;
  box-shadow:0 4px 14px rgba(15,23,42,.04);
}
.acl-table{min-width:1180px}
.acl-level{
  display:inline-flex;
  min-width:58px;
  justify-content:center;
  padding:4px 7px;
  border-radius:999px;
  font-size:11px;
  font-weight:800;
  text-transform:uppercase;
}
.acl-level.none{background:#f1f5f9;color:#64748b}
.acl-level.view{background:#dbeafe;color:#1d4ed8}
.acl-level.admin{background:#dcfce7;color:#166534}
.acl-status.active{color:#166534;font-weight:800}
.acl-status.disabled{color:#b91c1c;font-weight:800}
.acl-actions{display:flex;gap:6px;white-space:nowrap}
.acl-actions button{min-height:30px;padding:5px 8px;font-size:11px}
.acl-editor{
  position:fixed;
  inset:0;
  z-index:150;
  padding:30px;
  background:rgba(15,23,42,.5);
  overflow:auto;
}
.acl-editor[hidden]{display:none}
.acl-editor-card{
  width:min(820px,100%);
  margin:0 auto;
  padding:20px;
  background:#fff;
  border-radius:14px;
  box-shadow:0 24px 65px rgba(15,23,42,.32);
}
.acl-form-grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:12px;
  margin:18px 0;
}
.acl-form-grid label{font-size:12px;font-weight:800;color:#334155}
.acl-form-grid input:not([type=checkbox]){width:100%;min-width:0;margin-top:6px}
.acl-check{display:flex;align-items:center;gap:8px}
.acl-check input{width:16px;min-width:16px;height:16px;min-height:16px;flex:none}
.acl-permissions{
  border:1px solid #e2e8f0;
  border-radius:10px;
  overflow:hidden;
}
.acl-perm-head{padding:10px 12px;background:#f8fafc;font-size:12px;font-weight:800}
.acl-perm-row{
  display:grid;
  grid-template-columns:180px 1fr;
  align-items:center;
  gap:12px;
  padding:9px 12px;
  border-top:1px solid #e2e8f0;
}
.acl-perm-row select{width:100%;min-width:0}
.acl-editor-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
.help-grid{
  display:grid;
  grid-template-columns:repeat(3,minmax(240px,1fr));
  gap:14px;
}
.help-card{
  background:#fff;
  border:1px solid #dbe3ee;
  border-radius:11px;
  padding:17px;
  box-shadow:0 4px 14px rgba(15,23,42,.04);
}
.help-card h3{margin:0 0 8px;color:#0f2f52}
.help-card p{margin:0;color:#475569;font-size:13px;line-height:1.55}
.help-visual-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:0 0 18px}
.help-visual-tile{display:flex;align-items:center;gap:12px;width:100%;min-height:92px;padding:16px;border:1px solid #cbd5e1;border-radius:13px;background:#fff;color:#0f2f52;text-align:left;cursor:pointer;box-shadow:0 4px 14px rgba(15,23,42,.05)}
.help-visual-tile:hover{border-color:#93c5fd;background:#f8fbff;transform:translateY(-1px)}
.help-visual-icon{display:flex;align-items:center;justify-content:center;flex:0 0 42px;height:42px;border-radius:11px;background:#eef2ff;color:#4338ca;font-size:22px;font-weight:900}
.help-visual-copy b{display:block;font-size:14px}.help-visual-copy span{display:block;margin-top:4px;color:#64748b;font-size:12px;line-height:1.4}
.help-back-btn{white-space:nowrap}
@media(max-width:900px){.help-visual-grid{grid-template-columns:1fr}}
@media(max-width:900px){
  .acl-form-grid{grid-template-columns:1fr}
  .help-grid{grid-template-columns:1fr}
  .acl-editor{padding:12px}
}


/* Milestone 5 R5 - keep Spam Score hover above quarantine rows */
#quarantineTab .qmail-list{
  overflow:visible !important;
}
#quarantineTab .qmail{
  position:relative;
  overflow:visible !important;
  z-index:1;
}
#quarantineTab .qmail:hover,
#quarantineTab .qmail:focus-within{
  z-index:500;
}
#quarantineTab .qscorebox{
  position:relative;
  overflow:visible !important;
  z-index:2;
}
#quarantineTab .qscore-hover{
  position:relative;
  z-index:3;
}
#quarantineTab .qscore-hover:hover,
#quarantineTab .qscore-hover:focus,
#quarantineTab .qscore-hover:focus-within{
  z-index:1000;
}
#quarantineTab .qscore-tooltip{
  z-index:10000 !important;
  pointer-events:auto;
}


/* Milestone 5 R7 - clickable bounced summary drill-down */
.summary-count-link{
  min-height:0;
  padding:0;
  border:0;
  background:transparent;
  color:#2563eb;
  font-weight:800;
  text-decoration:underline;
  text-underline-offset:2px;
  cursor:pointer;
}
.summary-count-link:hover{color:#1d4ed8}
.summary-count-link:disabled{
  color:#94a3b8;
  text-decoration:none;
  cursor:default;
}

.address-detail-panel{width:min(1440px,calc(100% - 40px));max-height:88vh;overflow:auto;background:#fff;border-radius:14px;padding:18px}
.address-detail-table{min-width:1180px}
.address-detail-table td{vertical-align:top}
.bounce-detail-panel{
  width:min(1280px,calc(100% - 40px));
  max-height:88vh;
  overflow:auto;
  background:#fff;
  border-radius:14px;
  padding:18px;
  box-shadow:0 24px 70px rgba(15,23,42,.32);
}
.bounce-detail-wrap{max-height:62vh}
.bounce-detail-table{min-width:1050px}
.bounce-detail-table td:nth-child(1){white-space:nowrap}
.bounce-detail-table td:nth-child(2),
.bounce-detail-table td:nth-child(3){
  max-width:260px;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}
.bounce-detail-table td:nth-child(4){min-width:220px}
.bounce-detail-table td:nth-child(5){min-width:360px;white-space:normal}


/* Milestone 5 R8 - Excel-style text filters and Delivery top spacing */
#deliveryTab{
  padding-top:18px;
}
.text-filter-operator{
  min-width:150px;
  font-weight:700;
  background:#f8fafc;
}
.excel-filter-controls{
  align-items:center;
}
.excel-text-filter{
  display:flex;
  align-items:center;
  gap:8px;
  min-width:min(520px,100%);
}
.excel-text-filter input{
  flex:1 1 280px;
  min-width:180px;
}
.excel-text-filter .text-filter-operator{
  flex:0 0 150px;
}
@media(max-width:900px){
  #deliveryTab{padding-top:24px}
  .excel-text-filter{
    flex-wrap:wrap;
    min-width:0;
    width:100%;
  }
  .excel-text-filter .text-filter-operator{
    flex:1 1 150px;
  }
}


/* Milestone 5 R9 - collapsed sidebar tab tooltips */
.sidebar-collapsed .side-nav .tabbtn{position:relative}
.sidebar-collapsed .side-nav .tabbtn::after{
  content:attr(data-tooltip);position:absolute;left:calc(100% + 12px);top:50%;
  transform:translateY(-50%);z-index:20000;min-width:max-content;max-width:240px;
  padding:7px 10px;border-radius:7px;background:#0f172a;color:#f8fafc;
  font-size:12px;font-weight:700;line-height:1.2;white-space:nowrap;
  opacity:0;visibility:hidden;pointer-events:none;
  box-shadow:0 8px 24px rgba(15,23,42,.28);transition:opacity .12s ease,visibility .12s ease
}
.sidebar-collapsed .side-nav .tabbtn::before{
  content:"";position:absolute;left:calc(100% + 5px);top:50%;transform:translateY(-50%);
  z-index:20001;border:6px solid transparent;border-right-color:#0f172a;
  opacity:0;visibility:hidden;pointer-events:none;transition:opacity .12s ease,visibility .12s ease
}
.sidebar-collapsed .side-nav .tabbtn:hover::after,
.sidebar-collapsed .side-nav .tabbtn:focus-visible::after,
.sidebar-collapsed .side-nav .tabbtn:hover::before,
.sidebar-collapsed .side-nav .tabbtn:focus-visible::before{opacity:1;visibility:visible}
@media(max-width:820px){
  .sidebar-collapsed .side-nav .tabbtn::after,
  .sidebar-collapsed .side-nav .tabbtn::before{display:none!important}
}


/* Milestone 5 R12 - upper-right page indicators */
.top-page-line{
  display:flex;
  justify-content:flex-end;
  align-items:center;
  min-height:30px;
  margin:4px 0 8px;
}
.top-page-line span{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-width:78px;
  padding:5px 9px;
  border:1px solid #dbe3ee;
  border-radius:8px;
  background:#f8fafc;
  color:#475569;
  font-size:11px;
  font-weight:800;
  white-space:nowrap;
}
@media(max-width:700px){
  .top-page-line{justify-content:flex-start}
}


/* Milestone 5 R15 - native Mail Size dashboard */
#mailSizeTab{padding-bottom:28px}
#mailSizeTab .ms-profile-pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
@media(max-width:900px){#mailSizeTab .ms-profile-pair{grid-template-columns:1fr}}
.ms-section{margin:8px 0 18px}
.ms-section-head,.ms-card-head,.ms-profile-head{
  display:flex;align-items:center;justify-content:space-between;gap:12px
}
.ms-section-head{margin-bottom:9px}
.ms-section-head h3{margin:0;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#475569}
.ms-section-head span,.ms-card-subtitle{font-size:11px;color:#64748b}
.ms-layout{display:grid;grid-template-columns:350px minmax(0,1fr);gap:18px;align-items:start}
.ms-left,.ms-config-stack{display:grid;gap:18px}
.ms-card{background:#fff;border:1px solid #dbe4ee;border-radius:13px;padding:17px;box-shadow:0 7px 22px rgba(15,23,42,.05)}
.ms-card-title{font-size:15px;font-weight:850;color:#0f172a}
.ms-card-subtitle{margin-top:3px}
.ms-calc-grid{display:grid;grid-template-columns:1fr 90px;gap:10px;align-items:end;margin-top:15px}
.ms-calc-grid label>span,.ms-calc-grid>div>span{display:block;margin-bottom:5px;font-size:10px;font-weight:800;color:#475569}
.ms-number-input{height:40px;display:flex;align-items:center;border:1px solid #cbd5e1;border-radius:8px;overflow:hidden}
.ms-number-input input{min-width:0;width:100%;height:100%;border:0;outline:0;padding:0 9px;font-weight:850}
.ms-number-input b{padding:0 9px;color:#64748b;font-size:11px}
.ms-calc-result{height:40px;display:flex;align-items:center;justify-content:center;border-radius:8px;background:#eff6ff;color:#1d4ed8;font-size:13px}
.ms-calc-result b{font-size:16px;margin-right:4px}
.ms-formula{margin-top:9px;padding:8px 9px;border-radius:7px;background:#f8fafc;color:#64748b;font-size:10px}
.ms-cooldown{margin-top:10px;padding:8px 9px;border:1px solid #fed7aa;border-radius:7px;background:#fff7ed;color:#b45309;font-size:11px;font-weight:800}
.ms-profile{padding:0;overflow:hidden}
.ms-profile-accent{height:4px}
.ms-profile.outlook .ms-profile-accent{background:#0078d4}
.ms-profile.webmail .ms-profile-accent{background:#e11d48}
.ms-profile-body{padding:17px}
.ms-profile-head{margin-bottom:14px}
.ms-chip{padding:5px 8px;border-radius:999px;background:#f1f5f9;color:#475569;font-size:10px;font-weight:800}
.ms-limit{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;padding:13px;border:1px solid #e2e8f0;border-radius:10px;background:#fbfdff}
.ms-limit.warning{border-color:#fed7aa;background:#fffaf3}
.ms-limit>div:first-child{min-width:0}
.ms-limit>div:first-child>b{display:block;font-size:12px;color:#0f172a}
.ms-limit-label{display:block;margin-bottom:4px;font-size:9px;font-weight:850;text-transform:uppercase;letter-spacing:.05em;color:#64748b}
.ms-limit.warning .ms-limit-label{color:#b45309}
.ms-limit-form{display:flex;height:39px;align-items:center;border:1px solid #cbd5e1;border-radius:8px;overflow:hidden;background:#fff}
.ms-limit-form>span{height:100%;display:flex;align-items:center;padding:0 9px;background:#f8fafc;color:#64748b;font:10px ui-monospace,SFMono-Regular,Menlo,monospace;border-right:1px solid #e2e8f0}
.ms-limit-form input{width:54px;height:100%;border:0;outline:0;text-align:center;font-weight:900}
.ms-limit-form>b{height:100%;display:flex;align-items:center;padding:0 7px;border-left:1px solid #e2e8f0;color:#64748b;font-size:10px}
.ms-limit-form button{height:100%;border:0;padding:0 12px;color:#fff;font-size:10px;font-weight:900;cursor:pointer}
.ms-profile.outlook .ms-limit-form button{background:#0078d4}
.ms-profile.webmail .ms-limit-form button{background:#e11d48}
.ms-limit-form button:disabled{background:#94a3b8!important;cursor:not-allowed}
.ms-backup-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 0;border-bottom:1px solid #f1f5f9}
.ms-backup-row:last-child{border-bottom:0}
.ms-backup-row b{display:block;font-size:11px;color:#334155}
.ms-backup-row small{display:block;margin-top:2px;max-width:210px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#94a3b8;font-size:9px}
.ms-revert{border:1px solid #fecaca;background:#fff;color:#b91c1c;border-radius:6px;padding:5px 8px;font-size:9px;font-weight:850;cursor:pointer}
.ms-bottom-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}
.ms-audit-list{display:grid;gap:6px;max-height:220px;overflow:auto;margin-top:12px}
.ms-audit-item{padding:7px 8px;border:1px solid #eef2f7;border-radius:7px;background:#fbfdff;color:#475569;font:10px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
.ms-notes-table{width:100%;border-collapse:collapse;margin-top:10px;font-size:10px}
.ms-notes-table td{padding:8px;border-bottom:1px solid #f1f5f9}
.ms-notes-table td:first-child{width:34%;font-weight:850;color:#475569}
.ms-empty{padding:16px;text-align:center;color:#94a3b8;font-size:10px}
@media(max-width:1100px){
  .ms-layout{grid-template-columns:1fr}
}
@media(max-width:760px){
  .ms-bottom-grid{grid-template-columns:1fr}
  .ms-limit{grid-template-columns:1fr}
  .ms-limit-form{width:100%}
  .ms-limit-form>span{flex:1 1 auto;overflow:hidden;text-overflow:ellipsis}
}


/* Milestone 5 R17 - SpamAssassin Whitelist / Blacklist manager */
.sl-kpis{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:10px;margin:10px 0 14px}
.sl-kpi{padding:13px 14px;border:1px solid #dbe4ee;border-radius:11px;background:#fff;box-shadow:0 4px 14px rgba(15,23,42,.04)}
.sl-kpi span{display:block;color:#64748b;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.04em}
.sl-kpi b{display:block;margin-top:5px;color:#0f172a;font-size:20px}
.sl-kpi.whitelist{border-top:3px solid #16a34a}
.sl-kpi.blacklist{border-top:3px solid #dc2626}
.sl-controls{margin-bottom:0}
.sl-table-wrap{overflow:auto;border:1px solid #dbe4ee;border-radius:11px;background:#fff}
.sl-table{width:100%;min-width:1020px;border-collapse:collapse;font-size:11px}
.sl-table th{padding:10px;text-align:left;background:#f8fafc;color:#475569;border-bottom:1px solid #dbe4ee;font-size:9px;letter-spacing:.05em}
.sl-table td{padding:10px;border-bottom:1px solid #eef2f7;vertical-align:middle}
.sl-table tbody tr:last-child td{border-bottom:0}
.sl-table code{font-size:10px;background:#f1f5f9;padding:3px 5px;border-radius:5px;color:#334155}
.sl-kind,.sl-scope{display:inline-flex;padding:4px 7px;border-radius:999px;font-size:9px;font-weight:850}
.sl-kind.whitelist{background:#ecfdf3;color:#166534;border:1px solid #bbf7d0}
.sl-kind.blacklist{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}
.sl-scope{background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe}
.sl-actions{display:flex;gap:6px}
.sl-actions button{padding:5px 8px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;color:#334155;font-size:9px;font-weight:800;cursor:pointer}
.sl-actions button.danger{color:#b91c1c;border-color:#fecaca}
.sl-actions button:disabled{opacity:.45;cursor:not-allowed}
.sl-editor{position:fixed;inset:0;z-index:30000;display:grid;place-items:center;padding:20px;background:rgba(15,23,42,.48)}
.sl-editor[hidden]{display:none!important}
.sl-editor-card{width:min(720px,100%);max-height:90vh;overflow:auto;padding:18px;border-radius:14px;background:#fff;box-shadow:0 25px 70px rgba(15,23,42,.30)}
.sl-form-grid{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin-top:16px}
.sl-form-grid label{display:flex;flex-direction:column;gap:5px;color:#475569;font-size:10px;font-weight:850}
.sl-form-grid input,.sl-form-grid select{width:100%;padding:9px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;color:#0f172a}
.sl-format-note{margin-top:13px;padding:10px;border-radius:8px;background:#f8fafc;color:#475569;font-size:10px;line-height:1.55}
.sl-format-note code{background:#e2e8f0;padding:2px 4px;border-radius:4px}
.sl-editor-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:15px}
.sl-bulkbar{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:10px 0;padding:9px 10px;border:1px solid #dbe4ee;border-radius:9px;background:#f8fafc}
.sl-bulk-left,.sl-bulk-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sl-selected-count{font-size:10px;font-weight:850;color:#475569}
.sl-bulk-delete{padding:7px 10px;border:1px solid #fecaca;border-radius:7px;background:#fff;color:#b91c1c;font-size:10px;font-weight:850;cursor:pointer}
.sl-bulk-delete:disabled{opacity:.45;cursor:not-allowed}
.sl-select-cell{width:36px;text-align:center!important}
.sl-row-check,.sl-select-visible{width:11px;height:11px;margin:0;vertical-align:middle;cursor:pointer;accent-color:currentColor}
.sl-search-wrap{display:flex;gap:7px;align-items:center;flex:1 1 360px}
.sl-search-wrap input{min-width:180px;flex:1 1 auto}
.sl-search-btn,.sl-clear-btn{padding:8px 10px;border:1px solid #cbd5e1;border-radius:7px;background:#fff;color:#334155;font-size:10px;font-weight:850;cursor:pointer}
.sl-import-card{width:min(850px,100%)}
.sl-import-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
.sl-import-grid label{display:flex;flex-direction:column;gap:5px;color:#475569;font-size:10px;font-weight:850}
.sl-import-grid input,.sl-import-grid select{width:100%;padding:9px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;color:#0f172a}
.sl-import-file{grid-column:1/-1}
.sl-import-preview{margin-top:14px;border:1px solid #e2e8f0;border-radius:9px;overflow:hidden}
.sl-import-stats{display:grid;grid-template-columns:repeat(4,minmax(100px,1fr));gap:8px;margin:12px 0}
.sl-import-stat{padding:9px;border:1px solid #e2e8f0;border-radius:8px;background:#f8fafc}
.sl-import-stat span{display:block;font-size:9px;text-transform:uppercase;color:#64748b;font-weight:850}
.sl-import-stat b{display:block;margin-top:4px;font-size:16px;color:#0f172a}
.sl-import-stat.add b{color:#15803d}.sl-import-stat.dup b{color:#b45309}.sl-import-stat.invalid b{color:#b91c1c}
.sl-import-results{max-height:250px;overflow:auto;padding:8px;background:#fbfdff}
.sl-import-row{display:grid;grid-template-columns:52px 130px minmax(0,1fr) 80px;gap:8px;padding:6px;border-bottom:1px solid #eef2f7;font-size:9px;color:#334155}
.sl-import-row:last-child{border-bottom:0}
.sl-import-row .add{color:#15803d;font-weight:850}.sl-import-row .duplicate{color:#b45309;font-weight:850}.sl-import-row .invalid{color:#b91c1c;font-weight:850}
@media(max-width:850px){.sl-bulkbar{align-items:flex-start;flex-direction:column}.sl-import-grid{grid-template-columns:1fr}.sl-import-file{grid-column:auto}.sl-import-stats{grid-template-columns:repeat(2,minmax(0,1fr))}.sl-import-row{grid-template-columns:44px 110px minmax(0,1fr)}}
@media(max-width:850px){
  .sl-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
  .sl-form-grid{grid-template-columns:1fr}
}


/* R18.4 User Experience Pack */
.ux-filter-badge{display:inline-flex;align-items:center;min-height:30px;padding:0 10px;border-radius:999px;background:#ecfeff;border:1px solid #a5f3fc;color:#155e75;font-size:11px;font-weight:800;white-space:nowrap}
.ux-filter-badge.active{background:#dbeafe;border-color:#93c5fd;color:#1d4ed8}
.ux-last-refresh{font-size:11px;color:#64748b;white-space:nowrap}
.ux-page-size{min-width:96px}
.delivery-compact thead th,.sl-table thead th,.audit-table thead th,.summary-table thead th{position:sticky;top:0;z-index:5;background:#f8fafc}
.ux-copy{border:0;background:transparent;color:#2563eb;padding:2px 5px;cursor:pointer;font-size:11px;vertical-align:middle}
.ux-copy:hover{background:#eff6ff;border-radius:5px}
.ux-empty{padding:28px!important;text-align:center!important;color:#64748b}
.ux-empty button{margin-left:8px}
.ux-last-refresh{font-size:11px;color:#64748b;white-space:nowrap}
@media(max-width:900px){.ux-last-refresh{width:100%}}

/* R18.5 Operational Safety & Administration Pack */
.status-card small{display:block;margin-top:6px;color:#64748b;font-size:11px;line-height:1.35}.status-card.feature{border-left:4px solid #0ea5e9}.status-card.feature.warning{border-left-color:#f59e0b}
.ops-panel{margin-top:18px;display:grid;gap:14px}.ops-grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:12px}.ops-card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px;box-shadow:var(--shadow)}.ops-card span{display:block;color:#64748b;font-size:12px}.ops-card b{display:block;margin-top:5px;font-size:18px;overflow-wrap:anywhere}.ops-card.warning{border-color:#fbbf24;background:#fffbeb}.ops-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.ops-actions input{min-width:260px;max-width:480px}.ops-table-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}.ops-table{min-width:920px}.ops-fingerprint{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;color:#475569;overflow-wrap:anywhere}.ops-changed{display:flex;gap:4px;flex-wrap:wrap}.ops-chip{font-size:10px;padding:2px 6px;border-radius:999px;background:#e2e8f0;color:#334155}.ops-match{color:#15803d;font-weight:700}.ops-diff{color:#b45309;font-weight:700}
.conflict-modal-panel{width:min(1100px,95vw);max-height:88vh;overflow:auto;background:#fff;border-radius:14px;padding:18px}.conflict-table{min-width:760px}.conflict-pref{display:inline-flex;margin:2px;padding:3px 6px;border-radius:999px;background:#fee2e2;color:#991b1b;font-size:10px;font-weight:700}
@media(max-width:900px){.ops-grid{grid-template-columns:1fr}}


/* R18.6 Eye Comfort Pack - Amavis Quarantine only */
#quarantineTab{
  background:#f8fafc;
  color:#1f2937;
}
#quarantineTab .page-head h2{font-size:24px;color:#1e293b}
#quarantineTab .page-subtitle{color:#64748b}
#quarantineTab .qnote{
  background:#f1f5f9;
  color:#334155;
  border-left-color:#94a3b8;
  border-radius:8px;
}
#quarantineTab .qhero{gap:12px;margin-bottom:14px}
#quarantineTab .qmetric{
  min-height:94px;
  padding:14px 16px;
  border-color:#d9e2ec;
  border-radius:12px;
  box-shadow:none;
}
#quarantineTab .qmetric.total,
#quarantineTab .qmetric.spam,
#quarantineTab .qmetric.virus,
#quarantineTab .qmetric.banned{border-color:#d9e2ec}
#quarantineTab .metric-icon{
  width:42px;height:42px;font-size:19px;
  color:#334155;background:#eef2f7 !important;
  border:1px solid #d7e0ea;
}
#quarantineTab .qmetric.total .metric-icon{color:#315b8a}
#quarantineTab .qmetric.spam .metric-icon{color:#9f4753}
#quarantineTab .qmetric.virus .metric-icon{color:#9a6a2f}
#quarantineTab .qmetric.banned .metric-icon{color:#6f5a99}
#quarantineTab .qmetric.updated .metric-icon{color:#526b82;border-color:#d7e0ea}
#quarantineTab .qmetric span{font-size:12px;color:#5f6f80}
#quarantineTab .qmetric b{font-size:23px;color:#26384a}
#quarantineTab .qmetric small{color:#7a8997}
#quarantineTab .qmetric-filter:hover{transform:none;box-shadow:0 2px 8px rgba(15,23,42,.045)}
#quarantineTab .qmetric-filter.active{
  border-color:#8ca6be !important;
  box-shadow:0 0 0 2px rgba(100,116,139,.12);
  background:#f8fbfd;
}
#quarantineTab .qtoolbar{
  gap:10px;
  padding:13px 14px;
  margin-bottom:12px;
  border-color:#dbe3ea;
  box-shadow:none;
}
#quarantineTab .qtoolbar input,
#quarantineTab .qtoolbar select{
  background:#fff;
  color:#334155;
  border-color:#cfd9e3;
}
#quarantineTab .qtoolbar input:focus,
#quarantineTab .qtoolbar select:focus{
  outline:2px solid rgba(71,103,135,.15);
  border-color:#829ab1;
}
#quarantineTab .ux-filter-badge{background:#eef3f7;color:#526779;border-color:#d8e1e8}
#quarantineTab .ux-last-refresh{color:#708090}
#quarantineTab .qlist-head{
  min-height:46px;
  background:#e9eff5;
  color:#334155;
  border-color:#d5dee7;
  font-size:12px;
  font-weight:750;
}
#quarantineTab .qmail-list{
  border-left-color:#dbe3ea;
  border-right-color:#dbe3ea;
  background:#fff;
}
#quarantineTab .qmail{
  min-height:132px;
  border-bottom-color:#e2e8ee !important;
  background:#fff;
}
#quarantineTab .qmail:nth-child(even){background:#fbfcfd}
#quarantineTab .qside{
  padding-top:20px;
  border-right-color:#e5eaf0;
  background:#f7f9fb !important;
  color:#526170 !important;
}
#quarantineTab .qcat{
  color:#475569;
  font-size:12px;
  letter-spacing:.025em;
}
#quarantineTab .qmail-time{font-size:12px;color:#718096}
#quarantineTab .qmail-main{
  padding:16px 20px;
  border-right-color:#e5eaf0;
}
#quarantineTab .qdetails{
  row-gap:8px;
  font-size:13px;
  line-height:1.5;
}
#quarantineTab .qdetails-label{color:#596879;font-weight:700}
#quarantineTab .qdetails-value{color:#26384a}
#quarantineTab .qdetails-subject{color:#1f3347;font-weight:650}
#quarantineTab .qdetails-id{color:#557da2;font-size:11px}
#quarantineTab .qauthbox,
#quarantineTab .qscorebox,
#quarantineTab .qactionbox{
  gap:9px;
  padding:14px 16px;
  border-right-color:#e5eaf0;
  background:transparent;
}
#quarantineTab .qauthline{font-size:12px;color:#607080}
#quarantineTab .qauth{
  background:#eef2f6;
  color:#526273;
  border:1px solid #dce4eb;
}
#quarantineTab .qscorebox{background:transparent}
#quarantineTab .qscorelabel{color:#718096}
#quarantineTab .qscore{font-size:17px}
#quarantineTab .qscore.low{color:#557da2}
#quarantineTab .qscore.medium{color:#9a6a2f}
#quarantineTab .qscore.high{color:#a84c57}
#quarantineTab .qstate{background:#eef2f6;color:#5f6f80}
#quarantineTab .qstate.released{background:#edf7f0;color:#4f785b}
#quarantineTab .qstate.flagged{background:#faf4e8;color:#8a6a35}
#quarantineTab .qactions button{
  min-height:36px;
  font-size:12px;
  font-weight:650;
  border-radius:8px;
  box-shadow:none;
}
#quarantineTab .qactions button:first-child{
  background:#f6fbf7;color:#477456;border-color:#bfd8c5;
}
#quarantineTab .qactions button:last-child{
  background:#fff8f8;color:#96545c;border-color:#e0c3c7;
}
#quarantineTab .qbulkbar{
  background:#f5f8fb;
  border-color:#dbe3ea;
  box-shadow:none;
}
#quarantineTab .qbulk-release{background:#f6fbf7 !important;color:#477456 !important;border-color:#bfd8c5 !important}
#quarantineTab .qbulk-spam{background:#fff8f8 !important;color:#96545c !important;border-color:#e0c3c7 !important}
#quarantineTab .top-page-line{color:#718096}
#quarantineTab .qscore-tooltip{
  /* M7 Quarantine Intelligence: opaque evidence card separated from table background */
  background:#ffffff !important;
  color:#111827 !important;
  border:1px solid #94a3b8 !important;
  border-radius:12px;
  box-shadow:0 18px 48px rgba(15,23,42,.28),0 5px 14px rgba(15,23,42,.16) !important;
  opacity:1 !important;
  backdrop-filter:none !important;
  -webkit-backdrop-filter:none !important;
  isolation:isolate;
}
#quarantineTab .qscore-tooltip::after{border-left-color:#ffffff !important}
#quarantineTab .qscore-tip-head{
  background:#0f2742 !important;
  color:#ffffff !important;
  border-bottom:1px solid #cbd5e1 !important;
}
#quarantineTab .qscore-tip-body{background:#ffffff;color:#111827}
#quarantineTab .qscore-tip-row:hover{background:#f1f5f9}
#quarantineTab .qscore-tip-rule{color:#0f172a}
#quarantineTab .qscore-tip-eq{color:#64748b}
#quarantineTab .qscore-tip-value{color:#92400e;font-weight:800}
#quarantineTab .qscore-tip-empty{color:#64748b}

/* Milestone 6 - explicit learning state/actions without changing the five-column quarantine layout */
#quarantineTab .qlearnstate{font-size:10px;color:#64748b;padding:3px 7px;border-radius:999px;background:#f1f5f9}
#quarantineTab .qlearnstate.learned{color:#166534;background:#dcfce7;font-weight:700}
#quarantineTab .qactions .qrelease{background:#fff;color:#15803d;border:1px solid #86efac}
#quarantineTab .qactions .qspam{background:#fff;color:#b91c1c;border:1px solid #fca5a5}
#quarantineTab .qactions .qham{background:#fff;color:#1d4ed8;border:1px solid #93c5fd}
#quarantineTab .qactions .qham:hover:not(:disabled){background:#eff6ff}



/* Milestone 6 R5 — Summary + Quarantine UX */
.daily-bounce-compact{
  width:min(760px,100%);
  max-width:760px;
  margin-right:auto;
  overflow-x:auto;
}
.daily-bounce-table{
  table-layout:fixed;
  width:100%;
  min-width:560px;
}
.daily-bounce-table th,
.daily-bounce-table td{vertical-align:middle}
.daily-bounce-table .bounce-date-col,
.daily-bounce-table td:first-child{
  width:118px;
  white-space:nowrap;
}
.daily-bounce-table th:nth-child(2),
.daily-bounce-table td:nth-child(2){
  width:auto;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}
.daily-bounce-table th.num,
.daily-bounce-table td.num{
  width:92px;
  text-align:right;
  font-variant-numeric:tabular-nums;
}
.daily-bounce-table tr.total-row td{vertical-align:middle}
@media(max-width:680px){
  .daily-bounce-compact{max-width:100%}
  .daily-bounce-table{min-width:520px}
}
.quarantine-top-pager{
  justify-content:flex-end;
  margin:4px 0 8px;
}
.quarantine-top-pager .pager{
  margin-top:0;
}
#quarantineTab .qpager{
  display:flex;
  align-items:center;
  justify-content:center;
  gap:8px;
}
#quarantineTab .qpager button{
  min-width:34px;
  width:34px;
  height:32px;
  min-height:32px;
  padding:0;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  font-size:18px;
  line-height:1;
}
#quarantineTab .qpager span{
  min-width:92px;
  text-align:center;
  white-space:nowrap;
  font-size:11px;
  font-weight:800;
  color:#475569;
}
#quarantineTab .qprimary-actions{
  display:flex!important;
  flex-direction:column;
  align-items:stretch;
  justify-content:center;
  gap:7px;
  width:100%;
  max-width:100%;
}
#quarantineTab .qprimary-actions button{
  width:100%;
  max-width:100%;
  min-width:0;
  min-height:34px;
  padding:6px 7px;
  font-size:10px;
  line-height:1.15;
  white-space:normal;
  overflow-wrap:anywhere;
}
#quarantineTab .qreleaseham{
  background:#0f766e!important;
  border-color:#0f766e!important;
  color:#fff!important;
}
#quarantineTab .qspam{
  background:#b45309!important;
  border-color:#b45309!important;
  color:#fff!important;
}
#quarantineTab .qdetail-tools{
  display:flex;
  align-items:center;
  gap:6px;
  flex-wrap:wrap;
  min-width:0;
}
#quarantineTab .qintel-link{
  min-height:26px;
  padding:4px 7px;
  border:1px solid #cbd5e1;
  border-radius:6px;
  background:#f8fafc;
  color:#475569;
  font-size:10px;
  font-weight:700;
}
@media(max-width:900px){
  #quarantineTab .qprimary-actions{
    flex-direction:row;
  }
  #quarantineTab .qprimary-actions button{
    flex:1 1 0;
  }
}


/* M7 AI R1.1 manual Email Analysis + offline Geo-IP */
.email-analysis-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:14px;align-items:start;min-width:0}
.email-analysis-card{background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow);padding:16px;min-width:0}
.email-analysis-card h3{margin:0 0 6px}.email-analysis-note{font-size:12px;color:#64748b;margin-bottom:12px}
#emailAnalysisRaw{width:100%;min-height:240px;max-height:420px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.45;padding:12px;border:1px solid #cbd5e1;border-radius:8px;background:#fbfdff}
.email-analysis-actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.email-analysis-actions input[type=file]{min-width:260px;flex:1}
.email-analysis-kv{display:grid;grid-template-columns:minmax(110px,150px) minmax(0,1fr);gap:7px 12px;font-size:13px;min-width:0}.email-analysis-kv span{color:#64748b}.email-analysis-kv b{overflow-wrap:anywhere;word-break:break-word;min-width:0}
.email-analysis-section{margin-top:14px;padding-top:12px;border-top:1px solid #e2e8f0;min-width:0}.email-analysis-section h4{margin:0 0 9px}
.email-analysis-rules{width:100%;font-size:12px;border-collapse:collapse}.email-analysis-rules th,.email-analysis-rules td{position:static;padding:6px 8px}.email-analysis-rules td:last-child{text-align:right;font-weight:700}
.geo-badge{display:inline-flex;padding:3px 8px;border-radius:999px;background:#ecfeff;color:#155e75;font-size:11px;font-weight:700}
.email-analysis-result-shell{min-width:0}
.email-analysis-primary-row{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px;align-items:start}
.email-analysis-support-row{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px;align-items:start;margin-top:14px}
.email-analysis-full{grid-column:1/-1;min-width:0}
.amavis-dryrun-card{border:1px solid #93c5fd;border-radius:12px;background:#f8fbff;padding:12px;min-width:0}
.amavis-dryrun-card h4{margin:0 0 8px}.amavis-dryrun-state{display:inline-flex;padding:3px 8px;border-radius:999px;font-size:9px;font-weight:900;background:#e2e8f0;color:#334155}.amavis-dryrun-state.ready{background:#dcfce7;color:#166534}.amavis-dryrun-state.unavailable{background:#fef3c7;color:#92400e}.amavis-dryrun-safety{margin-top:10px;padding:8px;border:1px dashed #60a5fa;border-radius:8px;background:#eff6ff;color:#1e3a8a;font-size:10px;font-weight:700}.ea-comparison{border:1px solid #cbd5e1;border-radius:10px;background:#f8fafc;padding:10px;margin-top:14px;min-width:0}
@media(max-width:1100px){.email-analysis-primary-row,.email-analysis-support-row{grid-template-columns:1fr}}

/* AI R1.1.3 UI defect corrections */
#mailSizeTab .ms-limit{display:flex;flex-direction:column;align-items:stretch;gap:12px}
#mailSizeTab .ms-limit>div:first-child{width:100%;min-width:0}
#mailSizeTab .ms-limit>div:first-child>b{white-space:normal;overflow-wrap:normal;word-break:normal}
#mailSizeTab .ms-limit-form{width:100%;display:grid;grid-template-columns:auto minmax(72px,1fr) auto auto}
#mailSizeTab .ms-limit-form>span{white-space:nowrap}
#mailSizeTab .ms-limit-form input{width:100%;min-width:72px}
#quarantineTab .qhero{grid-template-columns:repeat(4,minmax(150px,1fr)) minmax(265px,1.45fr)!important}
#quarantineTab .qmetric.updated{min-width:265px}
#quarantineTab .qmetric.updated>div:last-child{min-width:0}
#quarantineTab .qmetric.updated b{font-size:18px!important;white-space:nowrap;letter-spacing:-.01em}
#quarantineTab .qmetric.updated small:last-child{white-space:nowrap;font-size:10px;overflow:hidden;text-overflow:ellipsis}
@media(max-width:1200px){#quarantineTab .qhero{grid-template-columns:repeat(2,minmax(220px,1fr))!important}#quarantineTab .qmetric.updated{grid-column:span 2}}
@media(max-width:700px){#quarantineTab .qhero{grid-template-columns:1fr!important}#quarantineTab .qmetric.updated{grid-column:auto;min-width:0}}
.email-analysis-drop{margin:10px 0;padding:18px;border:2px dashed #94a3b8;border-radius:10px;background:#f8fafc;text-align:center;color:#475569;font-size:12px}
.email-analysis-drop.dragover{border-color:#2563eb;background:#eff6ff}
.email-analysis-list{margin:6px 0 0;padding-left:18px;font-size:12px;color:#334155}

/* Milestone 6 R4 - fixed-height navigation and Quarantine Intelligence */
.sidebar{height:100dvh;max-height:100dvh;overflow:hidden}
.side-nav{flex:1 1 auto;min-height:0;overflow-y:auto;overscroll-behavior:contain;scrollbar-width:thin}
.sidebar-foot{flex:0 0 auto;margin-top:0;position:relative;bottom:0;background:#102c50;border-top:1px solid rgba(255,255,255,.12)}
.qintel-modal{display:none;position:fixed;inset:0;z-index:22000;background:rgba(15,23,42,.55);padding:24px}
.qintel-modal.open{display:flex;align-items:center;justify-content:center}
.qintel-panel{width:min(1050px,96vw);max-height:90vh;overflow:auto;background:#fff;border-radius:14px;box-shadow:0 24px 70px rgba(15,23,42,.32)}
.qintel-head{position:sticky;top:0;z-index:2;display:flex;justify-content:space-between;gap:14px;align-items:center;padding:16px 18px;background:#fff;border-bottom:1px solid #e2e8f0}
.qintel-head h3{margin:0;font-size:18px}.qintel-body{padding:18px}.qintel-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.qintel-card{border:1px solid #e2e8f0;border-radius:10px;padding:13px;background:#fbfdff}.qintel-card h4{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#475569}.qintel-kv{display:grid;grid-template-columns:160px minmax(0,1fr);gap:7px 10px;font-size:11px}.qintel-kv span{color:#64748b}.qintel-kv b{overflow-wrap:anywhere}.qintel-table{width:100%;border-collapse:collapse;font-size:10px}.qintel-table th,.qintel-table td{padding:7px;border-bottom:1px solid #eef2f7;text-align:left}.qintel-ok{color:#15803d}.qintel-missing{color:#94a3b8}.qintel-actions{display:flex;gap:8px;flex-wrap:wrap}.qintel-btn{font-size:10px;padding:7px 9px}.qreleaseham{background:#0f766e!important;color:#fff!important}.qintelopen{background:#475569!important;color:#fff!important}
.qintel-ai{background:#f8fafc;border:1px solid #94a3b8;box-shadow:0 8px 22px rgba(15,23,42,.08)}
.qintel-ai h4{color:#0f172a}.qintel-ai-note{margin-top:10px;padding:9px 10px;border-radius:8px;background:#eef2ff;color:#3730a3;font-size:10px;line-height:1.45}.qintel-ai-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.qintel-ai-actions button{border:1px solid #6366f1;background:#4f46e5;color:#fff;border-radius:7px;padding:7px 10px;font-size:10px;font-weight:800;cursor:pointer}.qintel-ai-actions button:disabled{opacity:.45;cursor:not-allowed}
.qintel-live-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}.qintel-live-panel{border:1px solid #cbd5e1;border-radius:9px;background:#fff;padding:10px}.qintel-live-title{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px;font-size:11px;font-weight:800;color:#0f172a;text-transform:uppercase;letter-spacing:.04em}.qintel-live-badge{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:2px 7px;background:#dcfce7;color:#166534;font-size:9px;font-weight:900}.qintel-live-badge::before{content:"";width:6px;height:6px;border-radius:50%;background:#16a34a;box-shadow:0 0 0 3px rgba(22,163,74,.12)}.qintel-live-badge.stale{background:#fef3c7;color:#92400e}.qintel-live-badge.stale::before{background:#d97706}.qintel-live-updated{margin-top:7px;color:#64748b;font-size:9px}.qintel-live-error{color:#b91c1c!important}@media(max-width:760px){.qintel-live-grid{grid-template-columns:1fr}}
#quarantineTab .qactions{grid-template-columns:1fr 1fr!important}
@media(max-width:760px){.qintel-grid{grid-template-columns:1fr}.qintel-kv{grid-template-columns:1fr}.qintel-modal{padding:8px}}

/* R1.1.36 — professional Quarantine Intelligence reflow.
   Keep the modal inside the viewport; only evidence tables may scroll horizontally. */
.qintel-modal{overflow:hidden}
.qintel-panel{width:min(1480px,98vw);max-width:98vw;overflow-x:hidden}
.qintel-body{overflow-x:hidden}
.qintel-grid{grid-template-columns:minmax(0,3fr) minmax(360px,2fr);align-items:start}
.qintel-grid>*{min-width:0}
.qintel-identity{grid-column:1/-1;background:#fff;border-color:#d9e2ef}
.qintel-identity-grid{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:12px}
.qintel-identity-cell{min-width:0}
.qintel-identity-cell span{display:block;color:#64748b;font-size:9px;font-weight:700;margin-bottom:4px}
.qintel-identity-cell b{display:block;color:#0f172a;font-size:10px;overflow-wrap:anywhere;word-break:break-word}
.qintel-ai-primary{grid-column:1}
.qintel-ground-truth{grid-column:2;background:#fff}
.qintel-ground-truth .qintel-kv{grid-template-columns:145px minmax(0,1fr)}
.qintel-ground-truth select,.qintel-ground-truth input,.qintel-ground-truth textarea{width:100%;max-width:100%;min-width:0;box-sizing:border-box}
.qintel-ground-truth .qintel-ai-actions{justify-content:flex-end}
.qintel-proposal-box{margin-bottom:10px;padding:10px;border:1px solid #dbeafe;border-radius:9px;background:#f8fbff}
.qintel-proposal-source{margin-top:5px;color:#64748b;font-size:9px;overflow-wrap:anywhere}
.qintel-support-pair{min-width:0}
.qintel-wide{grid-column:1/-1}
.qintel-table-wrap{width:100%;max-width:100%;overflow-x:auto}
.qintel-table{min-width:0}
.qheader-pre{max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}
@media(max-width:1100px){
  .qintel-grid{grid-template-columns:1fr}
  .qintel-ai-primary,.qintel-ground-truth,.qintel-support-pair,.qintel-wide{grid-column:1}
  .qintel-identity-grid{grid-template-columns:repeat(3,minmax(0,1fr))}
}
@media(max-width:680px){
  .qintel-panel{width:98vw;max-width:98vw}
  .qintel-identity-grid{grid-template-columns:1fr 1fr}
  .qintel-ground-truth .qintel-kv{grid-template-columns:1fr}
}




/* R1.1.37 — approved professional Quarantine Intelligence layout contract */
.qintel-panel{width:min(1536px,99vw);max-width:99vw;max-height:96vh;border-radius:12px}
.qintel-body{padding:14px}
.qintel-grid{grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px}
.qintel-identity-grid{grid-template-columns:repeat(8,minmax(0,1fr));gap:0}
.qintel-identity-cell{padding:0 12px;border-right:1px solid #e5e7eb}
.qintel-identity-cell:first-child{padding-left:0}.qintel-identity-cell:last-child{border-right:0}
.qintel-status-pill{display:inline-flex!important;width:max-content;padding:3px 8px;border:1px solid #fecaca;border-radius:999px;background:#fff1f2;color:#dc2626!important}
.qintel-ai-primary,.qintel-ground-truth{min-height:0}
.qintel-active-none{color:#dc2626}
.qintel-gt-top{display:grid;grid-template-columns:minmax(0,3fr) minmax(220px,2fr);gap:10px}
.qintel-gt-info{padding:12px;border:1px solid #dbeafe;border-radius:9px;background:#f5f8ff;color:#3743b5;font-size:10px;line-height:1.55}
.qintel-section-label{margin-bottom:9px;color:#243ee7;font-size:11px;font-weight:900;text-transform:uppercase}.qintel-section-label.admin{color:#b45309}
.qintel-admin-box{margin-top:10px;padding:12px;border:1px solid #fde2a7;border-radius:10px;background:#fffdf5}
.qintel-form-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px 12px}.qintel-form-grid label{min-width:0}.qintel-form-grid label>span{display:block;margin-bottom:5px;color:#334155;font-size:10px;font-weight:700}.qintel-form-grid small{display:block;margin-top:4px;color:#64748b;font-size:9px}
.qintel-gt-actions{display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap}.qintel-gt-actions button{border:1px solid #4f46e5;border-radius:7px;padding:9px 13px;font-size:10px;font-weight:850;cursor:pointer}.qintel-gt-actions button:disabled{opacity:.45;cursor:not-allowed}.qintel-gt-actions .qintel-ack{background:#16a34a;border-color:#16a34a;color:#fff}.qintel-gt-actions #aiGtSaveButton{background:#4f46e5;color:#fff}.qintel-gt-actions .qintel-reset{background:#fff;color:#334155;border-color:#cbd5e1}
.qintel-conflict-note{margin-top:10px;padding:10px;border-radius:8px;background:#f5f8ff;color:#3343b8;font-size:10px}
.qintel-ground-truth textarea{resize:vertical}
@media(max-width:1200px){.qintel-identity-grid{grid-template-columns:repeat(4,minmax(0,1fr))}.qintel-identity-cell{border-right:0;border-bottom:1px solid #eef2f7;padding:8px}.qintel-gt-top{grid-template-columns:1fr}}
@media(max-width:900px){.qintel-grid{grid-template-columns:1fr}.qintel-ai-primary,.qintel-ground-truth,.qintel-wide,.qintel-support-pair{grid-column:1}.qintel-form-grid{grid-template-columns:1fr}}
@media(max-width:600px){.qintel-identity-grid{grid-template-columns:1fr 1fr}}

/* R1.1.46 — Quarantine Intelligence grid realignment.
   Use explicit nested rows so optional admin cards and newly added three-tier
   evidence never leave orphaned grid columns or uneven card geometry. */
.qintel-grid{grid-template-columns:minmax(0,1fr);align-items:stretch}
.qintel-review-row,.qintel-support-row{grid-column:1/-1;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;align-items:stretch;min-width:0}
.qintel-review-row.qintel-review-solo{grid-template-columns:minmax(0,1fr)}
.qintel-review-row>.qintel-card,.qintel-support-row>.qintel-card{height:100%;min-width:0;box-sizing:border-box}
.qintel-ai-primary,.qintel-ground-truth,.qintel-support-pair{grid-column:auto}
.qintel-live-grid{align-items:stretch}
.qintel-live-panel{height:100%;min-width:0;box-sizing:border-box}
.qintel-ai-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;align-items:stretch}
.qintel-ai-metrics.qintel-ai-metrics-single{grid-template-columns:minmax(0,1fr)}
.qintel-ai-metric{min-width:0;height:100%;box-sizing:border-box;border:1px solid #cbd5e1;border-radius:9px;background:#fff;padding:10px}
.qintel-ai-metrics-single .qintel-ai-metric{width:100%}
.qintel-live-grid>.qintel-live-panel,.qintel-ai-metrics>.qintel-ai-metric{align-self:stretch}
.qintel-live-grid .qintel-kv,.qintel-ai-metrics .qintel-ai-grid{width:100%}
.qintel-ai-metric h4{margin:0 0 8px;font-size:11px;color:#0f172a}
.qintel-ai-grid{display:grid;grid-template-columns:145px minmax(0,1fr);gap:7px 10px;align-items:start;font-size:10px}
.qintel-ai-grid span{color:#64748b;min-width:0}
.qintel-ai-grid b{min-width:0;overflow-wrap:anywhere;word-break:break-word}
.qintel-kv{align-items:start}
.qintel-wide{grid-column:1/-1}
@media(max-width:1100px){.qintel-review-row,.qintel-support-row{grid-template-columns:minmax(0,1fr)}}
@media(max-width:760px){.qintel-ai-metrics{grid-template-columns:minmax(0,1fr)}.qintel-ai-grid{grid-template-columns:1fr}.qintel-review-row,.qintel-support-row{gap:10px}}

/* R6.5 Fix 2 — Mail Flow SVG stylesheet belongs to MAIN dashboard */
.svg-flow-toolbar{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  margin-bottom:10px;padding:10px 14px;border-radius:10px;
  background:#0b2d4d;color:#fff
}
.svg-flow-toolbar h2{margin:0;color:#fff;font-size:18px}
.svg-flow-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.svg-flow-actions>span{font-size:10px;color:#dbeafe}
.mail-flow-svg-frame{
  width:100%;overflow:visible;border:1px solid #d4deeb;border-radius:12px;
  background:#f4f8fd;padding:8px;box-sizing:border-box
}
.approved-mail-flow-frame{
  width:100%;overflow:auto;border:1px solid #d4deeb;border-radius:12px;
  background:#fff;padding:8px;box-sizing:border-box;
  box-shadow:0 8px 28px rgba(15,23,42,.08)
}
.approved-mail-flow-image{
  display:block;width:100%;height:auto;max-width:100%;margin:0 auto;border-radius:8px
}
.approved-mail-flow-frame:fullscreen,
.approved-mail-flow-frame:-webkit-full-screen{
  width:100vw!important;height:100vh!important;max-width:none!important;
  background:#fff!important;padding:12px!important;box-sizing:border-box;overflow:auto
}
.approved-mail-flow-frame:fullscreen .approved-mail-flow-image,
.approved-mail-flow-frame:-webkit-full-screen .approved-mail-flow-image{
  width:100%;height:100%;object-fit:contain
}
/* Animated Mail Flow overlays the approved baseline architecture.
   The approved PNG remains available as a static reference fallback below. */
.legacy-mail-flow-runtime{display:none!important}
/* The approved baseline architecture remains authoritative.
   Animation is a transparent overlay only; the underlying chart is unchanged. */
.approved-mail-flow-stage{position:relative;width:100%;line-height:0}
.approved-mail-flow-stage .approved-mail-flow-image{position:relative;z-index:1}
.approved-mail-flow-overlay{position:absolute;z-index:2;inset:0;width:100%;height:100%;pointer-events:none;overflow:visible}
.approved-mail-flow-overlay .anim-flow{fill:none;stroke-width:4;stroke-linecap:round;stroke-dasharray:3 22;animation:approvedFlowTravel 1.65s linear infinite;filter:drop-shadow(0 0 3px currentColor);opacity:.82}
.approved-mail-flow-overlay .inbound{stroke:#2563eb;color:#2563eb}
.approved-mail-flow-overlay .outbound{stroke:#16a34a;color:#16a34a;animation-duration:1.9s}
.approved-mail-flow-overlay .shared{stroke:#7c3aed;color:#7c3aed;animation-duration:2.1s}
.approved-mail-flow-overlay .quarantine{stroke:#dc2626;color:#dc2626;animation-duration:1.45s}
.approved-mail-flow-overlay .release{stroke:#0f9f6e;color:#0f9f6e;animation-duration:1.75s}
@keyframes approvedFlowTravel{to{stroke-dashoffset:-100}}
@media (prefers-reduced-motion: reduce){.approved-mail-flow-overlay .anim-flow{animation:none;stroke-dasharray:none;opacity:.35}}
.mail-flow-svg{
  display:block;width:100%;height:auto;min-width:0!important;max-width:100%;
  background:#f8fbff;border-radius:9px
}
.mail-flow-svg text{
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  fill:#0f172a
}
.mail-flow-svg .svg-title{font-size:24px;font-weight:800;fill:#fff!important;letter-spacing:.04em}
.mail-flow-svg .svg-live{font-size:12px;font-weight:800;fill:#dcfce7!important}
.mail-flow-svg .svg-updated{font-size:10px;fill:#dbeafe!important}
.mail-flow-svg .svg-section{font-size:16px;font-weight:800;fill:#17499a!important}
.mail-flow-svg .svg-section.outbound{fill:#23703a!important}
.mail-flow-svg .svg-sub{font-size:11px;fill:#334155!important}

.mail-flow-svg .svg-node>rect{
  fill:#ffffff!important;stroke:#aebfd6!important;stroke-width:1.6!important;
  filter:url(#shadow)
}
.mail-flow-svg .svg-node:hover>rect,
.mail-flow-svg .svg-node:focus>rect{
  fill:#eef6ff!important;stroke:#2563eb!important;stroke-width:2.4!important
}
.mail-flow-svg .svg-node-label{font-size:12px!important;font-weight:800;fill:#0f172a!important}
.mail-flow-svg .svg-node-sub{font-size:9.5px!important;fill:#475569!important}
.mail-flow-svg .svg-active{font-size:9px;fill:#15803d!important;font-weight:800}
.mail-flow-svg .svg-count{font-size:13px;font-weight:900;fill:#1452ae!important}
.mail-flow-svg .svg-count.danger,
.mail-flow-svg .svg-op-count.danger{fill:#dc2626!important}
.mail-flow-svg .svg-count.warn,
.mail-flow-svg .svg-op-count.warn{fill:#d97706!important}
.mail-flow-svg .svg-op-count.purple{fill:#7c3aed!important}
.mail-flow-svg .svg-small-bold{font-size:10px;font-weight:800;fill:#0f172a!important}
.mail-flow-svg .svg-tiny{font-size:8px;fill:#475569!important}
.mail-flow-svg .svg-kicker{font-size:8px;font-weight:800;letter-spacing:.08em;fill:#9f1239!important}
.mail-flow-svg .svg-quar-title{font-size:16px;font-weight:900;fill:#991b1b!important}
.mail-flow-svg .svg-linkish{font-size:8.5px;fill:#2563eb!important;font-weight:700}
.mail-flow-svg .svg-node-label.purple{fill:#6d28d9!important}

.mail-flow-svg .flow-blue,
.mail-flow-svg .flow-green,
.mail-flow-svg .flow-red,
.mail-flow-svg .flow-purple{fill:none!important;stroke-width:2.4}
.mail-flow-svg .flow-blue{stroke:#2563eb!important}
.mail-flow-svg .flow-green{stroke:#16a34a!important}
.mail-flow-svg .flow-red{stroke:#dc2626!important}
.mail-flow-svg .flow-purple{stroke:#7c3aed!important}


}

.mail-flow-svg .opcard>rect{
  fill:#ffffff!important;stroke:#c9d7e8!important;stroke-width:1.2!important
}
.mail-flow-svg .opcard:hover>rect,
.mail-flow-svg .opcard:focus>rect{
  fill:#f2f7ff!important;stroke:#2563eb!important;stroke-width:2!important
}
.mail-flow-svg .svg-op-label{font-size:11px!important;font-weight:800;fill:#0f172a!important}
.mail-flow-svg .svg-op-count{font-size:14px;font-weight:900;fill:#1452ae!important}
.mail-flow-svg .svg-op-count.good{fill:#15803d!important}

.mail-flow-svg .modulebox>rect{
  fill:#ffffff!important;stroke:#c9d7e8!important;stroke-width:1.2!important
}
.mail-flow-svg .modulebox:hover>rect,
.mail-flow-svg .modulebox:focus>rect{
  fill:#f6faff!important;stroke:#2563eb!important;stroke-width:2!important
}
.mail-flow-svg .blue{fill:#1d4ed8!important}

.mail-flow-svg .svg-click{cursor:pointer;outline:none}
.mail-flow-svg .svg-click:focus{filter:drop-shadow(0 0 5px rgba(37,99,235,.45))}
.mail-flow-svg .svg-click:hover{filter:drop-shadow(0 3px 4px rgba(15,23,42,.13))}

.svg-pulse{animation:svgPulse 1.5s ease-in-out infinite}
@keyframes svgPulse{0%,100%{opacity:1}50%{opacity:.25}}
#mailFlowSvg:fullscreen{background:#f8fbff;padding:8px}

.flow-live-badge{
  display:inline-flex!important;align-items:center;gap:6px!important;
  color:#166534!important;background:#ecfdf3;border:1px solid #bbf7d0;
  border-radius:999px;padding:5px 8px
}
.flow-live-badge i{width:7px;height:7px;border-radius:50%;background:#22c55e}

@media(max-width:900px){
  .svg-flow-toolbar{align-items:flex-start;flex-direction:column}
  .mail-flow-svg-frame{overflow:auto}
  .mail-flow-svg{min-width:900px!important}
}


/* R6.5 Fix 3 — centered shared quarantine and clutter reduction */
.mail-flow-svg .svg-node-label{font-size:11px!important}
.mail-flow-svg .svg-node-sub{font-size:8.5px!important}
.mail-flow-svg .svg-op-label{font-size:10.5px!important}
.mail-flow-svg .svg-quar-title{font-size:14px!important}
.mail-flow-svg #sharedQuarantineGroup:hover rect,
.mail-flow-svg #sharedQuarantineGroup:focus rect{fill:#fff7f7!important;stroke:#b91c1c!important}
.mail-flow-svg #sharedQuarantineGroup text{pointer-events:none}

\n/* Milestone 7 Enterprise — flow controls */\n#mailFlowRefreshBtn:disabled{opacity:.7;cursor:wait}\n#mailFlowSvg:fullscreen,#mailFlowSvg:-webkit-full-screen{width:100vw!important;height:100vh!important;max-width:none!important;background:#f8fbff!important;padding:12px;box-sizing:border-box}\n
/* AI R1.1.4 professional navigation + aligned Mail Size controls */
.side-nav{display:block;padding:12px 10px}
.nav-group{display:grid;gap:5px;margin:0 0 14px}
.nav-group:last-child{margin-bottom:4px}
.nav-group-label{padding:0 14px 4px;color:#8fa8c8;font-size:9px;font-weight:850;letter-spacing:.10em;text-transform:uppercase;white-space:nowrap}
.nav-group .tabbtn{margin:0}
body.sidebar-collapsed .nav-group{margin-bottom:10px}
body.sidebar-collapsed .nav-group-label{display:none}
@media(max-width:820px){.nav-group-label{display:block!important}}

#mailSizeTab .ms-profile-pair{align-items:stretch}
#mailSizeTab .ms-profile{height:100%}
#mailSizeTab .ms-profile-body{display:flex;flex-direction:column;height:100%;box-sizing:border-box}
#mailSizeTab .ms-limit{display:grid;grid-template-columns:1fr;gap:12px;align-items:start;min-height:112px;padding:13px}
#mailSizeTab .ms-limit-current{display:grid;grid-template-columns:1fr auto;column-gap:10px;align-items:center}
#mailSizeTab .ms-limit-current .ms-limit-label{grid-column:1;margin:0}
#mailSizeTab .ms-current-value{grid-column:2;grid-row:1 / span 2;display:flex;align-items:baseline;gap:5px;color:#0f172a;white-space:nowrap}
#mailSizeTab .ms-current-value strong{font-size:18px;line-height:1}
#mailSizeTab .ms-current-value span{font-size:10px;font-weight:800;color:#64748b}
#mailSizeTab .ms-limit-current small{grid-column:1;margin-top:4px;color:#64748b;font-size:9px}
#mailSizeTab .ms-limit-edit{display:flex;align-items:end;justify-content:space-between;gap:12px;border-top:1px solid #eef2f7;padding-top:10px}
#mailSizeTab .ms-limit-edit>label{font-size:10px;font-weight:850;color:#475569;white-space:nowrap}
#mailSizeTab .ms-limit-form{width:auto;display:inline-flex;flex:0 0 auto}
#mailSizeTab .ms-limit-form input{box-sizing:border-box;width:6ch;min-width:6ch;max-width:6ch;padding:0 8px;text-align:center;font-variant-numeric:tabular-nums}
#mailSizeTab .ms-limit-form>b{min-width:34px;justify-content:center}
#mailSizeTab .ms-limit-form button{min-width:66px}
@media(max-width:760px){
  #mailSizeTab .ms-limit-edit{align-items:flex-start;flex-direction:column}
  #mailSizeTab .ms-limit-form{width:auto}
}


/* R1.1.9 consolidated UI corrections */
.flow-modal{z-index:30000!important;align-items:center!important;justify-content:center!important;padding:clamp(8px,2vw,28px)!important}
.flow-modal.open{display:flex!important}
.flow-panel{width:min(980px,96vw)!important;height:auto!important;max-height:90vh!important;overflow:auto!important;position:relative!important;z-index:30001!important}
.approved-mail-flow-frame{width:100%!important;max-width:100%!important;overflow:hidden!important}
.approved-mail-flow-image{display:block!important;width:100%!important;max-width:100%!important;height:auto!important;object-fit:contain!important}
.mail-flow-svg-frame,.mail-flow-svg{width:100%!important;max-width:100%!important;height:auto!important}
.sidebar,.side-nav{overflow:visible!important}
body.sidebar-collapsed .side-nav .tabbtn{position:relative!important}
body.sidebar-collapsed .side-nav .tabbtn::after{z-index:31000!important;pointer-events:none!important;white-space:nowrap!important;background:#0f172a!important;color:#fff!important;border:1px solid #334155!important;box-shadow:0 8px 24px rgba(15,23,42,.35)!important}

/* R1.1.9 structural UI corrections */
.sidebar-tooltip-portal{position:fixed;z-index:50000;transform:translateY(-50%);padding:7px 10px;border-radius:7px;background:#0f172a;color:#fff;border:1px solid #334155;box-shadow:0 8px 24px rgba(15,23,42,.35);font-size:12px;font-weight:700;white-space:nowrap;pointer-events:none;opacity:0;visibility:hidden;transition:opacity .08s ease}
.sidebar-tooltip-portal.show{opacity:1;visibility:visible}
body.flow-dialog-open #quarantineTab .qmail:hover,body.flow-dialog-open #quarantineTab .qmail:focus-within{z-index:1!important;box-shadow:none!important;transform:none!important}
body.flow-dialog-open #quarantineTab .qscore-tooltip{display:none!important}
.flow-source-note{margin:0 0 12px;padding:9px 11px;border:1px solid #bfdbfe;border-radius:8px;background:#eff6ff;color:#1e3a8a;font-size:11px}
@media(min-width:821px){body.sidebar-collapsed .side-nav .tabbtn::after,body.sidebar-collapsed .side-nav .tabbtn::before{display:none!important}}


/* Monitor — read-only authentication log visibility */
.monitor-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 12px}.monitor-toolbar input{min-width:260px}.monitor-toolbar select{min-width:120px}.monitor-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;align-items:start}.monitor-panel{background:#fff;border:1px solid #dbe3ee;border-radius:12px;padding:14px;box-shadow:0 4px 14px rgba(15,23,42,.05)}.monitor-panel h3{margin:0}.monitor-source{font-size:12px;color:#64748b;word-break:break-all}.monitor-source.ok{color:#15803d}.monitor-source.err{color:#b91c1c;font-weight:700}.monitor-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin:10px 0}.monitor-stat{border:1px solid #e2e8f0;border-radius:9px;padding:9px;background:#f8fafc}.monitor-stat span{display:block;font-size:11px;color:#64748b}.monitor-stat b{font-size:18px}.monitor-table-wrap{max-height:440px;overflow:auto;border:1px solid #e2e8f0;border-radius:9px}.monitor-table{width:100%;border-collapse:collapse;font-size:12px}.monitor-table th{position:sticky;top:0;background:#f8fafc;z-index:1;text-align:left}.monitor-table th,.monitor-table td{padding:8px;border-bottom:1px solid #edf2f7;vertical-align:top}.monitor-detail{max-width:440px;white-space:normal;word-break:break-word;color:#475569}.monitor-badge{display:inline-block;border-radius:999px;padding:2px 7px;font-weight:700;font-size:11px}.monitor-badge.SUCCESS{background:#dcfce7;color:#166534}.monitor-badge.FAILED{background:#fee2e2;color:#991b1b}.monitor-badge.INFO{background:#e2e8f0;color:#334155}@media(max-width:1100px){.monitor-grid{grid-template-columns:1fr}}

/* R1.1.17 Monitor DB reports + sidebar scroll correction */
.sidebar{overflow:hidden!important}
.side-nav{flex:1 1 auto!important;min-height:0!important;overflow-y:auto!important;overflow-x:hidden!important;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:rgba(191,219,254,.45) transparent}
.side-nav::-webkit-scrollbar{width:7px}.side-nav::-webkit-scrollbar-thumb{background:rgba(191,219,254,.38);border-radius:999px}.side-nav::-webkit-scrollbar-track{background:transparent}
body.sidebar-collapsed .side-nav{overflow-y:auto!important;overflow-x:hidden!important}
.monitor-protocol-tabs{display:flex;gap:8px;margin:0 0 12px}.monitor-protocol-tabs button{background:#fff;border:1px solid #cbd5e1;color:#334155}.monitor-protocol-tabs button.active{background:#2563eb;border-color:#2563eb;color:#fff}
.monitor-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.monitor-panel-head .monitor-cards{margin:0;min-width:240px;grid-template-columns:repeat(2,minmax(100px,1fr))}
.monitor-user-link{border:0;background:transparent;padding:0;color:#1d4ed8;font-weight:800;text-decoration:underline;cursor:pointer}.monitor-user-link:hover{color:#6d28d9}.good-num{color:#15803d;font-weight:800}.bad-num{color:#b91c1c;font-weight:800}.monitor-geo small{display:block;color:#64748b;margin-top:2px}.monitor-detail-panel{width:min(1180px,96vw)!important}.monitor-detail-grid{display:grid;grid-template-columns:.85fr 1.15fr;gap:16px;padding-top:6px}.monitor-detail-grid h3{margin:0 0 8px}.monitor-detail-grid .monitor-table-wrap{max-height:58vh}
@media(max-width:1000px){.monitor-detail-grid{grid-template-columns:1fr}.monitor-panel-head{flex-direction:column}.monitor-panel-head .monitor-cards{width:100%}}



/* R1.1.26 live multi-tier trainer flow + trainer-calibrated Email Analysis */
.ai-live-flow{min-width:1360px}.ai-live-top{display:grid;grid-template-columns:150px 170px minmax(480px,1fr) 145px 155px 180px 150px 165px;gap:12px;align-items:stretch}.ai-live-stage,.ai-tier-wrap{position:relative;border:1px solid #cbd5e1;border-radius:12px;background:#fff;padding:12px;box-shadow:0 4px 13px rgba(15,23,42,.05)}.ai-live-stage:not(:last-child)::after,.ai-tier-wrap::after{content:"→";position:absolute;right:-11px;top:46%;z-index:4;background:#eef4fa;color:#1d4ed8;font-size:18px;font-weight:900;line-height:22px}.ai-live-stage h4,.ai-tier-wrap h4{margin:0 0 8px;font-size:12px;color:#0f2f52}.ai-live-stage p{font-size:11px;color:#475569;line-height:1.42;margin:5px 0}.ai-live-stage .stage-live{display:inline-flex;margin-top:8px;padding:2px 7px;border-radius:999px;background:#dcfce7;color:#166534;font-size:9px;font-weight:900}.ai-tier-wrap{border-color:#8b5cf6;background:#fbfaff;padding:9px}.ai-tier-title{text-align:center;font-size:11px;font-weight:900;color:#5b21b6;margin:0 0 8px;text-transform:uppercase}.ai-tier-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.ai-tier-card{border:1px solid #dbe3ee;border-radius:9px;padding:8px;background:#fff;min-height:145px}.ai-tier-card h5{margin:0 0 5px;font-size:11px}.ai-tier-card ul{margin:5px 0 0;padding-left:16px;font-size:9.5px;color:#475569;line-height:1.45}.ai-tier-card.message{border-color:#86efac}.ai-tier-card.infrastructure{border-color:#93c5fd}.ai-tier-card.campaign{border-color:#fdba74}.engine-status{display:inline-flex;padding:2px 6px;border-radius:999px;font-size:8px;font-weight:900}.engine-status.operational{background:#dcfce7;color:#166534}.engine-status.development{background:#dbeafe;color:#1d4ed8}.engine-status.building{background:#ffedd5;color:#c2410c}.ai-correlation{margin-top:8px;border:1px solid #c4b5fd;border-radius:9px;padding:7px 9px;background:#f5f3ff;text-align:center;font-size:10px;color:#4c1d95;font-weight:800}.ai-flow-live-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 0 rgba(34,197,94,.5);animation:aiPulse 1.8s infinite}.ai-live-stage.live::before,.ai-tier-wrap::before{content:"";position:absolute;inset:-2px;border-radius:13px;border:1px solid rgba(34,197,94,.25);pointer-events:none;animation:aiGlow 2.4s ease-in-out infinite}.ai-training-row{display:grid;grid-template-columns:repeat(6,minmax(150px,1fr));gap:22px;margin-top:14px;min-width:1180px}.ai-training-row .ai-flow-step{min-height:128px}.ai-training-row .ai-flow-step:not(:last-child)::after{right:-18px}.ai-calibration-box{margin-top:12px;border:1px solid #bfdbfe;border-radius:11px;background:#f8fbff;padding:10px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;font-size:11px}.ai-calibration-box b{display:block;color:#0f2f52;margin-bottom:3px}.ai-ea-alignment{display:block;min-width:0}.ai-ea-verdict{border:1px solid #c4b5fd;border-radius:12px;background:#faf8ff;padding:12px;min-width:0}.ai-ea-verdict-head{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}.ai-ea-verdict-big{font-size:22px;font-weight:950}.ai-ea-engine-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:10px}.ai-ea-engine{border:1px solid #dbe3ee;border-radius:10px;background:#fff;padding:9px;font-size:11px;min-width:0;overflow-wrap:anywhere;word-break:break-word}.ai-ea-engine h5{margin:0 0 6px}.ai-ea-engine small{display:block;color:#64748b;margin-top:5px;overflow-wrap:anywhere}.ai-ea-evidence{border:1px solid #fed7aa;border-radius:12px;background:#fffaf3;padding:12px;min-width:0}.ai-ea-evidence h4{margin:0 0 8px}.ai-ea-separation{margin-top:10px;padding:8px;border:1px dashed #f59e0b;border-radius:8px;font-size:10px;color:#92400e;background:#fffbeb;font-weight:700}.ai-ea-modelbar{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin-top:9px}.ai-ea-modelbar div{border:1px solid #e2e8f0;border-radius:8px;padding:7px;background:#fff;min-width:0}.ai-ea-modelbar span{display:block;font-size:8px;text-transform:uppercase;color:#64748b;font-weight:800}.ai-ea-modelbar b{display:block;font-size:10px;margin-top:3px;overflow-wrap:anywhere;word-break:break-word}@keyframes aiPulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.45)}70%{box-shadow:0 0 0 7px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}@keyframes aiGlow{0%,100%{opacity:.25}50%{opacity:.9}}@media(max-width:1100px){.ai-ea-engine-grid{grid-template-columns:1fr}.ai-ea-modelbar{grid-template-columns:repeat(2,minmax(0,1fr))}}
.ai-graph-shell{border:1px solid #dbe3ee;border-radius:14px;background:linear-gradient(180deg,#f8fbff 0,#eef4fa 100%);padding:16px;overflow:auto}.ai-flow-grid{display:grid;grid-template-columns:repeat(7,minmax(145px,1fr));gap:28px;align-items:stretch;min-width:1180px}.ai-flow-step{position:relative;border:1px solid #cbd5e1;border-radius:13px;padding:14px 12px;background:#fff;box-shadow:0 5px 15px rgba(15,23,42,.06);min-height:112px}.ai-flow-step:not(:last-child)::after{content:"→";position:absolute;right:-23px;top:42%;font-size:24px;font-weight:900;color:#4f46e5}.ai-flow-step b,.ai-flow-step span,.ai-flow-step small{display:block}.ai-flow-step span{margin-top:7px;color:#475569;font-size:12px;line-height:1.4}.ai-flow-step small{margin-top:9px;color:#0f766e;font-weight:800}.ai-flow-step.live{border-color:#86efac;box-shadow:0 0 0 2px rgba(34,197,94,.08)}.ai-flow-step.waiting{border-color:#fde68a}.ai-flow-step.none{border-color:#cbd5e1}.ai-stage-no{display:inline-flex!important;align-items:center;justify-content:center;width:23px;height:23px;border-radius:50%;background:#1d4ed8;color:#fff;font-size:11px;margin-bottom:7px}.ai-metric-strip{display:grid;grid-template-columns:repeat(6,minmax(115px,1fr));gap:9px;margin-top:13px}.ai-live-chip{border:1px solid #dbe3ee;background:#fff;border-radius:10px;padding:9px 10px;min-width:0}.ai-live-chip span{display:block;font-size:10px;color:#64748b;text-transform:uppercase;font-weight:800;letter-spacing:.03em}.ai-live-chip b{display:block;margin-top:4px;font-size:15px;color:#0f172a;overflow-wrap:anywhere}.intel-graph{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:18px;position:relative}.intel-engine{position:relative;background:#fff;border:1px solid #cbd5e1;border-radius:14px;padding:16px;box-shadow:0 5px 16px rgba(15,23,42,.06)}.intel-engine h3{margin:0 0 10px}.intel-feature-list{display:grid;gap:7px}.intel-feature{display:flex;gap:8px;align-items:center;border-radius:8px;background:#f8fafc;padding:7px 9px;font-size:12px;color:#334155}.intel-feature::before{content:"◆";color:#4f46e5;font-size:9px}.intel-merge{display:flex;justify-content:center;align-items:center;margin:14px 0 4px}.intel-merge span{border:1px solid #a5b4fc;background:#eef2ff;color:#3730a3;border-radius:999px;padding:8px 16px;font-weight:900}.intel-verdict{max-width:580px;margin:0 auto;display:grid;grid-template-columns:1fr;gap:8px;text-align:center}.intel-shadow-node{border:2px solid #6366f1;background:#fff;border-radius:14px;padding:13px;font-weight:900}.intel-noaction{border:1px solid #fecaca;background:#fff7f7;color:#991b1b;border-radius:12px;padding:10px;font-weight:800}.shadow-boundary{margin-top:15px;border:2px dashed #ef4444;border-radius:13px;padding:12px 14px;background:#fff}.live-state-grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:9px}.live-state-grid .ai-live-chip{background:#fbfdff}.summary-count-link{min-width:42px;padding:3px 8px;border:1px solid #bfdbfe;border-radius:7px;background:#eff6ff;color:#1d4ed8;font-weight:800;cursor:pointer}.summary-count-link:hover{background:#dbeafe}.qintel-live-panel .qintel-kv{grid-template-columns:135px minmax(160px,1fr)}.qintel-live-panel .qintel-kv b{word-break:normal;overflow-wrap:anywhere}@media(max-width:900px){.intel-graph{grid-template-columns:1fr}.ai-metric-strip,.live-state-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
</head>
<body>
<div class="app-shell">
<aside class="sidebar">
  <div class="brand">
    <div class="brand-mark">✉</div>
    <div class="brand-copy">
      <div class="brand-title">Postfix Delivery</div>
      <div class="brand-subtitle">Postfix Delivery Dashboard</div>
    </div>
    <button id="sidebarPin" class="sidebar-pin" type="button" title="Unpin sidebar">📌</button>
  </div>

  <nav class="side-nav" aria-label="Primary navigation">
    <div class="nav-group">
      <div class="nav-group-label">Mail Operations</div>
      <button class="tabbtn active" data-tab="deliveryTab" data-tooltip="Delivery"><span class="nav-icon">▣</span><span>Delivery</span></button>
      <button class="tabbtn" data-tab="summaryTab" data-tooltip="Summary"><span class="nav-icon">▥</span><span>Summary</span></button>
      <button class="tabbtn" data-tab="monitorTab" data-tooltip="Monitor"><span class="nav-icon">◌</span><span>Monitor</span></button>
      <button class="tabbtn" data-tab="quarantineTab" data-tooltip="Amavis Quarantine"><span class="nav-icon">☣</span><span>Amavis Quarantine</span></button>
      <button class="tabbtn" data-tab="emailAnalysisTab" data-tooltip="Email Analysis"><span class="nav-icon">⌕</span><span>Email Analysis</span></button>
    </div>
    <div class="nav-group">
      <div class="nav-group-label">Security &amp; Intelligence</div>
      <button class="tabbtn" data-tab="spamListsTab" data-tooltip="Whitelist / Blacklist"><span class="nav-icon">✓</span><span>Whitelist / Blacklist</span></button>
    </div>
    <div class="nav-group">
      <div class="nav-group-label">Administration</div>
      <button class="tabbtn mail-size-admin-only" data-tab="mailSizeTab" data-tooltip="Mail Size"><span class="nav-icon">↕</span><span>Mail Size</span></button>
      <button class="tabbtn" data-tab="systemTab" data-tooltip="System Status"><span class="nav-icon">◉</span><span>System Status</span></button>
      <button class="tabbtn" data-tab="auditTab" data-tooltip="Audit"><span class="nav-icon">☷</span><span>Audit</span></button>
      <button class="tabbtn acl-admin-only" data-tab="aclTab" data-tooltip="User ACL"><span class="nav-icon">♙</span><span>User ACL</span></button>
    </div>
    <div class="nav-group nav-group-support">
      <div class="nav-group-label">Support</div>
      <button class="tabbtn" data-tab="helpTab" data-tooltip="Help"><span class="nav-icon">?</span><span>Help</span></button>
    </div>
  </nav>

  <div class="sidebar-foot">
    <div class="side-status">● Service Online</div>
    <div id="sideClock"></div>
    <button class="logout-btn" type="button" onclick="logoutDashboard()">Logout</button>
  </div>
</aside>

<section class="content-shell">
<button id="mobileMenuBtn" class="mobile-menu-btn" type="button" title="Open navigation">☰</button>
<div id="sidebarBackdrop" class="sidebar-backdrop"></div>
<div id="sidebarTooltipPortal" class="sidebar-tooltip-portal" role="tooltip" aria-hidden="true"></div>

<div id="quarantineIntelModal" class="qintel-modal" role="dialog" aria-modal="true" aria-labelledby="qintelTitle">
  <div class="qintel-panel">
    <div class="qintel-head">
      <div><h3 id="qintelTitle">Quarantine Intelligence</h3><div id="qintelSubtitle" class="page-subtitle"></div></div>
      <button type="button" class="secondary-btn" onclick="closeQuarantineIntelligence()">Close</button>
    </div>
    <div id="qintelBody" class="qintel-body"><div class="qintel-card">Loading…</div></div>
  </div>
</div>

<main>


<div id="flowTab" class="tabpane">
  <div class="svg-flow-toolbar">
    <div>
      <h2>Mail Flow Chart</h2>
      <div class="page-subtitle">Animated overlay on the approved INBOUND / COMMON-SHARED / OUTBOUND architecture — one shared Bayes DB; mail processing is unchanged</div>
    </div>
    <div class="svg-flow-actions">
      <button class="help-back-btn secondary-btn" type="button" onclick="returnToHelp()">← Back to Help</button>
      <span class="flow-live-badge"><i></i> ANIMATED FLOW</span>
      <span id="flowLastUpdated" hidden>Last Updated: -</span>
      <button id="mailFlowRefreshBtn" type="button" class="secondary-btn" hidden>Refresh</button>
      <button id="mailFlowFullscreenBtn" type="button" class="secondary-btn">Full Screen</button>
    </div>
  </div>
  <div id="flowMessage" class="section-message"></div>
  <div id="approvedMailFlowFrame" class="approved-mail-flow-frame">
    <div class="approved-mail-flow-stage">
      <img id="approvedMailFlowImage" class="approved-mail-flow-image" src="/api/mail-flow/approved-image" alt="Approved Mail Flow Chart showing inbound and outbound Postfix, Amavis, SpamAssassin, shared Bayes DB, quarantine, release and delivery paths">
      <svg class="approved-mail-flow-overlay" viewBox="0 0 1536 1024" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
        <!-- INBOUND: external sender -> Postfix -> Amavis -> policy -> routing -> local delivery -> mailbox -->
        <path class="anim-flow inbound" d="M216 105V143 M216 232V278 M190 355V402 M190 485V533 M190 609V660 M190 740V785"/>
        <!-- Inbound Amavis <-> SpamAssassin -->
        <path class="anim-flow inbound" d="M289 300H348 M348 329H289"/>
        <!-- OUTBOUND: local sender -> Postfix submission -> Amavis -> policy -> routing -> Postfix outbound -> Internet -->
        <path class="anim-flow outbound" d="M1228 106V140 M1123 231V278 M1123 354V402 M1123 486V533 M1123 609V660 M1188 748V786"/>
        <!-- Outbound Amavis <-> SpamAssassin -->
        <path class="anim-flow outbound" d="M1215 299H1287 M1287 329H1215"/>
        <!-- Shared Bayes connections; one DB for inbound and outbound -->
        <path class="anim-flow shared" d="M532 312H670 M814 312H1004 M742 406V533"/>
        <!-- Quarantine branches -->
        <path class="anim-flow quarantine" d="M338 572H625 M1036 572H864"/>
        <!-- Release / Learn and reinjection to Postfix Outbound -->
        <path class="anim-flow release" d="M742 630V684 M861 724H1050"/>
      </svg>
    </div>
  </div>
  <div id="mailFlowSvgFrame" class="mail-flow-svg-frame legacy-mail-flow-runtime" aria-hidden="true">
  <svg id="mailFlowSvg" class="mail-flow-svg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Dynamic mail server flow chart">
    <defs>
      <linearGradient id="hdrGrad" x1="0" x2="1"><stop offset="0" stop-color="#0b3158"/><stop offset="1" stop-color="#08243f"/></linearGradient>
      <linearGradient id="cardBlue" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#f5f9ff"/></linearGradient>
      <linearGradient id="cardGreen" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#f5fff7"/></linearGradient>
      <linearGradient id="quarGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff7f7"/><stop offset="1" stop-color="#ffeded"/></linearGradient>
      <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="3" stdDeviation="4" flood-color="#0f172a" flood-opacity=".12"/></filter>
      <marker id="arrowBlue" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" fill="#2563eb"/></marker>
      <marker id="arrowGreen" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" fill="#16a34a"/></marker>
      <marker id="arrowRed" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" fill="#dc2626"/></marker>
      <marker id="arrowPurple" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" fill="#7c3aed"/></marker>

      <symbol id="s-mail" viewBox="0 0 64 64"><rect x="7" y="13" width="50" height="38" rx="6" fill="none" stroke="currentColor" stroke-width="4"/><path d="M10 18l22 18 22-18" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></symbol>
      <symbol id="s-globe" viewBox="0 0 64 64"><circle cx="32" cy="32" r="25" fill="none" stroke="currentColor" stroke-width="4"/><path d="M7 32h50M32 7c8 7 12 16 12 25S40 50 32 57M32 7c-8 7-12 16-12 25S24 50 32 57" fill="none" stroke="currentColor" stroke-width="3"/></symbol>
      <symbol id="s-server" viewBox="0 0 64 64"><rect x="10" y="8" width="44" height="18" rx="4" fill="none" stroke="currentColor" stroke-width="4"/><rect x="10" y="38" width="44" height="18" rx="4" fill="none" stroke="currentColor" stroke-width="4"/><circle cx="18" cy="17" r="3" fill="currentColor"/><circle cx="18" cy="47" r="3" fill="currentColor"/><path d="M28 17h17M28 47h17" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></symbol>
      <symbol id="s-shield" viewBox="0 0 64 64"><path d="M32 6l21 8v15c0 13-8 23-21 29C19 52 11 42 11 29V14z" fill="none" stroke="currentColor" stroke-width="4"/><path d="M22 32l7 7 14-16" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></symbol>
      <symbol id="s-scan" viewBox="0 0 64 64"><circle cx="27" cy="27" r="16" fill="none" stroke="currentColor" stroke-width="4"/><path d="M39 39l16 16" stroke="currentColor" stroke-width="5" stroke-linecap="round"/><path d="M19 27h16M27 19v16" stroke="currentColor" stroke-width="3" stroke-linecap="round"/></symbol>
      <symbol id="s-users" viewBox="0 0 64 64"><circle cx="24" cy="22" r="9" fill="none" stroke="currentColor" stroke-width="4"/><circle cx="43" cy="25" r="7" fill="none" stroke="currentColor" stroke-width="3"/><path d="M8 53c1-12 7-18 16-18s15 6 16 18M36 53c1-9 5-14 12-14 5 0 9 3 11 9" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round"/></symbol>
      <symbol id="s-db" viewBox="0 0 64 64"><ellipse cx="32" cy="13" rx="21" ry="8" fill="none" stroke="currentColor" stroke-width="4"/><path d="M11 13v16c0 5 9 8 21 8s21-3 21-8V13M11 29v16c0 5 9 8 21 8s21-3 21-8V29" fill="none" stroke="currentColor" stroke-width="4"/></symbol>
      <symbol id="s-queue" viewBox="0 0 64 64"><rect x="10" y="10" width="44" height="12" rx="3" fill="none" stroke="currentColor" stroke-width="4"/><rect x="10" y="26" width="44" height="12" rx="3" fill="none" stroke="currentColor" stroke-width="4"/><rect x="10" y="42" width="44" height="12" rx="3" fill="none" stroke="currentColor" stroke-width="4"/></symbol>
      <symbol id="s-lock" viewBox="0 0 64 64"><rect x="12" y="27" width="40" height="30" rx="5" fill="none" stroke="currentColor" stroke-width="4"/><path d="M21 27v-8c0-8 5-13 11-13s11 5 11 13v8" fill="none" stroke="currentColor" stroke-width="4"/><circle cx="32" cy="41" r="4" fill="currentColor"/></symbol>
      <symbol id="s-chart" viewBox="0 0 64 64"><path d="M10 52h44" stroke="currentColor" stroke-width="4"/><rect x="14" y="32" width="8" height="16" rx="2" fill="currentColor"/><rect x="28" y="22" width="8" height="26" rx="2" fill="currentColor"/><rect x="42" y="12" width="8" height="36" rx="2" fill="currentColor"/></symbol>
      <symbol id="s-geo" viewBox="0 0 64 64"><path d="M32 57s18-16 18-31A18 18 0 1014 26c0 15 18 31 18 31z" fill="none" stroke="currentColor" stroke-width="4"/><circle cx="32" cy="26" r="7" fill="none" stroke="currentColor" stroke-width="4"/></symbol>
    </defs>

    <!-- title bar -->
    <rect x="8" y="8" width="1584" height="60" rx="14" fill="url(#hdrGrad)"/>
    <use href="#s-mail" x="28" y="20" width="34" height="34" color="#dbeafe"/>
    <text x="78" y="45" class="svg-title">MAIL FLOW CHART</text>
    <circle cx="1305" cy="38" r="7" fill="#22c55e" class="svg-pulse"/><text x="1320" y="43" class="svg-live">LIVE</text>
    <text id="svgFlowUpdated" x="1390" y="43" class="svg-updated">Updated: -</text>

    <!-- inbound panel -->
    <rect x="20" y="82" width="1230" height="265" rx="13" fill="url(#cardBlue)" stroke="#4f8fe8" stroke-width="2"/>
    <text x="42" y="112" class="svg-section inbound">INBOUND MAIL FLOW</text><text x="42" y="132" class="svg-sub">External → Home</text>

    <!-- bayes inbound -->
    <g class="svg-click" role="button" tabindex="0" data-flow-target="quarantineTab" aria-label="Open SpamAssassin quarantine intelligence"><use href="#s-db" x="642" y="92" width="42" height="42" color="#16a34a"/><text x="692" y="108" class="svg-small-bold">SpamAssassin</text><text x="692" y="125" class="svg-small-bold">Bayes DB (maildb)</text></g><path d="M664 136V165" stroke="#16a34a" stroke-width="2" stroke-dasharray="5 4" marker-end="url(#arrowGreen)"/>

    <!-- inbound nodes -->
    <g class="svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" aria-label="Open inbound delivery records"><use href="#s-globe" x="48" y="188" width="62" height="62" color="#145ac6"/><text x="79" y="270" text-anchor="middle" class="svg-node-label">Internet</text><text x="79" y="287" text-anchor="middle" class="svg-node-sub">External Senders</text></g>
    <path d="M120 220H162" class="flow-blue" marker-end="url(#arrowBlue)"/>
    <g class="svg-node svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" aria-label="Open Postfix SMTP Listener"><rect x="170" y="160" width="150" height="132" rx="10"/><use href="#s-server" x="216" y="174" width="58" height="58" color="#50657e"/><text x="245" y="247" text-anchor="middle" class="svg-node-label">Postfix SMTP Listener</text><text x="245" y="264" text-anchor="middle" class="svg-node-sub">Port 25</text><text x="245" y="282" text-anchor="middle" class="svg-active">● Active</text></g>
    <path d="M320 220H352" class="flow-blue" marker-end="url(#arrowBlue)"/>
    <g class="svg-node svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="BLOCKED" aria-label="Open Postscreen"><rect x="360" y="160" width="160" height="132" rx="10"/><use href="#s-shield" x="410" y="174" width="60" height="60" color="#50657e"/><text x="440" y="247" text-anchor="middle" class="svg-node-label">Postscreen</text><text x="440" y="264" text-anchor="middle" class="svg-node-sub">Spam / RBL Check</text><text id="svgInboundPassed" x="402" y="284" text-anchor="middle" class="svg-count">0</text><text id="svgBlocked" x="478" y="284" text-anchor="middle" class="svg-count danger">0</text></g>
    <path d="M520 220H552" class="flow-blue" marker-end="url(#arrowBlue)"/>
    <g class="svg-node svg-click" role="button" tabindex="0" data-flow-target="quarantineTab" aria-label="Open Amavis / SpamAssassin"><rect x="560" y="160" width="175" height="132" rx="10"/><use href="#s-scan" x="617" y="174" width="60" height="60" color="#16833b"/><text x="648" y="247" text-anchor="middle" class="svg-node-label">Amavis / SpamAssassin</text><text x="648" y="264" text-anchor="middle" class="svg-node-sub">Spam / Virus Scan</text><text id="svgInboundClean" x="608" y="284" text-anchor="middle" class="svg-count">0</text><text id="svgInboundHeld" x="690" y="284" text-anchor="middle" class="svg-count danger">0</text></g>
    <path d="M735 220H777" class="flow-green" marker-end="url(#arrowGreen)"/>
    <g class="svg-node svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="DELIVERED" aria-label="Open Postfix Local Delivery"><rect x="785" y="160" width="170" height="132" rx="10"/><use href="#s-mail" x="840" y="176" width="58" height="58" color="#50657e"/><text x="870" y="247" text-anchor="middle" class="svg-node-label">Postfix Local Delivery</text><text x="870" y="264" text-anchor="middle" class="svg-node-sub">Dovecot LMTP</text><text id="svgInboundDelivered" x="870" y="285" text-anchor="middle" class="svg-count">0</text></g>
    <path d="M955 220H997" class="flow-blue" marker-end="url(#arrowBlue)"/>
    <g class="svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="DELIVERED" aria-label="Open delivered mail"><use href="#s-users" x="1018" y="182" width="68" height="68" color="#145ac6"/><text x="1052" y="270" text-anchor="middle" class="svg-node-label">Home Users</text><text x="1052" y="287" text-anchor="middle" class="svg-node-sub">Mailboxes</text></g>

    <!-- outbound panel -->
<g id="outboundFlowGroup" transform="translate(0 70)">

    <rect x="20" y="360" width="1230" height="265" rx="13" fill="url(#cardGreen)" stroke="#55a86a" stroke-width="2"/>
    <text x="42" y="390" class="svg-section outbound">OUTBOUND MAIL FLOW</text><text x="42" y="410" class="svg-sub">Home → External</text>
    <g class="svg-click" role="button" tabindex="0" data-flow-target="quarantineTab" aria-label="Open SpamAssassin quarantine intelligence"><use href="#s-db" x="540" y="372" width="42" height="42" color="#16a34a"/><text x="590" y="388" class="svg-small-bold">SpamAssassin</text><text x="590" y="405" class="svg-small-bold">Bayes DB (maildb)</text></g><path d="M562 416V444" stroke="#16a34a" stroke-width="2" stroke-dasharray="5 4" marker-end="url(#arrowGreen)"/>
    <g class="svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" aria-label="Open outbound delivery records"><use href="#s-users" x="48" y="466" width="62" height="62" color="#16833b"/><text x="79" y="548" text-anchor="middle" class="svg-node-label">Internal Senders</text><text x="79" y="565" text-anchor="middle" class="svg-node-sub">Authenticated Users</text></g>
    <path d="M120 500H162" class="flow-blue" marker-end="url(#arrowBlue)"/>
    <g class="svg-node svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" aria-label="Open Postfix Submission"><rect x="170" y="440" width="150" height="132" rx="10"/><use href="#s-server" x="216" y="454" width="58" height="58" color="#50657e"/><text x="245" y="527" text-anchor="middle" class="svg-node-label">Postfix Submission</text><text x="245" y="544" text-anchor="middle" class="svg-node-sub">587 / 465</text><text x="245" y="562" text-anchor="middle" class="svg-active">● Active</text></g>
    <path d="M320 500H352" class="flow-blue" marker-end="url(#arrowBlue)"/>
    <g class="svg-node svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="DEFERRED" aria-label="Open Postfix Queue"><rect x="360" y="440" width="160" height="132" rx="10"/><use href="#s-queue" x="410" y="454" width="60" height="60" color="#50657e"/><text x="440" y="527" text-anchor="middle" class="svg-node-label">Postfix Queue</text><text x="440" y="544" text-anchor="middle" class="svg-node-sub">Queue Manager</text><text id="svgDeferred" x="440" y="565" text-anchor="middle" class="svg-count warn">0</text></g>
    <path d="M520 500H552" class="flow-blue" marker-end="url(#arrowBlue)"/>
    <g class="svg-node svg-click" role="button" tabindex="0" data-flow-target="quarantineTab" aria-label="Open Amavis / SpamAssassin"><rect x="560" y="440" width="175" height="132" rx="10"/><use href="#s-scan" x="617" y="454" width="60" height="60" color="#16833b"/><text x="648" y="527" text-anchor="middle" class="svg-node-label">Amavis / SpamAssassin</text><text x="648" y="544" text-anchor="middle" class="svg-node-sub">Policy / Virus Scan</text><text id="svgOutboundClean" x="608" y="565" text-anchor="middle" class="svg-count">0</text><text id="svgOutboundHeld" x="690" y="565" text-anchor="middle" class="svg-count danger">0</text></g>
    <path d="M735 500H777" class="flow-green" marker-end="url(#arrowGreen)"/>
    <g class="svg-node svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="DELIVERED" aria-label="Open Postfix SMTP Delivery"><rect x="785" y="440" width="170" height="132" rx="10"/><use href="#s-mail" x="840" y="456" width="58" height="58" color="#50657e"/><text x="870" y="527" text-anchor="middle" class="svg-node-label">Postfix SMTP Delivery</text><text x="870" y="544" text-anchor="middle" class="svg-node-sub">Destination MX</text><text x="870" y="562" text-anchor="middle" class="svg-active">● Active</text></g>
    <path d="M955 500H997" class="flow-blue" marker-end="url(#arrowBlue)"/>
    <g class="svg-click" role="button" tabindex="0" data-flow-target="summaryTab" aria-label="Open outbound mail summary"><use href="#s-globe" x="1018" y="462" width="68" height="68" color="#145ac6"/><text x="1052" y="548" text-anchor="middle" class="svg-node-label">Internet</text><text x="1052" y="565" text-anchor="middle" class="svg-node-sub">External Recipients</text></g>

    
</g>
<!-- shared quarantine — centered between inbound and outbound -->
    <path d="M648 292V312H620" class="flow-red" marker-end="url(#arrowRed)"/>
    <path d="M648 510V414H720" class="flow-red" marker-end="url(#arrowRed)"/>
    <g id="sharedQuarantineGroup">
      <rect x="475" y="310" width="390" height="104" rx="12" fill="url(#quarGrad)" stroke="#dc2626" stroke-width="2" filter="url(#shadow)" class="svg-click" role="button" tabindex="0" data-flow-target="quarantineTab" aria-label="Open Amavis Quarantine"/>
      <use href="#s-lock" x="492" y="334" width="44" height="44" color="#b91c1c"/>
      <text x="548" y="326" class="svg-kicker">SHARED QUARANTINE</text>
      <text x="548" y="348" class="svg-quar-title">AMAVIS QUARANTINE</text>
      <text x="548" y="366" class="svg-node-sub">/var/lib/amavis/virusmails</text>
      <line x1="620" y1="374" x2="620" y2="403" stroke="#fecaca"/>
      <line x1="700" y1="374" x2="700" y2="403" stroke="#fecaca"/>
      <text id="svgQuarantineTotal" x="580" y="391" text-anchor="middle" class="svg-count danger">0</text>
      <text x="580" y="405" text-anchor="middle" class="svg-tiny">TOTAL</text>
      <text id="svgQuarantineSpam" x="660" y="391" text-anchor="middle" class="svg-count danger">0</text>
      <text x="660" y="405" text-anchor="middle" class="svg-tiny">SPAM</text>
      <text id="svgQuarantineVirus" x="745" y="391" text-anchor="middle" class="svg-count danger">0</text>
      <text x="745" y="405" text-anchor="middle" class="svg-tiny">VIRUS / BANNED</text>
    </g>
    <path d="M865 362H900" class="flow-purple" marker-end="url(#arrowPurple)"/>
    <g class="svg-click" role="button" tabindex="0" data-flow-target="quarantineTab" aria-label="Open quarantine release and learning">
      <rect x="910" y="322" width="190" height="80" rx="10" fill="#faf7ff" stroke="#7c3aed" stroke-width="2" stroke-dasharray="6 4"/>
      <text x="1005" y="346" text-anchor="middle" class="svg-node-label purple">Release / Learn</text>
      <text x="1005" y="365" text-anchor="middle" class="svg-node-sub">HAM / SPAM</text>
      <text x="1005" y="386" text-anchor="middle" class="svg-linkish">Open Quarantine →</text>
    </g>

    <!-- mail operations right -->
    <rect x="1270" y="82" width="310" height="535" rx="13" fill="#fff" stroke="#4f8fe8" stroke-width="2"/>
    <text x="1425" y="116" text-anchor="middle" class="svg-section">MAIL OPERATIONS</text>
    <g class="opcard svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="DELIVERED" aria-label="Open Delivered"><rect x="1290" y="135" width="270" height="52" rx="9"/><use href="#s-mail" x="1303" y="146" width="30" height="30" color="#16a34a"/><text x="1345" y="157" class="svg-op-label">Delivered</text><text id="svgDelivered" x="1535" y="158" text-anchor="end" class="svg-op-count good">0</text><text x="1535" y="177" text-anchor="end" class="svg-linkish">View →</text></g>
    <g class="opcard svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="DEFERRED" aria-label="Open Deferred"><rect x="1290" y="197" width="270" height="52" rx="9"/><use href="#s-queue" x="1303" y="208" width="30" height="30" color="#f59e0b"/><text x="1345" y="219" class="svg-op-label">Deferred</text><text id="svgDeferredOps" x="1535" y="220" text-anchor="end" class="svg-op-count warn">0</text><text x="1535" y="239" text-anchor="end" class="svg-linkish">View →</text></g>
    <g class="opcard svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="BOUNCED" aria-label="Open Bounced"><rect x="1290" y="259" width="270" height="52" rx="9"/><use href="#s-mail" x="1303" y="270" width="30" height="30" color="#dc2626"/><text x="1345" y="281" class="svg-op-label">Bounced</text><text id="svgBounced" x="1535" y="282" text-anchor="end" class="svg-op-count danger">0</text><text x="1535" y="301" text-anchor="end" class="svg-linkish">View →</text></g>
    <g class="opcard svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="BLOCKED" aria-label="Open Blocked"><rect x="1290" y="321" width="270" height="52" rx="9"/><use href="#s-shield" x="1303" y="332" width="30" height="30" color="#7c3aed"/><text x="1345" y="343" class="svg-op-label">Blocked</text><text id="svgBlockedOps" x="1535" y="344" text-anchor="end" class="svg-op-count purple">0</text><text x="1535" y="363" text-anchor="end" class="svg-linkish">View →</text></g>
    <g class="opcard svg-click" role="button" tabindex="0" data-flow-target="quarantineTab" aria-label="Open Quarantine"><rect x="1290" y="383" width="270" height="52" rx="9"/><use href="#s-lock" x="1303" y="394" width="30" height="30" color="#dc2626"/><text x="1345" y="405" class="svg-op-label">Quarantine</text><text id="svgQuarantineOps" x="1535" y="406" text-anchor="end" class="svg-op-count danger">0</text><text x="1535" y="425" text-anchor="end" class="svg-linkish">View →</text></g>
    <g class="opcard svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="DEFERRED" aria-label="Open Queue"><rect x="1290" y="445" width="270" height="52" rx="9"/><use href="#s-queue" x="1303" y="456" width="30" height="30" color="#0891b2"/><text x="1345" y="467" class="svg-op-label">Queue</text><text id="svgQueue" x="1535" y="468" text-anchor="end" class="svg-op-count">0</text><text x="1535" y="487" text-anchor="end" class="svg-linkish">View →</text></g>
    <g class="opcard svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="BLOCKED" aria-label="Open RBL / Security"><rect x="1290" y="507" width="270" height="52" rx="9"/><use href="#s-shield" x="1303" y="518" width="30" height="30" color="#2563eb"/><text x="1345" y="529" class="svg-op-label">RBL / Security</text><text id="svgRbl" x="1535" y="530" text-anchor="end" class="svg-op-count">0</text><text x="1535" y="549" text-anchor="end" class="svg-linkish">View →</text></g>
    <g class="opcard svg-click" role="button" tabindex="0" data-flow-target="summaryTab" aria-label="Open Reports & Analytics"><rect x="1290" y="569" width="270" height="38" rx="9"/><use href="#s-chart" x="1303" y="574" width="28" height="28" color="#f97316"/><text x="1345" y="591" class="svg-op-label">Reports & Analytics</text><text id="svgTotal" x="1535" y="592" text-anchor="end" class="svg-op-count">0</text><text x="1535" y="611" text-anchor="end" class="svg-linkish">View →</text></g>

    <!-- bottom module strip -->
<g id="bottomDashboardGroup" transform="translate(0 -22)">

    <rect x="20" y="770" width="1230" height="110" rx="13" fill="#fff" stroke="#4f8fe8" stroke-width="2"/><text x="635" y="792" text-anchor="middle" class="svg-small-bold blue">POSTFIX DELIVERY DASHBOARD</text>
    <g class="modulebox svg-click" role="button" tabindex="0" data-flow-target="summaryTab" aria-label="Open Mail Direction"><rect x="36" y="805" width="182" height="58" rx="9"/><use href="#s-chart" x="48" y="818" width="34" height="34" color="#2563eb"/><text x="92" y="826" class="svg-small-bold">Mail Direction</text><text id="svgEmailsSent" x="92" y="846" class="svg-tiny">Sent 0</text><text id="svgEmailsReceived" x="160" y="846" class="svg-tiny">Recv 0</text></g>
    <g class="modulebox svg-click" role="button" tabindex="0" data-flow-target="summaryTab" aria-label="Open Geo IP Intelligence"><rect x="228" y="805" width="182" height="58" rx="9"/><use href="#s-geo" x="240" y="818" width="34" height="34" color="#0891b2"/><text x="284" y="826" class="svg-small-bold">Geo IP Intelligence</text><text x="284" y="846" class="svg-tiny">Country / ASN</text></g>
    <g class="modulebox svg-click" role="button" tabindex="0" data-flow-target="quarantineTab" aria-label="Open Quarantine Manager"><rect x="420" y="805" width="182" height="58" rx="9"/><use href="#s-lock" x="432" y="818" width="34" height="34" color="#16a34a"/><text x="476" y="826" class="svg-small-bold">Quarantine Manager</text><text id="svgModuleQuarantine" x="476" y="846" class="svg-tiny">0 items</text></g>
    <g class="modulebox svg-click" role="button" tabindex="0" data-flow-target="systemTab" aria-label="Open Mail Server Status"><rect x="612" y="805" width="182" height="58" rx="9"/><use href="#s-server" x="624" y="818" width="34" height="34" color="#f59e0b"/><text x="668" y="826" class="svg-small-bold">Mail Server Status</text><text x="668" y="846" class="svg-tiny">Services / Metrics</text></g>
    <g class="modulebox svg-click" role="button" tabindex="0" data-flow-target="deliveryTab" data-flow-status="BLOCKED" aria-label="Open RBL & Security"><rect x="804" y="805" width="182" height="58" rx="9"/><use href="#s-shield" x="816" y="818" width="34" height="34" color="#7c3aed"/><text x="860" y="826" class="svg-small-bold">RBL & Security</text><text id="svgModuleBlocked" x="860" y="846" class="svg-tiny">0 blocked</text></g>
    <g class="modulebox svg-click" role="button" tabindex="0" data-flow-target="summaryTab" aria-label="Open Reports & Analytics"><rect x="996" y="805" width="238" height="58" rx="9"/><use href="#s-chart" x="1008" y="818" width="34" height="34" color="#f97316"/><text x="1052" y="826" class="svg-small-bold">Reports & Analytics</text><text x="1052" y="846" class="svg-tiny">Volume / Trends / Domains</text></g>

    
</g>
<!-- db bar + legend -->
    <rect x="1270" y="630" width="310" height="250" rx="13" fill="#fff" stroke="#4f8fe8" stroke-width="2"/><text x="1425" y="660" text-anchor="middle" class="svg-section">LEGEND</text>
    <path d="M1300 692H1348" class="flow-blue" marker-end="url(#arrowBlue)"/><text x="1365" y="697" class="svg-tiny">Clean Mail Flow</text><path d="M1300 727H1348" class="flow-red" marker-end="url(#arrowRed)"/><text x="1365" y="732" class="svg-tiny">Spam / Infected</text><path d="M1300 762H1348" class="flow-purple" marker-end="url(#arrowPurple)"/><text x="1365" y="767" class="svg-tiny">Quarantine / Management</text><path d="M1300 797H1348" stroke="#16a34a" stroke-width="2" stroke-dasharray="6 4" marker-end="url(#arrowGreen)"/><text x="1365" y="802" class="svg-tiny">Bayes DB Connection</text><circle cx="1310" cy="838" r="6" fill="#16a34a"/><text x="1328" y="842" class="svg-tiny">Active</text><circle cx="1410" cy="838" r="6" fill="#dc2626"/><text x="1428" y="842" class="svg-tiny">Issue / Blocked</text>
    <use href="#s-db" x="570" y="868" width="24" height="24" color="#2563eb"/><text x="605" y="885" class="svg-tiny blue">MariaDB — Dashboard Data, Logs, Analytics, History & Bayes</text>
  </svg>
  </div>
</div>
<div id="deliveryTab" class="tabpane">
<div class="cards">
<div class="card" data-filter="all">All<b id="total">0</b></div>
<div class="card" data-filter="DELIVERED">Delivered<b id="delivered">0</b></div>
<div class="card" data-filter="DEFERRED">Deferred<b id="deferred">0</b></div>
<div class="card" data-filter="BOUNCED">Bounced<b id="bounced">0</b></div>
<div class="card" data-filter="BLOCKED">Blocked<b id="blocked">0</b></div>
<div class="card" data-filter="QUARANTINED">Quarantined<b id="spam">0</b></div>
<div class="card" data-filter="REJECTED">Rejected<b id="rejected">0</b></div>
<div class="card" data-filter="UNDELIVERED">Undelivered<b id="undelivered">0</b></div>
</div>

<div class="controls excel-filter-controls">
<select id="searchField" class="text-filter-operator" title="Search field">
<option value="all" selected>All fields</option>
<option value="from">From</option>
<option value="to">To</option>
</select>
<select id="searchOperator" class="text-filter-operator" title="Text filter operator">
<option value="equals">Equals</option>
<option value="not_equal">Not equal</option>
<option value="begins_with">Begins with</option>
<option value="ends_with">Ends with</option>
<option value="contains" selected>Contains</option>
<option value="does_not_contain">Does not contain</option>
</select>
<input id="search" placeholder="Search delivery records">
<input id="dateFrom" type="date" title="From date">
<input id="dateTo" type="date" title="To date">
<select id="filter">
<option value="all">All (0)</option>
<option value="DELIVERED">Delivered (0)</option>
<option value="DEFERRED">Deferred (0)</option>
<option value="BOUNCED">Bounced (0)</option>
<option value="BLOCKED">Blocked (0)</option>
<option value="QUARANTINED">Quarantined (0)</option>
<option value="REJECTED">Rejected (0)</option>
<option value="UNDELIVERED">Undelivered (0)</option>
</select>
<button onclick="load()">Refresh</button>
<button class="secondary-btn" type="button" onclick="clearDeliveryFilters()">Clear All</button>
<select id="deliveryPageSize" class="ux-page-size" title="Rows per page">
<option value="20">20 rows</option><option value="50" selected>50 rows</option><option value="100">100 rows</option><option value="200">200 rows</option>
</select>
<span id="deliveryFilterCount" class="ux-filter-badge">0 filters active</span>
<span id="deliveryLastRefresh" class="ux-last-refresh">Last refreshed: -</span>
<a id="download">Download TXT</a>
</div>

<div class="top-page-line"><span id="pgTop">Page 1 of 1</span></div>
<div id="msg"></div>

<div class="wrap">
<table class="delivery-compact">
<thead>
<tr>
<th>TIMESTAMP</th>
<th>QUEUE ID</th>
<th>STATUS</th>
<th>SENDER</th>
<th>RECIPIENT</th>
<th>DELIVERED TO HOST</th>
<th>DETAIL</th>
</tr>
</thead>
<tbody id="rows"></tbody>
</table>
</div>

<div class="pager">
<button id="deliveryPrev" onclick="page(-1)">Previous</button>
<span id="pg"></span>
<button id="deliveryNext" onclick="page(1)">Next</button>
</div>
</div>

<div id="summaryTab" class="tabpane">
<h3>Mail Direction Summary</h3>
<div class="summary-grid">
<div class="summary-card">Home → External<b id="homeExternal">0</b></div>
<div class="summary-card">External → Home<b id="externalHome">0</b></div>
<div class="summary-card">Home → Home<b id="homeHome">0</b></div>
<div class="summary-card">External → External<b id="externalExternal">0</b></div>
<div class="summary-card">Emails Sent<b id="emailsSent">0</b></div>
<div class="summary-card">Emails Received<b id="emailsReceived">0</b></div>
</div>
<div class="summary-note">
Home domain(s): <b id="homeDomains">-</b><br>
Total final recipient records: <b id="summaryTotal">0</b>
</div>

<div class="summary-section">
<h3>Daily Bounced Domain Summary</h3>
<div class="summary-table-wrap daily-bounce-compact">
<table class="summary-table daily-bounce-table">
<thead>
<tr><th class="bounce-date-col">Date</th><th>Domain</th><th class="num">Sent</th><th class="num">Recv</th><th class="num">Total</th></tr>
</thead>
<tbody id="dailyBounceRows"></tbody>
</table>
</div>
</div>
</div>

<div id="bounceDetailModal" class="flow-modal" onclick="if(event.target===this)closeBounceDetail()">
  <div class="bounce-detail-panel">
    <div class="flow-head">
      <div>
        <h2 style="margin:0">Bounce Details</h2>
        <div id="bounceDetailTitle" class="page-subtitle"></div>
      </div>
      <button type="button" onclick="closeBounceDetail()">Close</button>
    </div>
    <div id="bounceSubjectNote" class="summary-note"></div>
    <div class="summary-table-wrap bounce-detail-wrap">
      <table class="summary-table bounce-detail-table">
        <thead>
          <tr>
            <th>DATE</th>
            <th>FROM</th>
            <th>TO</th>
            <th>SUBJECT</th>
            <th>REASON FOR BOUNCE</th>
          </tr>
        </thead>
        <tbody id="bounceDetailRows"></tbody>
      </table>
    </div>
    <div id="bounceDetailCount" class="section-message"></div>
  </div>
</div>



<div id="aiTrainerFlowTab" class="tabpane">
  <div class="page-head"><div><h2>AI Trainer Flow — Multi-Tier Threat Intelligence Framework</h2><div class="page-subtitle"><span id="tfGenerationHeadline">independent-g1</span> · SHADOW ONLY · graphical live trainer state · live architecture aligned with Email Analysis</div></div><div class="page-head-actions"><button class="help-back-btn" type="button" onclick="returnToHelp()">← Back to Help</button><div class="auto-pill"><span>LIVE</span><b>10s</b></div></div></div>
  <div class="ai-graph-shell ai-live-flow">
    <div class="ai-live-top">
      <div class="ai-live-stage live"><i class="ai-stage-no">1</i><h4>Incoming Mail</h4><p>All mail via Postfix.</p><p>Delivered normally.</p><p>No AI influence.</p><span class="stage-live"><i class="ai-flow-live-dot"></i>&nbsp; LIVE</span></div>
      <div class="ai-live-stage live"><i class="ai-stage-no">2</i><h4>AI Feature Extraction</h4><p>Independent schema <b id="tfSchemaNode">v4</b>.</p><p>7 feature families.</p><p>No SA/Amavis decision features.</p><span class="stage-live">LIVE</span></div>
      <div class="ai-tier-wrap live">
        <div class="ai-tier-title">Multi-Tier Threat Intelligence Framework · Shadow Analysis</div>
        <div class="ai-tier-grid">
          <section class="ai-tier-card message"><h5>Message AI</h5><span class="engine-status operational">OPERATIONAL</span><ul><li>NLP / text patterns</li><li>Stylometry / structure</li><li>URL / domain analysis</li><li>MIME / attachment</li><li>Authentication alignment</li><li>Header / sender anomaly</li></ul></section>
          <section class="ai-tier-card infrastructure"><h5>Infrastructure AI</h5><span class="engine-status operational">OPERATIONAL · LOCAL</span><ul><li>SPF / DKIM / DMARC identity evidence</li><li>Observed source IP + offline ASN</li><li>Received PTR/from ↔ HELO consistency</li><li>Reply-To / Message-ID alignment</li><li>Sender IP / ASN rotation history</li><li>No live reputation dependency</li></ul></section>
          <section class="ai-tier-card campaign"><h5>Campaign AI</h5><span class="engine-status operational">OPERATIONAL · LOCAL</span><ul><li>Template fingerprint clustering</li><li>Snowshoe sender-domain rotation</li><li>Botnet-like source-IP diversity</li><li>Multi-ASN campaign evidence</li><li>URL-domain-set correlation</li><li>30-day local observation window</li></ul></section>
        </div>
        <div class="ai-correlation">Correlation Engine · SHADOW EXPLAINABLE v1 · combines Message + Infrastructure + Campaign evidence; no delivery authority</div>
      </div>
      <div class="ai-live-stage live"><i class="ai-stage-no">3</i><h4>Shadow Prediction</h4><p>AI predicts only.</p><p>Confidence + reasons.</p><small id="tfActiveNode">Active: None</small></div>
      <div class="ai-live-stage live"><i class="ai-stage-no">4</i><h4>Admin Review</h4><p>Admin reviews message and AI evidence.</p><p>Prediction ≠ ground truth.</p></div>
      <div class="ai-live-stage live"><i class="ai-stage-no">5</i><h4>Admin Ground Truth</h4><p>HAM / SPAM authoritative label.</p><p>UCE / PHISH / BEC may be review context.</p><small id="tfLabelsNode">0 approved labels</small></div>
      <div class="ai-live-stage live"><i class="ai-stage-no">6</i><h4>Store in MariaDB</h4><p>Generation and source retained.</p><p>Forward-only evidence lifecycle.</p></div>
      <div class="ai-live-stage live"><i class="ai-stage-no">7</i><h4>Eligible Dataset</h4><p>Admin approved only.</p><p>Legacy generations excluded.</p><p>Balanced and validated.</p></div>
    </div>
    <div class="ai-training-row">
      <div class="ai-flow-step live"><i class="ai-stage-no">8</i><b>Dataset Preflight</b><span>Enough HAM/SPAM, no legacy rows, no SA/Amavis features, duplicate/invalid checks, Hard-HAM present.</span><small>Any failed gate stops training</small></div>
      <div id="tfTrainingNode" class="ai-flow-step waiting"><i class="ai-stage-no">9</i><b>Train Candidate</b><span>balanced-logistic-regression-hashed-v4-authneutral-independent</span><small id="tfCandidateNode">Candidate: None</small></div>
      <div id="tfValidationNode" class="ai-flow-step waiting"><i class="ai-stage-no">10</i><b>Validate Candidate</b><span>Hold-out validation, stratified split, Hard-HAM and subtype evaluation.</span><small id="tfValidationNodeText">Waiting for candidate</small></div>
      <div class="ai-flow-step live"><i class="ai-stage-no">11</i><b>Calculate Metrics</b><span>Accuracy, balanced accuracy, precision/recall/F1, HAM→SPAM FP, SPAM→HAM FN.</span><small>Quality before headline accuracy</small></div>
      <div class="ai-flow-step live"><i class="ai-stage-no">12</i><b>Write Candidate</b><span>Model file, Candidate ID, schema and generation.</span><small>Candidate remains SHADOW ONLY</small></div>
      <div class="ai-flow-step live"><i class="ai-stage-no">13</i><b>Record Training Run</b><span>Store run and metrics in MariaDB with audit history.</span><small>7-day calibration follows</small></div>
    </div>
    <div class="ai-calibration-box"><div><b>Candidate Status</b>Shadow predictions continue; no mail action.</div><div><b>Admin 7-Day Calibration</b>Review metrics, error patterns, Hard-HAM and hard cases.</div><div><b>Decision</b>KEEP / REJECT / PROMOTE — promotion still does not mean enforcement during validation.</div></div>
    <div class="ai-metric-strip">
      <div class="ai-live-chip"><span>Generation</span><b id="tfGeneration">-</b></div><div class="ai-live-chip"><span>Approved Labels</span><b id="tfLabels">0</b></div><div class="ai-live-chip"><span>HAM / SPAM</span><b id="tfHamSpam">0 / 0</b></div><div class="ai-live-chip"><span>Hard-HAM</span><b id="tfHardHam">0</b></div><div class="ai-live-chip"><span>Candidate</span><b id="tfCandidate">None</b></div><div class="ai-live-chip"><span>Next Auto-train</span><b id="tfNext">-</b></div>
    </div>
  </div>
  <div class="summary-section"><h3>Live Candidate Metrics</h3><div id="trainerLiveMetrics" class="summary-note">Waiting for live trainer status…</div></div>
</div>

<div id="aiIntelligenceTab" class="tabpane">
  <div class="page-head"><div><h2>AI Intelligence Layout</h2><div class="page-subtitle">Independent evidence architecture · graphical SHADOW ONLY intelligence map</div></div><div class="page-head-actions"><button class="help-back-btn" type="button" onclick="returnToHelp()">← Back to Help</button><div class="auto-pill"><span>LIVE</span><b>10s</b></div></div></div>
  <div class="ai-graph-shell">
    <div class="intel-graph">
      <section class="intel-engine"><h3>✉ Message AI</h3><div class="intel-feature-list"><div class="intel-feature">HAM/SPAM shadow classification</div><div class="intel-feature">NLP / text patterns</div><div class="intel-feature">Authentication alignment</div><div class="intel-feature">Sender / header anomaly</div><div class="intel-feature">URL / domain structure</div><div class="intel-feature">MIME / attachment metadata</div><div class="intel-feature">Structural stylometry</div></div></section>
      <section class="intel-engine"><h3>⌁ Infrastructure AI</h3><div class="intel-feature-list"><div class="intel-feature">Connecting IP / ASN traits</div><div class="intel-feature">PTR / HELO consistency</div><div class="intel-feature">BPH indicators</div><div class="intel-feature">Abused cloud / ESP</div><div class="intel-feature">Compromised SMTP indicators</div><div class="intel-feature">Network rotation evidence</div></div></section>
      <section class="intel-engine"><h3>◎ Campaign AI</h3><div class="intel-feature-list"><div class="intel-feature">Botnet clustering</div><div class="intel-feature">Snowshoe patterns</div><div class="intel-feature">UCE clusters</div><div class="intel-feature">Sender / IP / domain rotation</div><div class="intel-feature">Template / campaign similarity</div><div class="intel-feature">Historical independent patterns</div></div></section>
    </div>
    <div class="intel-merge"><span>Independent Evidence Fusion</span></div>
    <div class="intel-verdict"><div class="intel-shadow-node">SHADOW VERDICT · <span id="intelVerdictState">No active independent model</span></div><div class="intel-noaction">NO MAIL ACTION — cannot reject, quarantine, release, redirect, delete or alter Postfix/Amavis delivery</div></div>
    <div class="shadow-boundary"><b>Safety Boundary:</b> SpamAssassin and Amavis evidence may be displayed independently for operator comparison, but their scores/verdicts do not become AI ground truth or independent AI feature inputs.</div>
    <div class="live-state-grid" style="margin-top:13px">
      <div class="ai-live-chip"><span>Generation</span><b id="intelGeneration">-</b></div><div class="ai-live-chip"><span>Feature Schema</span><b id="intelSchema">-</b></div><div class="ai-live-chip"><span>Active Model</span><b id="intelActive">None</b></div><div class="ai-live-chip"><span>Candidate</span><b id="intelCandidate">None</b></div><div class="ai-live-chip"><span>Amavis AI Hook</span><b id="intelAmavisHook">DISABLED</b></div>
    </div>
  </div>
  <div class="summary-section"><h3>Live Intelligence State</h3><div id="intelLiveState" class="summary-note">Waiting for live trainer status…</div></div>
</div>

<div id="quarantineTab" class="tabpane">
<div class="page-head">
  <div>
    <h2>Amavis Quarantine Management</h2>
    <div class="page-subtitle">Review, release or mark emails as spam</div>
  </div>
  <div class="page-head-actions">
    <button class="icon-btn" title="Refresh" onclick="loadQuarantine(1)">↻</button>
    <div class="auto-pill"><span>Auto refresh</span><b>ON</b></div>
  </div>
</div>

<div class="qhero">
  <button class="qmetric total qmetric-filter active" type="button" data-qfilter="all">
    <div class="metric-icon">✉</div>
    <div><span>Total Visible</span><b id="qTotal">0</b><small>Emails</small></div>
  </button>
  <button class="qmetric spam qmetric-filter" type="button" data-qfilter="Spam">
    <div class="metric-icon">◇</div>
    <div><span>Spam</span><b id="qSpam">0</b><small>Emails</small></div>
  </button>
  <button class="qmetric virus qmetric-filter" type="button" data-qfilter="Virus">
    <div class="metric-icon">☣</div>
    <div><span>Virus</span><b id="qVirus">0</b><small>Emails</small></div>
  </button>
  <button class="qmetric banned qmetric-filter" type="button" data-qfilter="Banned">
    <div class="metric-icon">✋</div>
    <div><span>Banned</span><b id="qBanned">0</b><small>Emails</small></div>
  </button>
  <div class="qmetric released qmetric-static" aria-label="Released quarantine audit count">
    <div class="metric-icon">✓</div>
    <div><span>Released</span><b id="qReleased">0</b><small>Count only</small></div>
  </div>
  <div class="qreview-metric" aria-label="Admin Review Queue">
    <div class="metric-icon">☑</div>
    <div><span>Admin Review Queue</span><b id="qReviewRequired">0</b><small>Decision Required</small><br><button type="button" class="qreview-link" onclick="openRequiredReviewQueue()">Review Pending Messages</button></div>
  </div>
  <div class="qmetric updated">
    <div class="metric-icon">◷</div>
    <div>
      <span>Last Updated</span>
      <b id="qLastUpdated">-</b>
      <small>Quarantine Dir (ro)</small>
      <small>/host-amavis/virusmails</small>
    </div>
  </div>
</div>

<div class="qtoolbar">
  <div class="qsearch-wrap excel-text-filter">
    <select id="qSearchField" class="text-filter-operator" title="Search field">
<option value="all" selected>All fields</option>
<option value="from">From</option>
<option value="to">To</option>
    </select>
    <select id="qSearchOperator" class="text-filter-operator" title="Text filter operator">
<option value="equals">Equals</option>
<option value="not_equal">Not equal</option>
<option value="begins_with">Begins with</option>
<option value="ends_with">Ends with</option>
<option value="contains" selected>Contains</option>
<option value="does_not_contain">Does not contain</option>
    </select>
    <input id="qSearch" placeholder="Search by subject, sender, recipient or ID">
  </div>
  <div class="filter-group">
    <label>Date</label>
    <input id="qDate" type="date" title="Quarantine date">
  </div>
  <div class="filter-group"><label>Admin Decision</label><select id="qAdminDecision" onchange="setQuarantineAdminDecision(this.value)"><option value="all">All</option><option value="required">Required</option><option value="completed">Completed</option></select></div>
  <button class="secondary-btn" onclick="loadQuarantine(1)">Refresh</button>
  <button class="secondary-btn" type="button" onclick="clearQuarantineFilters()">Clear All</button>
  <select id="qPageSize" class="ux-page-size" title="Rows per page">
    <option value="20" selected>20 rows</option><option value="50">50 rows</option><option value="100">100 rows</option><option value="200">200 rows</option>
  </select>
  <span id="qFilterCount" class="ux-filter-badge">0 filters active</span>
  <span id="qLastRefresh" class="ux-last-refresh">Last refreshed: -</span>
  <button class="primary-btn qadmin-only" onclick="forceQuarantineRefresh()">Rescan Files</button>
</div>

<div class="top-page-line quarantine-top-pager">
  <div class="pager qpager">
    <button id="qTopPrev" type="button" onclick="qPage(-1)" aria-label="Previous quarantine page">‹</button>
    <span id="qPgTop">Page 1 of 1</span>
    <button id="qTopNext" type="button" onclick="qPage(1)" aria-label="Next quarantine page">›</button>
  </div>
</div>

<div class="qbulkbar qadmin-only">
  <label class="qbulkselect">
    <input id="qSelectAllVisible" type="checkbox">
    <span>Select all visible</span>
  </label>
  <span id="qSelectedCount" class="qselected-count">Selected: 0</span>
  <div class="qbulk-actions">
    <button id="qBulkRelease" class="secondary-btn qbulk-release" type="button" disabled>RELEASE SELECTED</button>
    <button id="qBulkSpam" class="primary-btn qbulk-spam" type="button" disabled>MARK SELECTED AS SPAM</button>
  </div>
  <span id="qBulkResult" class="qbulk-result"></span>
</div>

<div id="qMessage" class="section-message"></div>


<div class="qlist-head" aria-hidden="true">
  <div>Category / Time</div>
  <div>Message Details</div>
  <div>SPF / DKIM</div>
  <div>Spam Score</div>
  <div>Actions</div>
</div>

<div id="qRows" class="qmail-list"></div>

<div class="qfooterbar">
  <div id="qRangeText">Showing quarantine emails</div>
  <div class="pager qpager">
    <button id="qBottomPrev" type="button" onclick="qPage(-1)" aria-label="Previous quarantine page">‹</button>
    <span id="qPg"></span>
    <button id="qBottomNext" type="button" onclick="qPage(1)" aria-label="Next quarantine page">›</button>
  </div>
</div>

<div class="info-note">
  <div class="info-icon">i</div>
  <div>
    <b>Note</b>
    <div>Quarantine directory is mounted read-only. Emails are never deleted, moved or modified.</div>
    <div>Use Release + HAM for legitimate mail. Use Mark Spam for confirmed spam. Intelligence remains available from Message Details.</div>
  </div>
</div>

<div class="qdomains"><b>Top sender domains</b><div id="qDomains">-</div></div>
</div>


<div id="emailAnalysisTab" class="tabpane">
  <div class="page-head"><div><h2>Email Analysis</h2><div class="page-subtitle">Trainer-calibrated independent-g1 / schema-v4 shadow analysis — same candidate architecture as AI Trainer, local processing only</div></div><div class="auto-pill"><span>SHADOW</span><b>ONLY</b></div></div>
  <div id="emailAnalysisMessage" class="section-message"></div>
  <div class="email-analysis-grid">
    <section class="email-analysis-card">
      <h3>Message Input</h3>
      <div class="email-analysis-note">Upload .eml (RFC822/MIME) or .msg (Microsoft Outlook), or paste raw RFC822 source. The workbench uses the current independent-g1 candidate in SHADOW ONLY mode when available. Analysis never becomes ground truth automatically and is not added to quarantine, Bayes learning or AI training.</div>
      <div id="emailAnalysisDrop" class="email-analysis-drop">Drop an <b>.eml</b> or <b>.msg</b> file here, or choose a file below.</div>
      <div class="email-analysis-actions"><input id="emailAnalysisFile" type="file" accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook"><button type="button" onclick="analyzeEmailMessage()">Analyze Email</button><button type="button" class="secondary-btn" onclick="clearEmailAnalysis()">Clear</button></div>
      <textarea id="emailAnalysisRaw" spellcheck="false" placeholder="Paste complete RFC822 message source here...&#10;&#10;Received: ...&#10;From: ...&#10;To: ...&#10;Subject: ..."></textarea>
    </section>
    <section class="email-analysis-card email-analysis-result-shell">
      <h3>Analysis Result</h3>
      <div id="emailAnalysisResult" class="email-analysis-note">No message analyzed yet.</div>
    </section>
  </div>
</div>

<div id="spamListsTab" class="tabpane">
  <div class="page-head">
    <div>
      <h2>SpamAssassin Whitelist / Blacklist</h2>
      <div class="page-subtitle">Manage SQL-backed global, domain and user preferences</div>
    </div>
    <div class="page-head-actions">
      <button class="secondary-btn" type="button" onclick="loadSpamLists(1)">Refresh</button>
      <button class="secondary-btn" type="button" onclick="exportSpamLists()">Export .cf</button>
      <button class="secondary-btn" type="button" onclick="openSpamConflictCheck()">Check Conflicts</button>
      <button id="spamListImportButton" class="secondary-btn spam-list-admin-only" type="button" onclick="openSpamListImport()">Import .cf</button>
      <button id="spamListAddButton" class="primary-btn spam-list-admin-only" type="button" onclick="openSpamListEditor()">Add Entry</button>
    </div>
  </div>

  <div class="sl-kpis">
    <div class="sl-kpi"><span>Total entries</span><b id="slTotal">0</b></div>
    <div class="sl-kpi whitelist"><span>Whitelist on page</span><b id="slWhite">0</b></div>
    <div class="sl-kpi blacklist"><span>Blacklist on page</span><b id="slBlack">0</b></div>
    <div class="sl-kpi"><span>SQL Database</span><b id="slDbState">-</b></div>
  </div>

  <div class="controls excel-filter-controls sl-controls">
    <div class="sl-search-wrap">
      <input id="slSearch" placeholder="Search username/domain, preference or value">
      <button class="sl-search-btn" type="button" onclick="loadSpamLists(1)">Search</button>
      <button class="sl-clear-btn" type="button" onclick="clearSpamListSearch()">Clear</button>
    </div>
    <select id="slPreference">
      <option value="all">All preferences</option>
      <option value="whitelist_auth">whitelist_auth</option>
      <option value="whitelist_from">whitelist_from</option>
      <option value="blacklist_from">blacklist_from</option>
    </select>
    <select id="slScope">
      <option value="all">All scopes</option>
      <option value="global">Global</option>
      <option value="domain">Domain</option>
      <option value="user">User</option>
    </select>
    <select id="slPageSize" class="ux-page-size" title="Rows per page">
      <option value="20">20 rows</option><option value="50" selected>50 rows</option><option value="100">100 rows</option><option value="200">200 rows</option>
    </select>
    <span id="slFilterCount" class="ux-filter-badge">0 filters active</span>
    <span id="slLastRefresh" class="ux-last-refresh">Last refreshed: -</span>
  </div>

  <div class="top-page-line"><span id="slPgTop">Page 1 of 1</span></div>
  <div id="slMessage" class="section-message"></div>

  <div class="sl-bulkbar">
    <div class="sl-bulk-left">
      <span id="slSelectedCount" class="sl-selected-count">0 selected</span>
      <button id="slBulkDelete" class="sl-bulk-delete spam-list-admin-only" type="button" disabled onclick="bulkDeleteSpamLists()">Delete Selected</button>
    </div>
    <div class="sl-bulk-right"><span class="page-subtitle">Maximum 100 entries per bulk delete</span></div>
  </div>

  <div class="sl-table-wrap">
    <table class="sl-table">
      <thead>
        <tr>
          <th class="sl-select-cell"><input id="slSelectVisible" class="sl-select-visible" type="checkbox" title="Select visible entries" onchange="toggleSpamListVisible(this.checked)"></th>
          <th>ID</th>
          <th>LIST</th>
          <th>SCOPE</th>
          <th>USERNAME / DOMAIN</th>
          <th>PREFERENCE</th>
          <th>VALUE</th>
          <th>ACTIONS</th>
        </tr>
      </thead>
      <tbody id="slRows"></tbody>
    </table>
  </div>

  <div class="pager">
    <button onclick="spamListPage(-1)">Previous</button>
    <span id="slPg">Page 1 of 1</span>
    <button onclick="spamListPage(1)">Next</button>
  </div>

  <div id="spamListEditor" class="sl-editor" hidden>
    <div class="sl-editor-card">
      <div class="flow-head">
        <div>
          <h3 id="slEditorTitle" style="margin:0">Add Whitelist / Blacklist Entry</h3>
          <div class="page-subtitle">SpamAssassin SQL userpref entry</div>
        </div>
        <button type="button" onclick="closeSpamListEditor()">Close</button>
      </div>
      <input id="slPrefId" type="hidden">

      <div class="sl-form-grid">
        <label>Scope
          <select id="slEditScope" onchange="updateSpamScopeForm()">
            <option value="global">Global</option>
            <option value="domain">Domain</option>
            <option value="user">User</option>
          </select>
        </label>

        <label id="slPrincipalLabel">Username / Domain
          <input id="slEditPrincipal" maxlength="100" placeholder="user@example.com">
        </label>

        <label>Preference
          <select id="slEditPreference">
            <optgroup label="Whitelist">
              <option value="whitelist_auth">whitelist_auth</option>
              <option value="whitelist_from">whitelist_from</option>
            </optgroup>
            <optgroup label="Blacklist">
              <option value="blacklist_from">blacklist_from</option>
            </optgroup>
          </select>
        </label>

        <label>Value
          <input id="slEditValue" maxlength="100" placeholder="user@example.com or *@example.com">
        </label>
      </div>

      <div class="sl-format-note">
        <b>Scope storage:</b>
        Global = <code>@GLOBAL</code>,
        Domain = <code>%example.com</code>,
        User = <code>user@example.com</code>.
      </div>

      <div id="slEditorMessage" class="section-message"></div>
      <div class="sl-editor-actions">
        <button class="secondary-btn" type="button" onclick="closeSpamListEditor()">Cancel</button>
        <button class="primary-btn" type="button" onclick="saveSpamListEntry()">Save</button>
      </div>
    </div>
  </div>

  <div id="spamListImport" class="sl-editor" hidden>
    <div class="sl-editor-card sl-import-card">
      <div class="flow-head">
        <div>
          <h3 style="margin:0">Bulk Import Whitelist / Blacklist</h3>
          <div class="page-subtitle">SpamAssassin .cf / text format · preview before commit</div>
        </div>
        <button type="button" onclick="closeSpamListImport()">Close</button>
      </div>

      <div class="sl-import-grid">
        <label class="sl-import-file">Import file
          <input id="slImportFile" type="file" accept=".cf,.txt,text/plain">
        </label>
        <label>Target scope
          <select id="slImportScope" onchange="updateSpamImportScope()">
            <option value="global">Global</option>
            <option value="domain">Domain</option>
            <option value="user">User</option>
          </select>
        </label>
        <label id="slImportPrincipalLabel">Username / Domain
          <input id="slImportPrincipal" maxlength="100" placeholder="Not required for Global" disabled>
        </label>
      </div>

      <div class="sl-format-note">
        Accepted directives: <code>whitelist_from</code>, <code>whitelist_auth</code>, <code>blacklist_from</code>.
        Blank lines and lines beginning with <code>#</code> are ignored.
      </div>

      <div id="slImportMessage" class="section-message"></div>
      <div id="slImportPreview" hidden>
        <div class="sl-import-stats">
          <div class="sl-import-stat add"><span>Will Add</span><b id="slImportAdd">0</b></div>
          <div class="sl-import-stat dup"><span>Duplicate</span><b id="slImportDup">0</b></div>
          <div class="sl-import-stat invalid"><span>Invalid</span><b id="slImportInvalid">0</b></div>
          <div class="sl-import-stat"><span>Skipped</span><b id="slImportSkipped">0</b></div>
        </div>
        <div class="sl-import-preview"><div id="slImportRows" class="sl-import-results"></div></div>
      </div>

      <div class="sl-editor-actions">
        <button class="secondary-btn" type="button" onclick="closeSpamListImport()">Cancel</button>
        <button class="secondary-btn" type="button" onclick="previewSpamListImport()">Preview</button>
        <button id="slImportCommit" class="primary-btn" type="button" disabled onclick="commitSpamListImport()">Import</button>
      </div>
    </div>
  </div>
</div>




<div id="mailSizeTab" class="tabpane">
  <div class="page-head">
    <div>
      <h2>Manage Email Size</h2>
      <div class="page-subtitle">Postfix message-size limits for Outlook and Webmail</div>
    </div>
    <div class="page-head-actions">
      <button class="secondary-btn" type="button" onclick="loadMailSizeManager()">Refresh</button>
    </div>
  </div>

  <div id="mailSizeMessage" class="section-message"></div>

  <div class="ms-layout">
    <div class="ms-left">
      <section class="ms-card ms-calculator">
        <div class="ms-card-title">Base64 Size Calculator</div>
        <div class="ms-card-subtitle">Estimate the Postfix limit needed after MIME/Base64 overhead.</div>
        <div class="ms-calc-grid">
          <label>
            <span>Desired attachment size</span>
            <div class="ms-number-input">
              <input id="mailSizeWanted" type="number" min="1" max="99" value="20">
              <b>MB</b>
            </div>
          </label>
          <div>
            <span>Required limit</span>
            <div class="ms-calc-result"><b id="mailSizeRequired">28</b> MB</div>
          </div>
        </div>
        <div class="ms-formula">Desired size × 1.34 + 1 MB buffer, capped at 99 MB.</div>
        <div id="mailSizeCooldown" class="ms-cooldown" hidden></div>
      </section>

      <section class="ms-card">
        <div class="ms-card-head">
          <div>
            <div class="ms-card-title">Recent Backups</div>
            <div class="ms-card-subtitle">Latest configuration backups</div>
          </div>
        </div>
        <div id="mailSizeBackups"></div>
      </section>
    </div>

    <div class="ms-config-stack ms-profile-pair">
      <section class="ms-card ms-profile outlook">
        <div class="ms-profile-accent"></div>
        <div class="ms-profile-body">
          <div class="ms-profile-head">
            <div>
              <div class="ms-card-title">Submission — Port 587</div>
              <div class="ms-card-subtitle">Authenticated submission clients</div>
            </div>
            <span class="ms-chip">submission</span>
          </div>
          <div id="mailSizeOutlook"></div>
        </div>
      </section>

      <section class="ms-card ms-profile webmail">
        <div class="ms-profile-accent"></div>
        <div class="ms-profile-body">
          <div class="ms-profile-head">
            <div>
              <div class="ms-card-title">Webmail</div>
              <div class="ms-card-subtitle">Webmail message-size policy</div>
            </div>
            <span class="ms-chip">webmail</span>
          </div>
          <div id="mailSizeWebmail"></div>
        </div>
      </section>
    </div>
  </div>

  <div class="ms-bottom-grid">
    <section class="ms-card">
      <div class="ms-card-head">
        <div>
          <div class="ms-card-title">Audit Trail</div>
          <div class="ms-card-subtitle">Latest host-side Mail Size changes</div>
        </div>
      </div>
      <div id="mailSizeAudit" class="ms-audit-list"></div>
    </section>

    <section class="ms-card">
      <div class="ms-card-title">Operational Controls</div>
      <table class="ms-notes-table">
        <tbody>
          <tr><td>Deployment</td><td>Restricted host deploy helper</td></tr>
          <tr><td>Cooldown</td><td>30 seconds between configuration updates</td></tr>
          <tr><td>Maximum</td><td>99 MB per configured profile</td></tr>
          <tr><td>Rollback</td><td>Recent backups can be restored</td></tr>
          <tr><td>Dashboard ACL</td><td>Mail Size Admin permission required</td></tr>
        </tbody>
      </table>
    </section>
  </div>
</div>


<div id="spamConflictModal" class="flow-modal" onclick="if(event.target===this)closeSpamConflictCheck()">
  <div class="conflict-modal-panel">
    <div class="flow-head">
      <div><h2 style="margin:0">SpamAssassin List Conflicts</h2><div class="page-subtitle">Same scope/value present in both whitelist and blacklist preferences</div></div>
      <button type="button" onclick="closeSpamConflictCheck()">Close</button>
    </div>
    <div id="spamConflictMessage" class="section-message"></div>
    <div class="summary-note">Conflict detection is advisory. No SQL preference is changed or deleted by this check.</div>
    <div class="summary-table-wrap"><table class="conflict-table"><thead><tr><th>SCOPE</th><th>PRINCIPAL</th><th>VALUE</th><th>PREFERENCES</th><th>ROWS</th></tr></thead><tbody id="spamConflictRows"></tbody></table></div>
  </div>
</div>


<div id="monitorTab" class="tabpane">
<div class="page-head"><div><h2>Monitor</h2><div class="page-subtitle">Database-backed POP3 and Webmail authentication reports with offline GEO-IP evidence</div></div><div class="page-head-actions"><button type="button" onclick="loadMonitor()">Refresh</button></div></div>
<div class="monitor-toolbar"><input id="monitorSearch" placeholder="Search user, IP, country, city or ASN organization"><input id="monitorDateFrom" type="date" title="From date"><input id="monitorDateTo" type="date" title="To date"><label><input id="monitorAuto" type="checkbox"> Auto-refresh every 30s</label></div>
<div class="monitor-protocol-tabs"><button class="active" data-monitor-protocol="POP3" onclick="setMonitorProtocol('POP3',this)">POP3</button><button data-monitor-protocol="WEBMAIL" onclick="setMonitorProtocol('WEBMAIL',this)">Webmail</button></div>
<section class="monitor-panel"><div class="monitor-panel-head"><div><h3 id="monitorReportTitle">POP3 Login Summary</h3><div id="monitorSourceStatus" class="monitor-source"></div></div><div id="monitorStats" class="monitor-cards"></div></div><div class="monitor-table-wrap"><table class="monitor-table"><thead><tr><th>User</th><th>Success</th><th>Failed</th><th>Last Login</th><th>Last IP</th><th>GEO</th></tr></thead><tbody id="monitorSummaryRows"></tbody></table></div></section>
<div class="info-note" style="margin-top:14px"><div class="info-icon">i</div><div><b>Upgrade-only database monitor</b><div>Dovecot and Roundcube logs are mounted read-only. Parsed login events are appended with duplicate protection to the new <code>mail_login_events</code> table; the existing populated database is never recreated. GEO-IP uses local MMDB files only.</div></div></div></div>
<div id="monitorDetailModal" class="flow-modal" onclick="if(event.target===this)closeMonitorDetail()"><div class="flow-panel monitor-detail-panel"><div class="flow-head"><div><h2 id="monitorDetailTitle" style="margin:0">Login History</h2><div id="monitorDetailSubtitle" class="page-subtitle"></div></div><button type="button" onclick="closeMonitorDetail()">Close</button></div><div class="monitor-detail-grid"><section><h3>IP Summary</h3><div class="monitor-table-wrap"><table class="monitor-table"><thead><tr><th>IP</th><th>Success</th><th>Failed</th><th>Last Seen</th><th>GEO / ASN</th></tr></thead><tbody id="monitorIpRows"></tbody></table></div></section><section><h3>Login Events</h3><div class="monitor-table-wrap"><table class="monitor-table"><thead><tr><th>Date / Time</th><th>Status</th><th>IP</th><th>Method</th><th>Country / City</th></tr></thead><tbody id="monitorEventRows"></tbody></table></div></section></div></div></div>

<div id="systemTab" class="tabpane">
  <div class="page-head"><div><h2>System Status</h2><div class="page-subtitle">Runtime readiness, dependency impact and operational safety</div></div><div class="page-head-actions"><button onclick="loadHealth()">Refresh</button></div></div>
  <div id="statusSummary" class="section-message"></div>
  <div id="statusGrid" class="status-grid"></div>

  <section id="opsPanel" class="ops-panel" hidden>
    <div class="page-head">
      <div><h3 style="margin:0">Operational Safety</h3><div class="page-subtitle">Configuration snapshots, SpamAssassin conflict detection and backup visibility</div></div>
      <div class="page-head-actions"><button class="secondary-btn" type="button" onclick="loadOperations()">Refresh Safety Data</button></div>
    </div>
    <div class="ops-grid">
      <div class="ops-card"><span>Current configuration fingerprint</span><b id="opsFingerprint" class="ops-fingerprint">-</b></div>
      <div id="opsConflictCard" class="ops-card"><span>Whitelist / blacklist conflicts</span><b id="opsConflictCount">-</b><button type="button" onclick="openSpamConflictCheck()">Review Conflicts</button></div>
      <div class="ops-card"><span>Mail Size configuration backups</span><b id="opsBackupCount">-</b><small id="opsLatestBackup" class="page-subtitle">Latest: -</small></div>
    </div>
    <div class="ops-actions">
      <input id="opsSnapshotLabel" maxlength="255" placeholder="Snapshot label, e.g. Before Spam List migration">
      <button class="primary-btn" type="button" onclick="createConfigSnapshot()">Create Configuration Snapshot</button>
      <span id="opsMessage" class="section-message"></span>
    </div>
    <div class="ops-table-wrap">
      <table class="ops-table">
        <thead><tr><th>TIME</th><th>LABEL</th><th>USER</th><th>FINGERPRINT</th><th>STATE VS CURRENT</th><th>CHANGED SECTIONS</th></tr></thead>
        <tbody id="opsSnapshotRows"></tbody>
      </table>
    </div>
    <div class="info-note"><div class="info-icon">i</div><div><b>Safety model</b><div>Snapshots contain non-secret dashboard configuration only. Passwords and API keys are never stored in snapshots. Restore of host configuration remains an explicit administrator action in the owning feature.</div></div></div>
  </section>
</div>

<div id="auditTab" class="tabpane">
<h3>Quarantine Audit</h3>

<div class="controls excel-filter-controls">
<select id="auditSearchOperator" class="text-filter-operator" title="Text filter operator">
<option value="equals">Equals</option>
<option value="not_equal">Not equal</option>
<option value="begins_with">Begins with</option>
<option value="ends_with">Ends with</option>
<option value="contains" selected>Contains</option>
<option value="does_not_contain">Does not contain</option>
</select>
<input id="auditSearch" placeholder="Search sender, recipient, subject, IP or quarantine ID">
<input id="auditDateFrom" type="date" title="From date">
<input id="auditDateTo" type="date" title="To date">
<select id="auditAction">
<option value="all">All actions</option>
<option value="LOGIN_SUCCESS">Login Success</option>
<option value="LOGIN_FAILED">Login Failed</option>
<option value="LOGOUT">Logout</option>
<option value="AUTO_LOGOUT_INACTIVITY">Inactivity Timeout</option>
<option value="RELEASE">Released</option>
<option value="RELEASE_FAILED">Release Failed</option>
<option value="SPAM_FLG">Marked Spam</option>
<option value="ACL_USER_CREATE">ACL User Create</option>
<option value="ACL_USER_UPDATE">ACL User Update</option>
<option value="ACL_USER_DELETE">ACL User Delete</option>
<option value="SPAMLIST_CREATE">Whitelist/Blacklist Create</option>
<option value="SPAMLIST_UPDATE">Whitelist/Blacklist Update</option>
<option value="SPAMLIST_DELETE">Whitelist/Blacklist Delete</option>
<option value="SPAMLIST_BULK_DELETE">Whitelist/Blacklist Bulk Delete</option>
<option value="SPAMLIST_IMPORT">Whitelist/Blacklist Import</option>
<option value="SPAMLIST_EXPORT">Whitelist/Blacklist Export</option>
<option value="SPAMLIST_CONFLICT_CHECK">Whitelist/Blacklist Conflict Check</option>
<option value="CONFIG_SNAPSHOT_CREATE">Configuration Snapshot Create</option>
</select>
<button onclick="loadAudit(1)">Refresh</button>
<button class="secondary-btn" type="button" onclick="clearAuditFilters()">Clear All</button>
<select id="auditPageSize" class="ux-page-size" title="Rows per page">
<option value="20">20 rows</option><option value="50" selected>50 rows</option><option value="100">100 rows</option><option value="200">200 rows</option>
</select>
<span id="auditFilterCount" class="ux-filter-badge">0 filters active</span>
<span id="auditLastRefresh" class="ux-last-refresh">Last refreshed: -</span>
</div>

<div class="top-page-line"><span id="auditPgTop">Page 1 of 1</span></div>
<div id="auditMessage"></div>

<div class="audit-wrap">
<table class="audit-table">
<thead>
<tr>
<th>TIME</th>
<th>ACTION</th>
<th>USER</th>
<th>CLIENT IP</th>
<th>FROM</th>
<th>TO/CC</th>
<th>SUBJECT</th>
<th>SCORE</th>
<th>QUARANTINE ID</th>
<th>DETAIL</th>
</tr>
</thead>
<tbody id="auditRows"></tbody>
</table>
</div>

<div class="pager">
<button onclick="auditPage(-1)">Previous</button>
<span id="auditPg"></span>
<button onclick="auditPage(1)">Next</button>
</div>
</div>

<div id="aclTab" class="tabpane">
  <div class="page-head">
    <div>
      <h2>User ACL</h2>
      <div class="page-subtitle">Dashboard users, roles and per-tab permissions</div>
    </div>
    <div class="page-head-actions">
      <button class="secondary-btn" type="button" onclick="loadAclUsers()">Refresh</button>
      <button class="primary-btn" type="button" onclick="openAclEditor()">Add User</button>
    </div>
  </div>

  <div class="acl-note">
    <b>Access levels:</b> None blocks the area, View permits read-only use, and Admin permits management actions.
    Administrator accounts have full access to every area and can manage User ACL.
  </div>

  <div id="aclMessage" class="section-message"></div>
  <div class="acl-table-wrap">
    <table class="acl-table">
      <thead>
        <tr>
          <th>User</th><th>Status</th><th>Role</th>
          <th>Delivery</th><th>Summary</th><th>Quarantine</th>
          <th>Whitelist / Blacklist</th><th>Mail Size</th><th>Monitor</th><th>System</th><th>Audit</th><th>Mail Flow</th><th>Actions</th>
        </tr>
      </thead>
      <tbody id="aclRows"></tbody>
    </table>
  </div>

  <div id="aclEditor" class="acl-editor" hidden>
    <div class="acl-editor-card">
      <div class="flow-head">
        <div>
          <h3 id="aclEditorTitle" style="margin:0">Add User</h3>
          <div class="page-subtitle">Password minimum: 10 characters</div>
        </div>
        <button type="button" onclick="closeAclEditor()">Close</button>
      </div>
      <input id="aclUserId" type="hidden">
      <div class="acl-form-grid">
        <label>Username<input id="aclUsername" maxlength="128" autocomplete="off"></label>
        <label>Password<input id="aclPassword" type="password" autocomplete="new-password" placeholder="Leave blank when editing to keep current password"></label>
        <label class="acl-check"><input id="aclActive" type="checkbox" checked> Active</label>
        <label class="acl-check"><input id="aclIsAdmin" type="checkbox"> Administrator</label>
      </div>
      <div class="acl-permissions">
        <div class="acl-perm-head">Per-area permission</div>
        <div id="aclPermissionGrid"></div>
      </div>
      <div id="aclEditorMessage" class="section-message"></div>
      <div class="acl-editor-actions">
        <button class="secondary-btn" type="button" onclick="closeAclEditor()">Cancel</button>
        <button class="primary-btn" type="button" onclick="saveAclUser()">Save User</button>
      </div>
    </div>
  </div>
</div>

<div id="helpTab" class="tabpane">
  <div class="page-head">
    <div>
      <h2>Help</h2>
      <div class="page-subtitle">Postfix Delivery Dashboard</div>
    </div>
  </div>
  <div class="help-visual-grid" aria-label="Architecture diagrams">
    <button class="help-visual-tile" type="button" data-tab="flowTab" onclick="openHelpVisualization('flowTab')"><span class="help-visual-icon">⌁</span><span class="help-visual-copy"><b>Mail Flow Chart</b><span>Open the approved inbound / outbound mail architecture and live operational counters.</span></span></button>
    <button class="help-visual-tile" type="button" data-tab="aiTrainerFlowTab" onclick="openHelpVisualization('aiTrainerFlowTab')"><span class="help-visual-icon">⇄</span><span class="help-visual-copy"><b>AI Trainer Flow</b><span>Open the independent-g1 SHADOW training, validation and ground-truth flow.</span></span></button>
    <button class="help-visual-tile" type="button" data-tab="aiIntelligenceTab" onclick="openHelpVisualization('aiIntelligenceTab')"><span class="help-visual-icon">◈</span><span class="help-visual-copy"><b>AI Intelligence Layout</b><span>Open the Message, Infrastructure and Campaign AI architecture map.</span></span></button>
  </div>
  <div class="help-grid">
    <section class="help-card"><h3>Navigation</h3><p>The left menu is grouped into Overview, Mail Operations, Security &amp; Intelligence, Administration and Support. Existing routes and RBAC remain unchanged; unavailable functions stay hidden according to the signed-in user's permissions.</p></section>
    <section class="help-card"><h3>Delivery</h3><p>Shows final delivery states only. Search by Queue ID, sender, recipient, delivery target or detail. The visible page loads first using server-side pagination; global counters refresh afterward so they do not block the table. Search typing is debounced and superseded requests are cancelled. Click a Queue ID for the mail-flow timeline when Mail Flow access is permitted.</p></section>
    <section class="help-card"><h3>Summary</h3><p>Displays mail direction totals and a compact Daily Bounced Domain Summary with Sent, Recv and Total columns. R1.1.44 serves bounce summary and drill-down from an additive indexed <code>postfix_bounce_projection</code>, avoiding repeated timestamp/domain expression scans across the complete delivery table. The authoritative <code>postfix_delivery_final</code> data is preserved and new terminal bounces update the projection transactionally. Sent and Recv counts still drill down to the underlying bounced-message evidence for the selected date and domain. The retired Home-Domain Email ID MIS remains intentionally absent because log-derived address strings are not an authoritative mailbox directory.</p></section>
    <section class="help-card"><h3>Amavis Quarantine</h3><p>Review Spam, Virus and Banned objects with category filters, message metadata and bulk selection. Release remains separate from learning. Learn Spam and Learn Ham use the restricted host SpamAssassin learning path and update the existing production Bayes database through sa-learn.</p></section>
    <section class="help-card"><h3>Quarantine Intelligence</h3><p>Provides a compact forensic view for quarantined messages. The SpamAssassin evidence card shows final and required scores, verdict, SPF/DKIM/DMARC, Bayes evidence, top positive contributors, negative/trust rules and the complete test list. GEO-IP intelligence shows the observed public source IP and, when local MaxMind databases are installed, country/city and ASN details.</p><p><b>Ground-truth persistence:</b> saved Mail Admin HAM/SPAM decisions, classification, review/reversal reason and notes are restored from MariaDB when the same quarantine item is reopened. A save is reported successful only after the exact Admin Decision is read back from the authoritative CURRENT MariaDB row; shadow AI analysis failures cannot hide an already stored decision. Saved administrator ground truth takes precedence over the AI proposal. Independent attachment intelligence performs bounded local ZIP member inspection, including nested ZIPs and dangerous embedded script/executable extensions; members are never executed and Amavis/SpamAssassin verdicts are not used as AI features.</p></section>
    <section class="help-card"><h3>AI Trainer Flow &amp; Intelligence Layout</h3><p>Use the architecture buttons at the top of Help to open these diagrams. The live AI Trainer Flow visualizes the complete independent-g1 path: incoming mail → schema-v4 feature extraction → Message / Infrastructure / Campaign AI → correlation → shadow prediction → admin review and ground truth → database → eligible dataset → candidate training/validation → 7-day calibration. Operational, development and future/data-building capabilities are visually distinguished. Live values refresh from the authenticated trainer status API.</p></section>
    <section class="help-card"><h3>AI Shadow Intelligence</h3><p>The AI trainer is shadow-only and independent of SpamAssassin/Amavis classification. AI inference uses raw-message NLP/text, sender/header relationships, independently parsed SPF/DKIM/DMARC evidence, URL/domain structure, MIME/attachment metadata and hard-HAM weighting. SpamAssassin score, rule hits, X-Spam headers, Amavis verdict/category and quarantine state are excluded from the AI feature vector and remain visible only as a separate human-review result. Approved Learn Ham/Learn Spam actions provide the human label after the action succeeds. Schema-4 training adds local contextual phrase families and privacy-reduced stylometric/structural signals and can non-destructively re-extract retained legacy labels from their quarantine source; legacy feature rows remain archived. Automatic training never promotes or activates a model; explicit promotion affects shadow prediction only.</p></section>
    <section class="help-card"><h3>Email Analysis</h3><p>Email Analysis is calibrated to the AI Trainer. Paste RFC822 source or upload/drag an .eml file or a native Microsoft Outlook .msg file; when a current-generation candidate exists, the workbench uses that candidate for SHADOW ONLY inspection and displays its generation, schema and algorithm. The page uses a balanced full-width input layout followed by side-by-side Independent AI and Amavis / SpamAssassin Dry Run cards, a comparison strip, and supporting authentication/campaign evidence. The dry-run adapter is disabled until an explicitly configured analysis-only helper is available; it never submits to production Amavis SMTP port 10024. Message AI, Infrastructure AI and Campaign AI remain independent of SpamAssassin/Amavis decisions. Uploaded message content is temporary and is not added to quarantine, Bayes learning or AI training.</p></section>
    <section class="help-card"><h3>Amavis Log Intelligence</h3><p>Read-only intelligence correlates the current message and release-generated Queue IDs with <code>/var/lib/amavis/logs/amavis.log</code> (mounted read-only as <code>/host-amavis/logs/amavis.log</code>). Amavis-reported attachment filenames, archive-member descriptors and related log content are normalized into persistent MariaDB history and can be viewed for the current message. The dashboard does not open attachments, execute content, extract archives, or inspect mailbox contents.</p></section>
    <section class="help-card"><h3>BEC / Impersonation Intelligence</h3><p>Email Analysis evaluates identity, authentication and intent separately. It highlights display-name deception, email-address-in-display-name patterns, From/Reply-To mismatch, look-alike domains, shared-mail infrastructure context, payment/bank-change language, urgency/secrecy lures, suspicious links and attachment context. SPF/DKIM/DMARC PASS is identity/alignment evidence only and contributes no positive HAM trust weight. Fully authenticated UCE, phishing and compromised-account mail can still be SPAM. The first view stays simple; expand the evidence when deeper review is required.</p></section>
    <section class="help-card"><h3>SpamAssassin Learning & Human Correction</h3><p>Learn Spam and Learn Ham use the existing host SpamAssassin/Bayes database only. They do not create AI training labels. If a SpamAssassin learning verdict was wrong, Correct to HAM or Correct to SPAM updates Bayes and its audit trail, but AI Set-2 training remains restricted to explicit Mail Admin Ground Truth actions.</p></section>
    <section class="help-card"><h3>Release Verification</h3><p>A successful release command alone is not treated as final delivery proof. When Amavis/Postfix returns a release Queue ID, the dashboard records it under Release Status and follows that Queue ID through the existing Postfix delivery database to show QUEUED, DELIVERED, DEFERRED, BOUNCED or other final state. Older releases without a captured Queue ID are shown as legacy/unverified.</p></section>
    <section class="help-card"><h3>Whitelist / Blacklist</h3><p>Manage SpamAssassin SQL preferences in the userpref table. Supported whitelist preferences are whitelist_auth and whitelist_from; blacklist uses blacklist_from. View permission permits inspection; Admin permits add, edit and delete.</p></section>
    <section class="help-card"><h3>Manage Email Size</h3><p>Manages message-size limits using two aligned side-by-side vertical cards: Submission — Port 587 and Webmail. Each card shows the active limit, a compact four-digit-width numeric New Limit field, the MB unit and its own Update action. The configured host policy still enforces its permitted range. Access requires Mail Size Admin permission; privileged host changes use the loopback-only helper and are audited.</p></section>
    <section class="help-card"><h3>Mail Flow</h3><p>Use the Mail Flow Chart button at the top of Help to open the approved inbound/outbound architecture, including Postfix, Amavis/SpamAssassin, the shared Bayes database, quarantine, release/learning paths, mailbox delivery and outbound Internet delivery. Full-screen view uses the approved flow image.</p></section>
    <section class="help-card"><h3>Monitor</h3><p>Provides database-backed authentication reports for Dovecot POP3 logins from <code>/var/log/mail.log</code> plus Webmail logins from Roundcube <code>/var/lib/roundcube/logs/userlogins.log</code>. IMAP login events are intentionally not collected because routine IMAP client refreshes create noisy login activity. R1.1.44 uses durable MariaDB device/inode/byte-offset checkpoints for each read-only source, so the background reader processes only newly appended log bytes instead of rereading the historical tail every cycle. Existing populated login history is adopted at current EOF on upgrade, duplicate hashes remain a replay safeguard, and offline GEO-IP enrichment runs only for genuinely new events. The normal live summary reads the incrementally maintained <code>mail_login_user_summary</code> projection; filtered historical searches continue to use <code>mail_login_events</code>. Existing historical IMAP rows are left untouched. Click a user to review Date/Time, Success/Failed, IP history and offline GEO-IP/ASN evidence. Local GeoLite2 MMDB data is used only; no external lookup or mailbox-content inspection occurs.</p></section>
    <section class="help-card"><h3>System Status</h3><p>Checks MariaDB, mail.log, quarantine/state directories, Amavis PDP readiness and related dashboard health. Detailed readiness requires System access.</p></section>
    <section class="help-card"><h3>Amavis Log Intelligence</h3><p>Reads <code>/var/lib/amavis/logs/amavis.log</code> through the read-only container mount <code>/host-amavis/logs/amavis.log</code>. On Ubuntu the log is commonly <code>amavis:adm</code> with mode <code>0640</code>; set <code>AMAVIS_LOG_GID</code> to the host <code>adm</code> group GID so the container receives read-only group access. Permission failures are reported explicitly and never trigger mailbox inspection.</p></section>
    <section class="help-card"><h3>Audit</h3><p>Review login/logout, release, Learn Spam/Learn Ham, AI trainer activity, failed actions, Mail Size changes and User ACL administration events stored by the dashboard audit system.</p></section>
    <section class="help-card"><h3>User ACL</h3><p>Administrators can add, edit, disable or delete dashboard accounts and assign None/View/Admin per area. The current administrator cannot remove or disable their own administrator role.</p></section>
    <section class="help-card"><h3>Session Security</h3><p>Sessions use an idle timeout plus an absolute lifetime. Login throttling, same-site cookies and request-origin protection are enabled by Security Pack 1.</p></section>
    <section class="help-card"><h3>Quarantine Safety</h3><p>The quarantine directory is mounted read-only. The dashboard never deletes, moves, renames, truncates or overwrites quarantine objects. Release uses the host Amavis PDP workflow; analysis uploads are temporary and do not alter quarantine state.</p></section>
    <section class="help-card"><h3>Three-Tier AI Threat Intelligence</h3><p>R1.1.45 adds self-contained Infrastructure AI and Campaign AI evidence alongside Message AI. Infrastructure AI evaluates locally observed Received-header sender host/HELO consistency, source IP, offline ASN, authentication failures, sender/reply/message-ID relationships and local IP/ASN rotation. Campaign AI stores privacy-reduced one-way fingerprints for locally observed quarantine messages and correlates repeated templates, sender-domain rotation, source-IP diversity, multi-ASN behavior and URL-domain-set reuse over a 30-day local window. The Correlation Engine is SHADOW ONLY and has no Postfix, Amavis, release, quarantine or automatic ground-truth authority. Manual uploaded email analysis does not add samples to the production campaign repository.</p></section>

    <section class="help-card"><h3>R1.1.52 Training Provenance & Provider-Aware Transport</h3><p>Candidate training is restricted to CURRENT schema-v4 administrator Ground Truth sources only. Historical sa-learn, Bayes backfill, learning-correction and legacy-feature rows remain preserved for audit but are excluded from fitting and auto-train counts. Infrastructure AI also interprets Google and Microsoft transport-provider hops as contextual routing evidence rather than automatic spam/ham proof; authentication PASS remains identity evidence only.</p></section>
    <section class="help-card"><h3>R1.1.53 Semantic Impersonation & Action-Intent Intelligence</h3><p>Message AI now derives relationship features that connect sender domain, recipient domain, mail-service claims, delivery/release language and action-link destinations. A single keyword can never force a SPAM proposal. A SHADOW-only semantic overlay is raised only when a multi-signal recipient-mail-service impersonation chain is present, such as an unrelated external sender claiming the recipient domain's mail service and directing the user to an action URL outside both domains. The original learned-model verdict/confidence is retained for audit, schema remains v4 with seven feature families, and only explicit Mail Admin Ground Truth can create a training label.</p></section>
    <section class="help-card"><h3>R1.1.55 Admin Review Queue De-duplication</h3><p>Quarantine exposes a persistent <b>Admin Decision</b> filter with All / Required / Completed states. <b>Required</b> means the quarantine item has no authoritative CURRENT administrator Ground Truth row. The Review Queue count and <b>Review Pending Messages</b> hyperlink open that filtered queue. To inspect a pending item, use the existing <b>Intelligence</b> button; the duplicate per-row <b>Admin Decision Required / Review Now</b> control has been removed. Opening Intelligence never creates Ground Truth; only an explicit administrator save/acknowledgement does. Historical or superseded rows do not satisfy the requirement.</p></section>
    <section class="help-card"><h3>Quarantine Intelligence Grid Layout</h3><p>R1.1.51 keeps Quarantine Intelligence in explicit aligned review and evidence rows. AI Shadow Intelligence and Mail Admin Ground Truth stay paired on desktop; Current Data and Metrics remain equal-width; Independent Attachment Intelligence occupies the complete AI evidence row without an unused blank column; Infrastructure AI and Campaign AI remain paired and equal-width beneath it. GEO-IP and Sender Policy share a balanced support row, while Amavis trace and Learning History remain full-width. The layout collapses cleanly on smaller screens.</p></section>
    <section class="help-card"><h3>GEO-IP Database</h3><p>GEO-IP enrichment is offline. To enable location and ASN details, install compatible MaxMind GeoLite2/GeoIP2 MMDB files in the configured data/geoip directory. If databases are absent, the dashboard still reports the observed public source IP without contacting an external lookup service.</p></section>
  </div>
</div>



<div id="qHeaderModal" class="qheader-modal" onclick="if(event.target===this)closeQuarantineHeader()">
  <div class="qheader-panel" role="dialog" aria-modal="true" aria-labelledby="qHeaderTitle">
    <div class="qheader-head">
      <div><h2 id="qHeaderTitle" style="margin:0">Full Email Header</h2><div id="qHeaderId" class="page-subtitle"></div></div>
      <div class="qheader-actions"><button type="button" onclick="copyQuarantineHeader()">Copy Header</button><button type="button" onclick="closeQuarantineHeader()">Close</button></div>
    </div>
    <pre id="qHeaderText" class="qheader-pre"></pre>
  </div>
</div>

<div id="flowModal" class="flow-modal" onclick="if(event.target===this)closeFlow()">
  <div class="flow-panel">
    <div class="flow-head"><div><h2 style="margin:0">Mail Flow</h2><div id="flowQueue" class="page-subtitle"></div></div><button onclick="closeFlow()">Close</button></div>
    <div id="flowBody"></div>
  </div>
</div>

<script>

const SESSION_IDLE_TIMEOUT_MS=__SESSION_IDLE_TIMEOUT_MS__;
let sessionIdleTimer=null;
let sessionExpired=false;
let lastSessionTouch=0;

let CURRENT_ACCESS={username:"",is_admin:false,permissions:{}};
const ACL_AREAS=[
  ["delivery","Delivery"],
  ["summary","Summary"],
  ["quarantine","Amavis Quarantine"],
  ["spam_lists","Whitelist / Blacklist"],
  ["mail_size","Mail Size"],
  ["monitor","Monitor"],
  ["system","System Status"],
  ["audit","Audit"],
  ["mail_flow","Mail Flow"]
];
const ACL_RANK={none:0,view:1,admin:2};

function canAccess(area,minimum="view"){
  if(area==="help") return true;
  if(CURRENT_ACCESS.is_admin) return true;
  const level=CURRENT_ACCESS.permissions?.[area]||"none";
  return (ACL_RANK[level]||0)>=(ACL_RANK[minimum]||1);
}

async function loadCurrentAccess(){
  const response=await apiFetch("/api/me");
  if(!response.ok) throw new Error("Unable to load user access");
  CURRENT_ACCESS=await response.json();
  applyAccessToUi();
}

function applyAccessToUi(){
  const tabAreas={
    deliveryTab:"delivery",
    summaryTab:"summary",
    quarantineTab:"quarantine",
    emailAnalysisTab:"quarantine",
    spamListsTab:"spam_lists",
    mailSizeTab:"mail_size",
    monitorTab:"monitor",
    systemTab:"system",
    auditTab:"audit",
    aclTab:"user_acl",
    helpTab:"help"
  };
  document.querySelectorAll(".tabbtn").forEach(button=>{
    const area=tabAreas[button.dataset.tab];
    let allowed=true;
    if(area==="user_acl") allowed=Boolean(CURRENT_ACCESS.is_admin);
    else if(area==="mail_size") allowed=canAccess("mail_size","admin");
    else if(area) allowed=canAccess(area,"view");
    button.hidden=!allowed;
  });

  document.querySelectorAll(".qadmin-only").forEach(el=>{
    el.hidden=!canAccess("quarantine","admin");
  });
  document.querySelectorAll(".spam-list-admin-only").forEach(el=>{
    el.hidden=!canAccess("spam_lists","admin");
  });
}

async function apiFetch(input,init={}){
  const options={...init};
  const method=String(options.method||"GET").toUpperCase();
  if(["POST","PUT","PATCH","DELETE"].includes(method)){
    options.headers={...(options.headers||{}),"X-Postfix-Dashboard":"1"};
  }
  const response=await window.fetch(input,options);
  if(response.status===401){
    window.location="/login";
    throw new Error("Session expired");
  }
  return response;
}

async function touchSession(){
  const now=Date.now();
  if(now-lastSessionTouch<30000 || sessionExpired)return;
  lastSessionTouch=now;
  try{ await apiFetch("/api/session/touch",{method:"POST"}); }catch(_){}
}

function armSessionIdleTimer(){
  if(sessionExpired)return;
  if(sessionIdleTimer)clearTimeout(sessionIdleTimer);
  sessionIdleTimer=setTimeout(expireInactiveSession,SESSION_IDLE_TIMEOUT_MS);
  touchSession();
}

async function expireInactiveSession(){
  if(sessionExpired)return;
  sessionExpired=true;
  if(sessionIdleTimer)clearTimeout(sessionIdleTimer);
  try{
    await window.fetch("/api/session/inactivity-timeout",{method:"POST",keepalive:true,headers:{"X-Postfix-Dashboard":"1"}});
  }catch(_){}
  window.location="/login";
}

["pointerdown","keydown","wheel","touchstart"].forEach(eventName=>{
  window.addEventListener(eventName,armSessionIdleTimer,{passive:true});
});
armSessionIdleTimer();

async function logoutDashboard(){
  try{await window.fetch("/api/logout",{method:"POST",headers:{"X-Postfix-Dashboard":"1"}});}catch(_){}
  window.location="/login";
}


const UX_FILTER_KEY="postfix-dashboard-ux-filters-r18.4";
function uxNow(){return new Date().toLocaleTimeString();}
function uxCopy(value){
  const text=String(value||"");
  if(!text)return;
  navigator.clipboard?.writeText(text).catch(()=>{});
}
function uxSetRefresh(id){const el=document.getElementById(id);if(el)el.textContent=`Last refreshed: ${uxNow()}`;}
function uxFilterCount(values){return values.filter(Boolean).length;}
function uxBadge(id,count){const el=document.getElementById(id);if(!el)return;el.textContent=`${count} filter${count===1?"":"s"} active`;el.classList.toggle("active",count>0);}
function saveUxFilters(){
  const ids=["searchField","searchOperator","search","dateFrom","dateTo","filter","deliveryPageSize","qSearchField","qSearchOperator","qSearch","qDate","qAdminDecision","qPageSize","slSearch","slPreference","slScope","slPageSize","auditSearchOperator","auditSearch","auditDateFrom","auditDateTo","auditAction","auditPageSize"];
  const data={};ids.forEach(id=>{const el=document.getElementById(id);if(el)data[id]=el.value;});data.quarantineCategory=quarantineCategory;
  try{localStorage.setItem(UX_FILTER_KEY,JSON.stringify(data));}catch(_){}
}
function restoreUxFilters(){
  let data={};try{data=JSON.parse(localStorage.getItem(UX_FILTER_KEY)||"{}");}catch(_){}
  Object.entries(data).forEach(([id,value])=>{if(id==="quarantineCategory")return;const el=document.getElementById(id);if(el && [...el.options||[]].some(o=>o.value===String(value)) || (el && !el.options))el.value=value;});
  if(data.quarantineCategory)quarantineCategory=data.quarantineCategory;
  quarantineAdminDecision=["required","completed"].includes(String(document.getElementById("qAdminDecision")?.value||"").toLowerCase())?String(document.getElementById("qAdminDecision").value).toLowerCase():"all";
  DELIVERY_PAGE_SIZE=Number(document.getElementById("deliveryPageSize")?.value||50);
  QUARANTINE_PAGE_SIZE=Number(document.getElementById("qPageSize")?.value||20);
  SL_PAGE_SIZE=Number(document.getElementById("slPageSize")?.value||50);
  AUDIT_PAGE_SIZE=Number(document.getElementById("auditPageSize")?.value||50);
}
function updateDeliveryUx(){
  const count=uxFilterCount([document.getElementById("search")?.value,document.getElementById("dateFrom")?.value,document.getElementById("dateTo")?.value,document.getElementById("filter")?.value!=="all"?"status":"",document.getElementById("searchField")?.value!=="all"?"field":"",document.getElementById("searchOperator")?.value!=="contains"?"operator":""]);uxBadge("deliveryFilterCount",count);saveUxFilters();
}
function updateQuarantineUx(){
  const count=uxFilterCount([document.getElementById("qSearch")?.value,document.getElementById("qDate")?.value,quarantineCategory!=="all"?"category":"",quarantineAdminDecision!=="all"?"admin decision":"",document.getElementById("qSearchField")?.value!=="all"?"field":"",document.getElementById("qSearchOperator")?.value!=="contains"?"operator":""]);uxBadge("qFilterCount",count);saveUxFilters();
}
function updateSpamUx(){const count=uxFilterCount([document.getElementById("slSearch")?.value,document.getElementById("slPreference")?.value!=="all"?"pref":"",document.getElementById("slScope")?.value!=="all"?"scope":""]);uxBadge("slFilterCount",count);saveUxFilters();}
function updateAuditUx(){const count=uxFilterCount([document.getElementById("auditSearch")?.value,document.getElementById("auditDateFrom")?.value,document.getElementById("auditDateTo")?.value,document.getElementById("auditAction")?.value!=="all"?"action":"",document.getElementById("auditSearchOperator")?.value!=="contains"?"operator":""]);uxBadge("auditFilterCount",count);saveUxFilters();}
function clearDeliveryFilters(){document.getElementById("searchField").value="all";document.getElementById("searchOperator").value="contains";document.getElementById("search").value="";document.getElementById("dateFrom").value="";document.getElementById("dateTo").value="";document.getElementById("filter").value="all";p=1;updateDeliveryUx();load();}
function clearQuarantineFilters(){document.getElementById("qSearchField").value="all";document.getElementById("qSearchOperator").value="contains";document.getElementById("qSearch").value="";document.getElementById("qDate").value="";quarantineCategory="all";quarantineAdminDecision="all";const qAdminDecision=document.getElementById("qAdminDecision");if(qAdminDecision)qAdminDecision.value="all";document.querySelectorAll(".qmetric-filter").forEach(b=>b.classList.toggle("active",b.dataset.qfilter==="all"));qp=1;updateQuarantineUx();loadQuarantine(1);}
function clearAuditFilters(){document.getElementById("auditSearchOperator").value="contains";document.getElementById("auditSearch").value="";document.getElementById("auditDateFrom").value="";document.getElementById("auditDateTo").value="";document.getElementById("auditAction").value="all";ap=1;updateAuditUx();loadAudit(1);}

function conciseDetail(detail,status){
  const d=String(detail||"").toLowerCase();
  const s=String(status||"").toUpperCase();
  const rules=[
    [/over quota|quota exceeded|mailbox full|insufficient system storage/, "Mailbox over quota"],
    [/user unknown|unknown user|recipient address rejected|no such user|does not exist|unknown recipient/, "Invalid recipient address"],
    [/mailbox unavailable/, "Mailbox unavailable"],
    [/relay access denied|relay not permitted/, "Relay denied"],
    [/host or domain name not found|name service error|domain not found|nxdomain/, "Domain not found"],
    [/connection timed out|connect to .* timed out|timeout/, "Connection timed out"],
    [/connection refused/, "Connection refused"],
    [/network is unreachable|no route to host|host unreachable/, "Host unreachable"],
    [/temporary lookup failure|temporary failure/, "Temporary delivery failure"],
    [/too many connections/, "Too many connections"],
    [/message size exceeds|too large|size limit/, "Message too large"],
    [/blocked using|dnsbl|spamhaus|blacklist|rbl/, "Blocked by RBL"],
    [/spam|discarded as spam/, "Detected as spam"],
    [/virus|infected/, "Virus detected"],
    [/banned/, "Banned content"],
    [/authentication required|authentication failed|auth failed/, "Authentication failed"],
    [/policy rejection|rejected by policy|access denied/, "Rejected by policy"],
    [/greylist|greylisted/, "Greylisted"],
    [/certificate|tls|ssl/, "TLS/Certificate error"],
    [/delivered to maildir|delivered via|status=sent|250 2\.0\.0/, "Delivered"],
    [/deferred/, "Delivery deferred"],
    [/bounce|bounced|5\.[0-9]\.[0-9]/, "Delivery bounced"]
  ];
  for(const [pattern,label] of rules){ if(pattern.test(d)) return label; }
  if(s==="DELIVERED") return "Delivered";
  if(s==="DEFERRED") return "Delivery deferred";
  if(s==="BOUNCED") return "Delivery bounced";
  if(s==="BLOCKED") return "Blocked";
  if(s==="SPAM"||s==="QUARANTINED") return "Quarantined";
  if(s==="REJECTED") return "Rejected";
  if(s==="UNDELIVERED") return "Undelivered";
  const clean=String(detail||"-").replace(/\s+/g," ").trim();
  return clean.length>72?clean.slice(0,69)+"...":clean;
}
function statusBadge(status){
 const v=String(status||"").toUpperCase();
 const m={DELIVERED:["#dcfce7","#166534"],DEFERRED:["#fef3c7","#92400e"],BOUNCED:["#fee2e2","#991b1b"],BLOCKED:["#fee2e2","#991b1b"],SPAM:["#ffedd5","#9a3412"],QUARANTINED:["#ede9fe","#6d28d9"],REJECTED:["#fee2e2","#991b1b"],UNDELIVERED:["#e2e8f0","#334155"]};
 const p=m[v]||["#e2e8f0","#334155"];
 return `<span style="display:inline-block;padding:4px 8px;border-radius:999px;background:${p[0]};color:${p[1]};font-weight:700;font-size:11px">${esc(v||"-")}</span>`;
}
let p=1,tp=1;
let DELIVERY_PAGE_SIZE=50;
let deliveryHasMore=false;
let deliveryLoadController=null;
let deliveryLoadSequence=0;
let deliverySearchTimer=null;
// Historical source-audit compatibility marker; interactive paging now uses look-ahead:
// const deliveryPageText=`Page ${p} of ${tp}`;
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({
"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
}[c]));

function parseSpamAssassinRules(distribution){
  const raw=String(distribution||"").trim();
  if(!raw || raw==="No details") return [];
  return raw.split(",").map(part=>part.trim()).filter(Boolean).map(part=>{
    const match=part.match(/^([^=]+)=(.+)$/);
    const rule=(match?match[1]:part).trim();
    const value=(match?match[2]:"").trim();
    const numeric=Number.parseFloat(value);
    return {rule,value,numeric:Number.isFinite(numeric)?numeric:null};
  });
}
function spamRuleRows(distribution){
  // Compatibility: historical callers may still pass the raw SpamAssassin distribution string.
  const rules=Array.isArray(distribution)?distribution:parseSpamAssassinRules(distribution);
  if(!rules.length) return '<div class="qscore-tip-empty">No SpamAssassin rule details</div>';
  return rules.map(entry=>`
    <div class="qscore-tip-row">
      <span class="qscore-tip-rule">${esc(entry.rule)}</span>
      <span class="qscore-tip-eq">${entry.numeric===null?"=":entry.numeric>=0?"+":""}</span>
      <span class="qscore-tip-value">${esc(entry.value||"-")}</span>
    </div>`).join("");
}
function spamEvidenceSummary(item){
  const rules=parseSpamAssassinRules(item.distribution);
  const positives=rules.filter(x=>x.numeric!==null&&x.numeric>0).sort((a,b)=>b.numeric-a.numeric).slice(0,5);
  const negatives=rules.filter(x=>x.numeric!==null&&x.numeric<0).sort((a,b)=>a.numeric-b.numeric).slice(0,3);
  const allRows=spamRuleRows(rules);
  const auth=(label,value)=>`<span class="qscore-auth"><b>${label}</b> ${esc(String(value||"none").toUpperCase())}</span>`;
  return `
    <div class="qscore-tip-head qscore-intel-head">
      <span>SpamAssassin Intelligence</span><!-- SpamAssassin Rules evidence summary -->
    </div>
    <div class="qscore-summary-grid">
      <span>Final Score</span><b>${esc(item.score||"-")}</b>
      <span>Required Score</span><b>${esc(item.required_score||"5.0")}</b>
      <span>Verdict</span><b>${esc(item.spam_verdict||"UNKNOWN")}</b>
    </div>
    <div class="qscore-auth-row">${auth("SPF",item.spf)}${auth("DKIM",item.dkim)}${auth("DMARC",item.dmarc)}</div>
    <div class="qscore-section-title">Top contributing rules</div>
    <div class="qscore-tip-body">${spamRuleRows(positives)}</div>
    <div class="qscore-section-title">Negative / trust rules</div>
    <div class="qscore-tip-body">${spamRuleRows(negatives)}</div>
    <details class="qscore-all-tests">
      <summary>All tests (${rules.length})</summary>
      <div class="qscore-tip-body">${allRows}</div>
    </details>`;
}

function recipients(items){
  if(!items.length)return "-";
  const first=esc(items[0].recipient);

  if(items.length===1)return first;

  const tooltip=items.map((item,index)=>`
    <div class="tr">
      <b>${index+1}. ${esc(item.recipient)}</b><br>
      Status: ${esc(item.status)}<br>
      Target: ${esc(item.delivery_target)}<br>
      Detail: ${esc(item.status_detail)}
    </div>
  `).join("");

  return `
    <span class="rc">
      ${first}
      <span class="more">+${items.length-1}</span>
      <span class="tip">
        <b>${items.length} recipients</b>
        ${tooltip}
      </span>
    </span>
  `;
}

const DELIVERY_STATS_TTL_MS=60000;
let deliveryStatsFetchedAt=0;
let deliveryStatsPromise=null;
async function loadDeliveryStatistics(signal, force=false){
  const now=Date.now();
  if(!force && deliveryStatsFetchedAt && now-deliveryStatsFetchedAt<DELIVERY_STATS_TTL_MS) return null;
  if(deliveryStatsPromise) return deliveryStatsPromise;
  deliveryStatsPromise=(async()=>{
    const statsResponse=await apiFetch("/api/statistics",{signal});
    if(!statsResponse.ok) return null;
    const stat=await statsResponse.json();
    deliveryStatsFetchedAt=Date.now();
    return stat;
  })();
  try{return await deliveryStatsPromise;}finally{deliveryStatsPromise=null;}
}

async function load(){
  const sequence=++deliveryLoadSequence;
  if(deliveryLoadController) deliveryLoadController.abort();
  deliveryLoadController=new AbortController();
  const signal=deliveryLoadController.signal;

  const search=document.getElementById("search").value;
  const searchField=document.getElementById("searchField").value;
  const searchOperator=document.getElementById("searchOperator").value;
  const filter=document.getElementById("filter").value;
  const dateFrom=document.getElementById("dateFrom").value;
  const dateTo=document.getElementById("dateTo").value;
  const query=new URLSearchParams({
    page:p,
    page_size:DELIVERY_PAGE_SIZE,
    status_filter:filter,
    search:search,
    search_field:searchField,
    search_operator:searchOperator,
    date_from:dateFrom,
    date_to:dateTo,
    include_total:"false"
  });

  updateDeliveryUx();
  document.getElementById("msg").textContent="Loading Mail Delivery…";
  document.getElementById("rows").innerHTML='<tr><td class="ux-empty" colspan="7">Loading current delivery records…</td></tr>';

  try{
    // Paint the visible page first. Expensive global counters are intentionally
    // deferred so they can never block Mail Delivery rendering.
    const rowsResponse=await apiFetch("/api/deliveries?"+query,{signal});
    const data=await rowsResponse.json();
    if(!rowsResponse.ok) throw new Error(data.detail||"Unable to load delivery records");
    if(sequence!==deliveryLoadSequence) return;

    deliveryHasMore=Boolean(data.has_more);
    tp=data.total_pages||Math.max(p,deliveryHasMore?p+1:p);
    uxSetRefresh("deliveryLastRefresh");

    const rendered=(data.rows||[]).map(row=>{
      const mb=row.message_size_bytes==null?"-":(row.message_size_bytes/1048576).toFixed(2);
      const list=row.recipients||[];
      const deliveredHost=list[0]?.delivery_target||"-";
      const hoverMeta=`Size: ${mb} MB | Target: ${deliveredHost}`;
      return `
        <tr>
          <td>${esc(row.timestamp)}</td>
          <td>${canAccess("mail_flow","view")
            ? `<button class="queue-link" onclick='openFlow(${JSON.stringify(row.queue_id)})'>${esc(row.queue_id)}</button>`
            : esc(row.queue_id)}<button class="ux-copy" type="button" title="Copy Queue ID" onclick='uxCopy(${JSON.stringify(row.queue_id)})'>⧉</button></td>
          <td>${statusBadge(row.queue_status)}</td>
          <td>${esc(row.sender||"-")}<button class="ux-copy" type="button" title="Copy sender" onclick='uxCopy(${JSON.stringify(row.sender||"")})'>⧉</button></td>
          <td>${recipients(list)}</td>
          <td class="delivery-host" title="${esc(deliveredHost)}">${esc(deliveredHost)}</td>
          <td class="delivery-detail"><span class="delivery-meta" title="${esc(`${hoverMeta} | ${list[0]?.status_detail||"-"}`)}">${esc(conciseDetail(list[0]?.status_detail,row.queue_status))}</span></td>
        </tr>`;
    }).join("");
    document.getElementById("rows").innerHTML=rendered||'<tr><td class="ux-empty" colspan="7">No messages match the current filters. <button type="button" onclick="clearDeliveryFilters()">Clear Filters</button></td></tr>';
    document.getElementById("msg").textContent=`${(data.rows||[]).length} grouped queue records shown. Sender and size are correlated from qmgr metadata.`;

    const deliveryPageText=data.total_pages?`Page ${p} of ${data.total_pages}`:`Page ${p}${deliveryHasMore?" · more available":""}`;
    document.getElementById("pg").textContent=deliveryPageText;
    document.getElementById("pgTop").textContent=deliveryPageText;
    const prev=document.getElementById("deliveryPrev");
    const next=document.getElementById("deliveryNext");
    if(prev) prev.disabled=p<=1;
    if(next) next.disabled=!deliveryHasMore;

    document.getElementById("download").href="/api/reports/delivery.txt?"+new URLSearchParams({
      limit:1000,status_filter:filter,search:search,search_field:searchField,
      search_operator:searchOperator,date_from:dateFrom,date_to:dateTo
    });

    // Global statistics are secondary UI. Load after the visible records have
    // painted; failure here must not blank or delay the Delivery table.
    // R1.1.38 ordering invariant: apiFetch("/api/statistics" is encapsulated by
    // loadDeliveryStatistics below and is never awaited before visible rows.
    loadDeliveryStatistics(signal).then(stat=>{
      if(!stat || sequence!==deliveryLoadSequence) return;
      for(const key of ["total","delivered","deferred","bounced","blocked","spam","rejected","undelivered"]){
        const el=document.getElementById(key); if(el) el.textContent=stat[key]||0;
      }
      const labels={all:"All",DELIVERED:"Delivered",DEFERRED:"Deferred",BOUNCED:"Bounced",BLOCKED:"Blocked",QUARANTINED:"Quarantined",REJECTED:"Rejected",UNDELIVERED:"Undelivered"};
      const counts={all:stat.total||0,DELIVERED:stat.delivered||0,DEFERRED:stat.deferred||0,BOUNCED:stat.bounced||0,BLOCKED:stat.blocked||0,QUARANTINED:stat.spam||0,REJECTED:stat.rejected||0,UNDELIVERED:stat.undelivered||0};
      const filterSelect=document.getElementById("filter");
      for(const option of filterSelect.options) option.textContent=`${labels[option.value]} (${counts[option.value]||0})`;
      document.querySelectorAll(".card").forEach(card=>card.classList.toggle("active",card.dataset.filter===filter));
    }).catch(err=>{if(err?.name!=="AbortError") console.warn("Delivery statistics deferred load failed",err);});
  }catch(err){
    if(err?.name==="AbortError") return;
    if(sequence!==deliveryLoadSequence) return;
    document.getElementById("msg").textContent=err?.message||"Unable to load Mail Delivery.";
    document.getElementById("rows").innerHTML='<tr><td class="ux-empty" colspan="7">Unable to load delivery records. Use Refresh to retry.</td></tr>';
  }
}


async function openFlow(queueId){
  const modal=document.getElementById("flowModal");
  document.getElementById("flowQueue").textContent=`Queue ID: ${queueId}`;
  document.getElementById("flowBody").innerHTML="Loading...";
  document.activeElement?.blur?.();
  document.body.classList.add("flow-dialog-open");
  modal.classList.add("open");
  try{
    const response=await apiFetch("/api/flow/"+encodeURIComponent(queueId));
    const data=await response.json();
    if(!response.ok){throw new Error(data.detail||"Unable to load flow");}
    const sourceNote=(data.sources||[]).length?`<div class="flow-source-note"><b>Evidence:</b> ${(data.sources||[]).map(esc).join(" + ")}${data.live_log_fallback?" (live-log fallback used)":""}</div>`:"";
    document.getElementById("flowBody").innerHTML=sourceNote+(data.events||[]).map((event,index)=>`
      <div class="flow-event">
        <b>${index+1}. ${esc(event.status||event.stage||"EVENT")}</b>
        <div>${esc(event.timestamp||"-")} • ${esc(event.stage||"-")}</div>
        <div><b>From:</b> ${esc(event.sender||"-")}</div>
        <div><b>To:</b> ${esc(event.recipient||"-")}</div>
        <div><b>Target:</b> ${esc(event.target||"-")}</div>
        <div><b>Detail:</b> ${esc(event.detail||"-")}</div>
        <details><summary>Raw log</summary><pre>${esc(event.raw_log||"-")}</pre></details>
      </div>`).join("")||"No events found.";
  }catch(error){
    document.getElementById("flowBody").textContent=error.message||"Unable to load flow";
  }
}
function closeFlow(){document.getElementById("flowModal").classList.remove("open");document.body.classList.remove("flow-dialog-open");}


let monitorTimer=null;
let monitorProtocol="POP3";
let monitorSearchTimer=null;
let monitorRequestController=null;
function fmtDateTime(value){
  if(value===null||value===undefined||value==="")return "-";
  const raw=String(value).trim();
  const normalized=/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(raw)?raw.replace(" ","T"):raw;
  const d=new Date(normalized);
  if(Number.isNaN(d.getTime()))return raw;
  return d.toLocaleString(undefined,{year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"});
}
function monitorBadge(status){const x=String(status||"INFO").toUpperCase();return `<span class="monitor-badge ${esc(x)}">${esc(x)}</span>`;}
function monitorStatsHtml(c={}){return `<div class="monitor-stat"><span>SUCCESS</span><b>${Number(c.success||0)}</b></div><div class="monitor-stat"><span>FAILED</span><b>${Number(c.failed||0)}</b></div>`;}
function monitorGeo(row){const place=[row.last_country||row.country,row.last_city||row.city].filter(Boolean).join(" / ");const asn=row.asn?`AS${esc(row.asn)} ${esc(row.organization||"")}`:"";return esc(place||asn||"-")+(place&&asn?`<small>${asn}</small>`:"");}
function setMonitorProtocol(protocol,button){monitorProtocol=protocol;document.querySelectorAll("[data-monitor-protocol]").forEach(x=>x.classList.toggle("active",x===button));loadMonitor().catch(()=>{});}
async function loadMonitor(){
  if(!canAccess("monitor","view"))return;
  if(monitorRequestController)monitorRequestController.abort();
  monitorRequestController=new AbortController();
  const params=new URLSearchParams({protocol:monitorProtocol,search:document.getElementById("monitorSearch")?.value||"",date_from:document.getElementById("monitorDateFrom")?.value||"",date_to:document.getElementById("monitorDateTo")?.value||"",limit:"500"});
  let response;
  try{response=await apiFetch(`/api/monitor/summary?${params}`,{signal:monitorRequestController.signal});}catch(error){if(error?.name==="AbortError")return;throw error;}
  const data=await response.json();if(!response.ok)return;
  const source=monitorProtocol==="WEBMAIL"?data.sync?.sources?.roundcube:data.sync?.sources?.dovecot;
  const el=document.getElementById("monitorSourceStatus");if(el&&source){el.className=`monitor-source ${source.readable?"ok":"err"}`;el.textContent=source.readable?`${source.path} · read-only · DB sync +${Number(data.sync?.inserted||0)}`:`${source.path||"Log source"} · ${source.error||"unavailable"}`;}
  document.getElementById("monitorReportTitle").textContent=`${monitorProtocol==="WEBMAIL"?"Webmail":monitorProtocol} Login Summary`;
  document.getElementById("monitorStats").innerHTML=monitorStatsHtml(data.stats||{});
  document.getElementById("monitorSummaryRows").innerHTML=(data.rows||[]).map(x=>`<tr><td><button class="monitor-user-link" onclick='openMonitorDetail(${JSON.stringify(monitorProtocol)},${JSON.stringify(x.username)})'>${esc(x.username)}</button></td><td class="good-num">${Number(x.success_count||0)}</td><td class="bad-num">${Number(x.failed_count||0)}</td><td>${esc(fmtDateTime(x.last_login||""))}</td><td>${esc(x.last_ip||"")}</td><td class="monitor-geo">${monitorGeo(x)}</td></tr>`).join("")||'<tr><td colspan="6" class="ux-empty">No stored login activity for this filter.</td></tr>';
}
async function openMonitorDetail(protocol,username){
  const params=new URLSearchParams({protocol,username,date_from:document.getElementById("monitorDateFrom")?.value||"",date_to:document.getElementById("monitorDateTo")?.value||"",limit:"1000"});const response=await apiFetch(`/api/monitor/user-history?${params}`);const data=await response.json();if(!response.ok)return;
  document.getElementById("monitorDetailTitle").textContent=`${protocol} Login History`;
  document.getElementById("monitorDetailSubtitle").textContent=username;
  document.getElementById("monitorIpRows").innerHTML=(data.ips||[]).map(x=>`<tr><td>${esc(x.remote_ip||"")}</td><td class="good-num">${Number(x.success_count||0)}</td><td class="bad-num">${Number(x.failed_count||0)}</td><td>${esc(fmtDateTime(x.last_seen||""))}</td><td class="monitor-geo">${monitorGeo(x)}</td></tr>`).join("")||'<tr><td colspan="5" class="ux-empty">No IP history.</td></tr>';
  document.getElementById("monitorEventRows").innerHTML=(data.events||[]).map(x=>`<tr><td>${esc(fmtDateTime(x.event_time||x.timestamp_text||""))}</td><td>${monitorBadge(x.status)}</td><td>${esc(x.remote_ip||"")}</td><td>${esc(x.auth_method||"-")}</td><td>${monitorGeo(x)}</td></tr>`).join("")||'<tr><td colspan="5" class="ux-empty">No login events.</td></tr>';
  document.getElementById("monitorDetailModal")?.classList.add("open");
}
function closeMonitorDetail(){document.getElementById("monitorDetailModal")?.classList.remove("open");}
function syncMonitorAuto(){if(monitorTimer){clearInterval(monitorTimer);monitorTimer=null;}if(document.getElementById("monitorAuto")?.checked)monitorTimer=setInterval(()=>loadMonitor().catch(()=>{}),30000);}
document.getElementById("monitorSearch")?.addEventListener("input",()=>{if(monitorSearchTimer)clearTimeout(monitorSearchTimer);monitorSearchTimer=setTimeout(()=>loadMonitor().catch(()=>{}),350);});
["monitorDateFrom","monitorDateTo"].forEach(id=>document.getElementById(id)?.addEventListener("change",()=>loadMonitor().catch(()=>{})));document.getElementById("monitorAuto")?.addEventListener("change",syncMonitorAuto);



async function loadHealth(){
  const grid=document.getElementById("statusGrid");
  grid.innerHTML="Loading...";
  const response=await apiFetch("/api/system/ready");
  const data=await response.json().catch(()=>({}));
  const labels={database:"MariaDB",mail_log:"Postfix mail.log",quarantine_dir:"Quarantine directory",state_dir:"Audit/state directory",amavis_pdp:"Amavis PDP 127.0.0.1:9998"};
  const core=Object.entries(labels).map(([key,label])=>{
    const ok=Boolean(data.checks?.[key]);
    const impact={
      database:"Dashboard reporting, users and audit data depend on this database.",
      mail_log:"Delivery ingestion cannot read new Postfix events if this file is unavailable.",
      quarantine_dir:"Quarantine review is unavailable if the read-only source cannot be accessed.",
      state_dir:"Quarantine decision state and append-only audit require this directory.",
      amavis_pdp:"Message release requires connectivity to the Amavis PDP service."
    }[key]||"";
    return `<div class="status-card"><span>${esc(label)}</span><b class="${ok?'ok':'bad'}">${ok?'OK':'FAILED'}</b><small>${esc(impact)}</small></div>`;
  });
  const feature=Object.values(data.feature_checks||{}).map(item=>{
    const ok=Boolean(item.ok);
    return `<div class="status-card feature ${ok?'':'warning'}"><span>${esc(item.label||'Feature dependency')}</span><b class="${ok?'ok':'bad'}">${ok?'OK':'ATTENTION'}</b><small>${esc(item.impact||'')}</small></div>`;
  });
  grid.innerHTML=[...core,...feature].join("");
  const readerError=data.reader?.error?` • Reader error: ${data.reader.error}`:"";
  document.getElementById("statusSummary").textContent=`Status: ${data.status||'unknown'} • Active sessions: ${data.active_sessions??0}${readerError}`;
  const ops=document.getElementById("opsPanel");
  if(ops){
    ops.hidden=!canAccess("system","admin");
    if(!ops.hidden) await loadOperations();
  }
}

async function loadOperations(){
  if(!canAccess("system","admin")) return;
  const message=document.getElementById("opsMessage");
  if(message) message.textContent="Loading operational safety data...";
  const response=await apiFetch("/api/system/operations");
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    if(message) message.textContent=data.detail||"Unable to load operational safety data.";
    return;
  }
  document.getElementById("opsFingerprint").textContent=data.config_fingerprint||"-";
  const conflictCount=Number(data.spam_conflicts?.total||0);
  document.getElementById("opsConflictCount").textContent=String(conflictCount);
  document.getElementById("opsConflictCard").classList.toggle("warning",conflictCount>0 || data.spam_conflicts?.ok===false);
  const backup=data.mail_size_backups||{};
  document.getElementById("opsBackupCount").textContent=backup.available?String(backup.backup_count||0):"Unavailable";
  const latest=backup.latest_backup||{};
  document.getElementById("opsLatestBackup").textContent=backup.available?`Latest: ${latest.display_time||latest.file||'None'}`:"Latest: host helper unavailable";
  document.getElementById("opsSnapshotRows").innerHTML=(data.snapshots||[]).map(row=>{
    const changed=(row.changed_sections||[]).map(x=>`<span class="ops-chip">${esc(x)}</span>`).join("")||'<span class="ops-chip">none</span>';
    return `<tr><td>${esc(row.snapshot_time||'-')}</td><td>${esc(row.label||'-')}</td><td>${esc(row.username||'-')}</td><td class="ops-fingerprint">${esc(row.fingerprint||'-')}</td><td class="${row.matches_current?'ops-match':'ops-diff'}">${row.matches_current?'Matches current':'Different'}</td><td><div class="ops-changed">${changed}</div></td></tr>`;
  }).join("")||'<tr><td colspan="6" class="ux-empty">No configuration snapshots yet.</td></tr>';
  if(message) message.textContent="Passwords and API keys are excluded from configuration snapshots.";
}

async function createConfigSnapshot(){
  if(!canAccess("system","admin")) return;
  const label=document.getElementById("opsSnapshotLabel")?.value?.trim()||"Manual snapshot";
  const message=document.getElementById("opsMessage");
  const response=await apiFetch("/api/system/config-snapshots",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({label})});
  const data=await response.json().catch(()=>({}));
  if(!response.ok){if(message)message.textContent=data.detail||"Unable to create configuration snapshot.";return;}
  if(message) message.textContent=`Configuration snapshot ${data.id} created.`;
  if(document.getElementById("opsSnapshotLabel")) document.getElementById("opsSnapshotLabel").value="";
  await loadOperations();
}

async function openSpamConflictCheck(){
  const modal=document.getElementById("spamConflictModal");
  const message=document.getElementById("spamConflictMessage");
  const rows=document.getElementById("spamConflictRows");
  if(!modal||!message||!rows)return;
  modal.classList.add("open");
  message.textContent="Checking SQL preferences...";
  rows.innerHTML="";
  const response=await apiFetch("/api/spam-lists/conflicts?limit=500");
  const data=await response.json().catch(()=>({}));
  if(!response.ok){message.textContent=data.detail||"Unable to check conflicts.";return;}
  const total=Number(data.total||0);
  message.textContent=total?`${total} whitelist / blacklist conflict${total===1?'':'s'} detected${data.truncated?' (showing first 500)':''}.`:"No whitelist / blacklist conflicts detected.";
  rows.innerHTML=(data.items||[]).map(item=>`<tr><td>${esc(spamListScopeLabel(item.scope))}</td><td>${esc(item.principal||item.username||'-')}</td><td>${esc(item.value||'-')}</td><td>${(item.preferences||[]).map(x=>`<span class="conflict-pref">${esc(x)}</span>`).join(' ')}</td><td>${esc(item.rows_count||0)}</td></tr>`).join("")||'<tr><td colspan="5" class="ux-empty">No conflicts found.</td></tr>';
}
function closeSpamConflictCheck(){document.getElementById("spamConflictModal")?.classList.remove("open");}

function page(direction){
  if(direction>0 && !deliveryHasMore) return;
  p=Math.max(1,p+direction);
  load();
}

document.getElementById("search").oninput=()=>{
  p=1;
  clearTimeout(deliverySearchTimer);
  deliverySearchTimer=setTimeout(()=>load(),350);
};
document.getElementById("searchField").onchange=()=>{
  p=1;
  load();
};
document.getElementById("searchOperator").onchange=()=>{
  p=1;
  load();
};

document.getElementById("filter").onchange=()=>{
  p=1;
  load();
};

document.querySelectorAll(".card").forEach(card=>{
  card.addEventListener("click",()=>{
    document.getElementById("filter").value=card.dataset.filter;
    p=1;
    load();
  });
});



function bounceCountButton(row,direction){
  const count=Number(row?.[direction]||0);
  if(count<=0) return "0";
  const date=JSON.stringify(String(row.date_iso||""));
  const domain=JSON.stringify(String(row.domain||""));
  const dir=JSON.stringify(direction);
  return `<button class="summary-count-link" type="button"
    onclick='openBounceDetail(${date},${domain},${dir})'>${count}</button>`;
}

async function openBounceDetail(dateIso,domain,direction){
  const modal=document.getElementById("bounceDetailModal");
  const rowsEl=document.getElementById("bounceDetailRows");
  const title=document.getElementById("bounceDetailTitle");
  const note=document.getElementById("bounceSubjectNote");
  const count=document.getElementById("bounceDetailCount");

  const directionLabel=direction==="sent"?"Sent":"Received";
  title.textContent=`${directionLabel} • ${domain} • ${dateIso}`;
  rowsEl.innerHTML='<tr><td colspan="5">Loading...</td></tr>';
  note.textContent="";
  count.textContent="";
  modal.classList.add("open");

  const query=new URLSearchParams({
    date:dateIso,
    domain:domain,
    direction:direction
  });

  const response=await apiFetch("/api/summary/bounces/detail?"+query);
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    rowsEl.innerHTML=`<tr><td colspan="5">${esc(data.detail||"Unable to load bounce details")}</td></tr>`;
    return;
  }

  note.textContent=data.subject_note||"";
  count.textContent=`${data.total||0} bounced message(s)`;

  rowsEl.innerHTML=(data.rows||[]).map(row=>`
    <tr>
      <td>${esc(row.date||"-")}</td>
      <td title="${esc(row.from||"-")}">${esc(row.from||"-")}</td>
      <td title="${esc(row.to||"-")}">${esc(row.to||"-")}</td>
      <td>${esc(row.subject||"Not captured")}</td>
      <td title="${esc(row.reason||"-")}">${esc(row.reason||"-")}</td>
    </tr>
  `).join("")||'<tr><td colspan="5">No bounced messages found.</td></tr>';
}

function closeBounceDetail(){
  document.getElementById("bounceDetailModal")?.classList.remove("open");
}


function renderDailyDomainTable(rows, elementId){
  const target=document.getElementById(elementId);
  if(!rows || rows.length===0){
    target.innerHTML='<tr><td colspan="5">No records</td></tr>';
    return;
  }

  let html="";
  let currentDate="";
  let daySent=0;
  let dayReceived=0;

  function addTotal(date){
    if(!date)return;
    html+=`
      <tr class="total-row">
        <td>${esc(date)} Total</td>
        <td></td>
        <td class="num">${daySent}</td>
        <td class="num">${dayReceived}</td>
        <td class="num"><b>${daySent+dayReceived}</b></td>
      </tr>
    `;
  }

  for(const row of rows){
    if(currentDate && row.date!==currentDate){
      addTotal(currentDate);
      daySent=0;
      dayReceived=0;
    }

    const showDate=row.date!==currentDate ? row.date : "";
    currentDate=row.date;
    daySent+=Number(row.sent||0);
    dayReceived+=Number(row.received||0);

    html+=`
      <tr>
        <td>${esc(showDate)}</td>
        <td>${esc(row.domain)}</td>
        <td class="num">${bounceCountButton(row,"sent")}</td>
        <td class="num">${bounceCountButton(row,"received")}</td>
        <td class="num"><b>${Number(row.sent||0)+Number(row.received||0)}</b></td>
      </tr>
    `;
  }

  addTotal(currentDate);
  target.innerHTML=html;
}


let aiArchitectureLiveTimer=null;
async function refreshAIArchitectureLive(){
  const flow=document.getElementById("aiTrainerFlowTab"), intel=document.getElementById("aiIntelligenceTab");
  if(!flow&&!intel) return;
  try{
    const r=await apiFetch("/api/ai-trainer/status"); const d=await r.json(); if(!r.ok) throw new Error(d.detail||"status unavailable");
    const candidate=d.candidate||null, active=d.active||null;
    const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v};
    set("tfGeneration",d.generation_id||"-"); set("tfGenerationHeadline",d.generation_id||"-"); set("tfLabels",Number(d.dataset_samples||0).toLocaleString()); set("tfHamSpam",`${d.ham_labels||0} / ${d.spam_labels||0}`); set("tfHardHam",d.hard_ham_labels||0); set("tfCandidate",candidate?.version||"None"); set("tfNext",d.next_auto_train_in==null?"Disabled":d.next_auto_train_in);
    set("tfSchemaNode",`v${d.feature_schema||"-"}`); set("tfActiveNode",`Active: ${active?.version||"None"}`); set("tfLabelsNode",`${Number(d.dataset_samples||0).toLocaleString()} approved labels`); set("tfCandidateNode",`Candidate: ${candidate?.version||"None"}`); set("tfValidationNodeText",candidate?`${candidate.validation_samples||0} validation samples`:`Waiting for candidate`);
    set("intelGeneration",d.generation_id||"-"); set("intelSchema",`v${d.feature_schema||"-"}`); set("intelActive",active?.version||"None"); set("intelCandidate",candidate?.version||"None"); set("intelAmavisHook",(d.amavis_hook?.mode||"disabled").toUpperCase()); set("intelVerdictState",active?`Active shadow model ${active.version}`:"No active independent model");
    const trainingNode=document.getElementById("tfTrainingNode"), validationNode=document.getElementById("tfValidationNode"); if(trainingNode){trainingNode.classList.toggle("live",!!candidate);trainingNode.classList.toggle("waiting",!candidate)} if(validationNode){validationNode.classList.toggle("live",!!candidate);validationNode.classList.toggle("waiting",!candidate)}
    const metric=candidate?`Candidate <b>${esc(candidate.version||"-")}</b> · accuracy <b>${esc(candidate.accuracy??"N/A")}%</b> · balanced <b>${esc(candidate.balanced_accuracy??"N/A")}%</b> · validation <b>${esc(candidate.validation_samples??"-")}</b> samples · HAM→SPAM FP <b>${esc(candidate.ham_to_spam_false_positive_rate??"N/A")}</b> · SPAM→HAM FN <b>${esc(candidate.spam_to_ham_false_negative_rate??"N/A")}</b>`:`No independent candidate trained yet. <b>${d.dataset_samples||0}</b> approved labels in <b>${esc(d.generation_id||"current generation")}</b>.`;
    const m=document.getElementById("trainerLiveMetrics");if(m)m.innerHTML=metric;
    const i=document.getElementById("intelLiveState");if(i)i.innerHTML=`Generation <b>${esc(d.generation_id||"-")}</b> · schema <b>v${esc(d.feature_schema||"-")}</b> · active <b>${esc(active?.version||"None")}</b> · candidate <b>${esc(candidate?.version||"None")}</b> · Amavis AI hook <b>${esc((d.amavis_hook?.mode||"disabled").toUpperCase())}</b> · updated <b>${new Date().toLocaleTimeString()}</b>`;
  }catch(e){const m=document.getElementById("trainerLiveMetrics");if(m)m.textContent="Live trainer feed unavailable";const i=document.getElementById("intelLiveState");if(i)i.textContent="Live intelligence feed unavailable";}
}
function stopAIArchitectureLive(){if(aiArchitectureLiveTimer){clearInterval(aiArchitectureLiveTimer);aiArchitectureLiveTimer=null;}}
function aiArchitectureVisible(){return document.getElementById("aiTrainerFlowTab")?.classList.contains("active") || document.getElementById("aiIntelligenceTab")?.classList.contains("active");}
function ensureAIArchitectureLive(){
  if(!aiArchitectureVisible()){stopAIArchitectureLive();return;}
  if(!aiArchitectureLiveTimer){refreshAIArchitectureLive();aiArchitectureLiveTimer=setInterval(()=>{if(aiArchitectureVisible())refreshAIArchitectureLive();else stopAIArchitectureLive();},10000);}
}

async function loadSummary(){
  const dateFrom=document.getElementById("dateFrom").value;
  const dateTo=document.getElementById("dateTo").value;
  const query=new URLSearchParams({date_from:dateFrom,date_to:dateTo});

  const [summaryResponse,domainResponse]=await Promise.all([
    apiFetch("/api/summary?"+query),
    apiFetch("/api/summary/domains?"+query)
  ]);

  const data=await summaryResponse.json();
  const domainData=await domainResponse.json();
  document.getElementById("homeExternal").textContent=data.home_to_external||0;
  document.getElementById("externalHome").textContent=data.external_to_home||0;
  document.getElementById("homeHome").textContent=data.home_to_home||0;
  document.getElementById("externalExternal").textContent=data.external_to_external||0;
  document.getElementById("emailsSent").textContent=data.emails_sent||0;
  document.getElementById("emailsReceived").textContent=data.emails_received||0;
  document.getElementById("summaryTotal").textContent=data.total_recipient_records||0;
  document.getElementById("homeDomains").textContent=(data.home_domains||[]).join(", ");

  renderDailyDomainTable(
    domainData.bounced||[],
    "dailyBounceRows"
  );
}


let qp=1,qtp=1;
let QUARANTINE_PAGE_SIZE=20;
let quarantineCategory="all";
let quarantineAdminDecision="all";
const qSelected=new Set();
let qVisibleEligible=[];

function updateBulkSelectionUI(){
  const boxes=[...document.querySelectorAll(".qselect-item:not(:disabled)")];
  qVisibleEligible=boxes.map(box=>box.dataset.pdpId).filter(Boolean);

  const visibleSelected=qVisibleEligible.filter(id=>qSelected.has(id));
  const selectAll=document.getElementById("qSelectAllVisible");
  const count=document.getElementById("qSelectedCount");
  const releaseBtn=document.getElementById("qBulkRelease");
  const spamBtn=document.getElementById("qBulkSpam");

  boxes.forEach(box=>{ box.checked=qSelected.has(box.dataset.pdpId); });

  if(selectAll){
    selectAll.checked=qVisibleEligible.length>0 && visibleSelected.length===qVisibleEligible.length;
    selectAll.indeterminate=visibleSelected.length>0 && visibleSelected.length<qVisibleEligible.length;
    selectAll.disabled=qVisibleEligible.length===0;
  }
  if(count) count.textContent=`Selected: ${qSelected.size}`;
  if(releaseBtn) releaseBtn.disabled=qSelected.size===0;
  if(spamBtn) spamBtn.disabled=qSelected.size===0;
}

function bindQuarantineSelection(){
  document.querySelectorAll(".qselect-item:not(:disabled)").forEach(box=>{
    box.addEventListener("change",()=>{
      const id=box.dataset.pdpId;
      if(!id)return;
      if(box.checked)qSelected.add(id); else qSelected.delete(id);
      updateBulkSelectionUI();
    });
  });
  updateBulkSelectionUI();
}

function clearQuarantineSelection(){
  qSelected.clear();
  updateBulkSelectionUI();
}

async function quarantineBulkAction(mode){
  const ids=[...qSelected];
  if(!ids.length)return;

  const releaseBtn=document.getElementById("qBulkRelease");
  const spamBtn=document.getElementById("qBulkSpam");
  const resultEl=document.getElementById("qBulkResult");
  if(releaseBtn)releaseBtn.disabled=true;
  if(spamBtn)spamBtn.disabled=true;
  if(resultEl)resultEl.textContent=`Processing ${ids.length} selected item(s)...`;

  try{
    const response=await apiFetch("/api/quarantine/bulk-action",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({mode:mode,pdp_ids:ids})
    });
    const data=await response.json();
    if(!response.ok){
      if(resultEl)resultEl.textContent=data.detail||"Bulk action failed";
      updateBulkSelectionUI();
      return;
    }

    const succeeded=new Set(
      (data.results||[]).filter(row=>row.ok).map(row=>row.pdp_id)
    );
    succeeded.forEach(id=>qSelected.delete(id));

    if(resultEl){
      resultEl.textContent=`Completed: ${data.success||0} succeeded, ${data.failed||0} failed`;
    }
    await loadQuarantine(qp,{preserveSelection:true});
  }catch(_){
    if(resultEl)resultEl.textContent="Bulk action failed";
    updateBulkSelectionUI();
  }
}


async function quarantineAction(mode,pdpId){
  const url="/api/quarantine/action?"+new URLSearchParams({mode:mode,pdp_id:pdpId});
  const response=await apiFetch(url,{method:"POST"});
  const data=await response.json();
  if(!response.ok){
    alert(data.detail||"Quarantine action failed");
    return;
  }
  await loadQuarantine(qp);
}

async function quarantineLearn(mode,pdpId){
  const url="/api/quarantine/learn?"+new URLSearchParams({mode:mode,pdp_id:pdpId});
  const response=await apiFetch(url,{method:"POST"});
  const data=await response.json();
  if(!response.ok){
    alert(data.detail||"SpamAssassin learning failed");
    return;
  }
  await loadQuarantine(qp,{preserveSelection:true});
}

async function forceQuarantineRefresh(){
  const response=await apiFetch("/api/quarantine/refresh",{method:"POST"});
  const data=await response.json();
  if(!response.ok){
    alert(data.detail||"Quarantine rescan failed");
    return;
  }
  await loadQuarantine(1);
}

let qHeaderById={};
function openQuarantineHeader(pdpId){
  const modal=document.getElementById("qHeaderModal");
  document.getElementById("qHeaderId").textContent=String(pdpId||"");
  document.getElementById("qHeaderText").textContent=qHeaderById[pdpId]||"Header unavailable";
  modal?.classList.add("open");
}
function closeQuarantineHeader(){document.getElementById("qHeaderModal")?.classList.remove("open");}
function copyQuarantineHeader(){uxCopy(document.getElementById("qHeaderText")?.textContent||"");}

function setQuarantineAdminDecision(value){
  quarantineAdminDecision=["required","completed"].includes(String(value||"").toLowerCase())?String(value).toLowerCase():"all";
  const el=document.getElementById("qAdminDecision"); if(el) el.value=quarantineAdminDecision;
  loadQuarantine(1);
}
function openRequiredReviewQueue(){ setQuarantineAdminDecision("required"); }

async function loadQuarantine(pageNumber=qp,options={}){
  qp=Math.max(1,pageNumber);
  if(!options.preserveSelection) qSelected.clear();
  const query=new URLSearchParams({
    q:document.getElementById("qSearch").value,
    q_field:document.getElementById("qSearchField").value,
    q_operator:document.getElementById("qSearchOperator").value,
    date:document.getElementById("qDate").value,
    category:quarantineCategory,
    admin_decision:quarantineAdminDecision,
    page:qp,
    page_size:QUARANTINE_PAGE_SIZE
  });
  const response=await apiFetch("/api/quarantine?"+query);
  const data=await response.json();

  if(!response.ok){
    document.getElementById("qMessage").textContent=data.detail||"Unable to load quarantine.";
    return;
  }

  qtp=data.total_pages||1;
  updateQuarantineUx();
  uxSetRefresh("qLastRefresh");
  qp=data.page||1;
  document.getElementById("qTotal").textContent=data.total_items||0;
  const reviewRequired=Number(data.review_queue?.required||0);
  const reviewEl=document.getElementById("qReviewRequired"); if(reviewEl) reviewEl.textContent=reviewRequired.toLocaleString();
  const adminFilter=document.getElementById("qAdminDecision"); if(adminFilter) adminFilter.value=quarantineAdminDecision;
  apiFetch("/api/quarantine/released-count").then(r=>r.json()).then(x=>{const el=document.getElementById("qReleased");if(el)el.textContent=Number(x.released||0).toLocaleString();}).catch(()=>{});
  document.getElementById("qSpam").textContent=data.counts?.spam||0;
  document.getElementById("qVirus").textContent=data.counts?.virus||0;
  document.getElementById("qBanned").textContent=data.counts?.banned||0;
  const canManageQuarantine=canAccess("quarantine","admin");
  qHeaderById={};
  (data.items||[]).forEach(item=>{qHeaderById[item.pdp_id]=String(item.header||"");});

  document.getElementById("qRows").innerHTML=(data.items||[]).map(item=>{
    let state="Quarantined",stateClass="";
    if(item.is_released){state="Released";stateClass="released";}
    else if(item.is_manual_spam){state="Marked Spam";stateClass="flagged";}
    const finalized=Boolean(item.is_released||item.is_manual_spam);
    const actionDisabled=finalized||!canManageQuarantine;

    const category=String(item.category||"Spam").toLowerCase();
    const cardClass=category==="virus"?"virus-card":category==="banned"?"banned-card":"spam-card";
    const scoreEvidence=spamEvidenceSummary(item);

    const spfValue=String(item.spf||"none").toLowerCase();
    const dkimValue=String(item.dkim||"none").toLowerCase();
    const scoreNum=parseFloat(item.score||"0");
    let scoreClass="low";
    if(!Number.isNaN(scoreNum)){ if(scoreNum>=10) scoreClass="high"; else if(scoreNum>=5) scoreClass="medium"; }

    return `
      <div class="qmail">
        <div class="qside ${cardClass}">
          <label class="qrow-select" title="${finalized?"Already finalized":"Select for bulk action"}">
            <input class="qselect-item" type="checkbox"
              aria-label="Select quarantine item"
              data-pdp-id="${esc(item.pdp_id)}"
              ${actionDisabled?"disabled":""}>
          </label>
          <div class="qcat">${esc(item.category)}</div>
          <div class="qmail-time">${esc(item.timestamp)}</div>
        </div>
        <div class="qmail-main">
          <div class="qdetails">
            <div class="qdetails-label">From:</div>
            <div class="qdetails-value" title="${esc(item.from)}">${esc(item.from)}</div>
            <div class="qdetails-label">To:</div>
            <div class="qdetails-value" title="${esc(item.display_to||"No home-domain recipient found")}">${esc(item.display_to||"No home-domain recipient found")}</div>
            <div class="qdetails-label">Subject:</div>
            <div class="qdetails-value qdetails-subject" title="${esc(item.subject)}">${esc(item.subject)}</div>
            <div class="qdetails-label">ID:</div>
            <div class="qdetails-value qdetails-id" title="${esc(item.pdp_id)}">${esc(item.pdp_id)}</div>
            <div class="qdetails-label">Tools:</div>
            <div class="qdetail-tools">
              <button type="button" class="qheader-btn" onclick='openQuarantineHeader(${JSON.stringify(item.pdp_id)})'>View Full Header</button>
              <button type="button" class="qintel-link" onclick='openQuarantineIntelligence(${JSON.stringify(item.pdp_id)})'>Intelligence</button>
            </div>
          </div>
        </div>
        <div class="qauthbox">
          <div class="qauthline"><span>SPF</span><span class="qauth ${spfValue}">${esc(spfValue.toUpperCase())}</span></div>
          <div class="qauthline"><span>DKIM</span><span class="qauth ${dkimValue}">${esc(dkimValue.toUpperCase())}</span></div>
        </div>
        <div class="qscorebox">
          <div class="qscorelabel">Spam score</div>
          <div class="qscore-hover" tabindex="0" aria-label="SpamAssassin score breakdown">
            <span class="qscore ${scoreClass}">Score: ${esc(item.score)}</span>
            <div class="qscore-tooltip" role="tooltip">${scoreEvidence}</div>
          </div>
          <span class="qstate ${stateClass}">${esc(state)}</span>
          <span class="qlearnstate ${item.learning?"learned":""}">${item.learning?`Learned ${esc(String(item.learning).toUpperCase())}`:"Not learned"}</span>
          ${item.is_released?`<div class="qrelease-status"><b>Release Status</b><span>${esc(item.release_status?.delivery_status||item.release_status?.status||"RELEASED")}</span><span>Queue ID: ${item.release_status?.queue_id?(canAccess("mail_flow","view")?`<button type="button" class="queue-link" onclick='openFlow(${JSON.stringify(item.release_status.queue_id)})'>${esc(item.release_status.queue_id)}</button>`:esc(item.release_status.queue_id)):"Not captured"}</span></div>`:""}
        </div>
        <div class="qactionbox">
          <div class="qactions qprimary-actions">
            <button class="qreleaseham" ${actionDisabled||item.learning?"disabled":""} onclick='quarantineReleaseLearnHam(${JSON.stringify(item.pdp_id)})'>RELEASE + HAM</button>
            <button class="qspam" ${actionDisabled?"disabled":""} onclick='quarantineAction("spam",${JSON.stringify(item.pdp_id)})'>MARK SPAM</button>
            ${item.learning?`<button class="secondary-btn qcorrect" onclick='quarantineCorrectLearning(${JSON.stringify(item.pdp_id)},${JSON.stringify(item.learning==="spam"?"ham":"spam")})'>CORRECT TO ${item.learning==="spam"?"HAM":"SPAM"}</button>`:""}
          </div>
        </div>
      </div>`;
  }).join("")||'<div class="qmail"><div class="qmail-main">No quarantine items.</div></div>';

  bindQuarantineSelection();

  const quarantinePageText=`Page ${qp} of ${qtp}`;
  document.getElementById("qPg").textContent=quarantinePageText;
  document.getElementById("qPgTop").textContent=quarantinePageText;
  ["qTopPrev","qBottomPrev"].forEach(id=>{
    const button=document.getElementById(id);
    if(button) button.disabled=qp<=1;
  });
  ["qTopNext","qBottomNext"].forEach(id=>{
    const button=document.getElementById(id);
    if(button) button.disabled=qp>=qtp;
  });
  document.getElementById("qMessage").textContent=
    data.error?`Cache error: ${data.error}`:`${data.total_items||0} items`;
  document.getElementById("qLastUpdated").textContent=data.last_updated||"-";
  document.getElementById("qRangeText").textContent=
    `Showing page ${qp} of ${qtp} • ${data.total_items||0} emails`;
  document.getElementById("qDomains").innerHTML=
    (data.top_domains||[]).map(x=>`${esc(x.domain)} (${x.count})`).join(" &nbsp; | &nbsp; ")||"-";
}

async function quarantineCorrectLearning(pdpId,newMode){
  const label=String(newMode||"").toUpperCase();
  if(!window.confirm(`Correct this message's previous human learning decision to ${label}? SpamAssassin will forget the prior class and learn the opposite class. The audit history will be retained.`)) return;
  const message=document.getElementById("qMessage");
  try{
    const response=await apiFetch(`/api/quarantine/correct-learning?mode=${encodeURIComponent(newMode)}&pdp_id=${encodeURIComponent(pdpId)}`,{method:"POST"});
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"Classification correction failed");
    message.textContent=`Corrected to ${label}. Previous decision: ${String(data.previous_learning||"").toUpperCase()}.`;
    await loadQuarantine(qp,{preserveSelection:true});
  }catch(error){ message.textContent=error.message||"Classification correction failed"; }
}

async function quarantineReleaseLearnHam(pdpId){
  if(!window.confirm("Release this message and then learn it as HAM?")) return;
  const message=document.getElementById("qMessage");
  message.textContent="Releasing message and learning HAM...";
  try{
    const response=await apiFetch(`/api/quarantine/release-learn-ham?pdp_id=${encodeURIComponent(pdpId)}`,{method:"POST"});
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"Release + HAM failed");
    message.textContent=data.ok?"Released and learned as HAM":(data.error||"Released; HAM learning failed");
    await loadQuarantine(qp);
  }catch(error){
    message.textContent=error.message||"Release + HAM failed";
  }
}

function emailRuleRows(rows){
  if(!rows?.length) return '<div class="ea-empty">No matching scored rules.</div>';
  return `<table class="email-analysis-rules"><thead><tr><th>Rule</th><th>Score</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.name||"-")}</td><td>${r.score==null?esc(r.value||"-"):esc((Number(r.score)>=0?"+":"")+Number(r.score).toFixed(1))}</td></tr>`).join("")}</tbody></table>`;
}

let emailAnalysisSelectedFile=null;
async function selectEmailAnalysisFile(file){
  if(!file)return;
  const lower=(file.name||"").toLowerCase();
  const message=document.getElementById("emailAnalysisMessage");
  if(!lower.endsWith(".eml")&&!lower.endsWith(".msg")){message.textContent="Unsupported file type. Select an .eml or Microsoft Outlook .msg file.";emailAnalysisSelectedFile=null;return;}
  if(file.size>10485760){message.textContent="Selected file exceeds the 10 MB manual-analysis limit.";emailAnalysisSelectedFile=null;return;}
  emailAnalysisSelectedFile=file;
  if(lower.endsWith(".msg")){document.getElementById("emailAnalysisRaw").value="";document.getElementById("emailAnalysisRaw").placeholder="Outlook .msg selected. Binary MSG content is parsed on the server and is not shown here.";}else{document.getElementById("emailAnalysisRaw").value=await file.text();}
  message.textContent=`Loaded ${file.name} (${file.size} bytes). Click Analyze Email.`;
}
document.getElementById("emailAnalysisFile")?.addEventListener("change",async event=>{await selectEmailAnalysisFile(event.target.files?.[0]);});
const emailDrop=document.getElementById("emailAnalysisDrop");
emailDrop?.addEventListener("dragover",e=>{e.preventDefault();emailDrop.classList.add("dragover");});
emailDrop?.addEventListener("dragleave",()=>emailDrop.classList.remove("dragover"));
emailDrop?.addEventListener("drop",async e=>{e.preventDefault();emailDrop.classList.remove("dragover");await selectEmailAnalysisFile(e.dataTransfer?.files?.[0]);});

function fileToBase64(file){
  return new Promise((resolve,reject)=>{
    const reader=new FileReader();
    reader.onerror=()=>reject(reader.error||new Error("Unable to read selected file"));
    reader.onload=()=>{const bytes=new Uint8Array(reader.result);let binary="";const chunk=0x8000;for(let i=0;i<bytes.length;i+=chunk){binary+=String.fromCharCode(...bytes.subarray(i,i+chunk));}resolve(btoa(binary));};
    reader.readAsArrayBuffer(file);
  });
}

async function analyzeEmailMessage(){
  const raw=document.getElementById("emailAnalysisRaw")?.value||"";
  const message=document.getElementById("emailAnalysisMessage");
  const result=document.getElementById("emailAnalysisResult");
  if(!raw.trim()&&!emailAnalysisSelectedFile){message.textContent="Paste email source or select an .eml/.msg file first.";return;}
  message.textContent="Analyzing locally…";
  result.innerHTML="Analyzing…";
  try{
    let payload={raw};
    if(emailAnalysisSelectedFile){payload={filename:emailAnalysisSelectedFile.name,data_b64:await fileToBase64(emailAnalysisSelectedFile)};}
    const response=await apiFetch("/api/email-analysis",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"Email analysis failed");
    const sa=data.spamassassin||{}, auth=data.authentication||{}, geo=data.geoip||{}, ai=data.ai||{}, trainer=data.ai_trainer||{};
    const candidate=trainer.candidate||null, active=trainer.active||null;
    const aiVerdict=ai.verdict||ai.reason||"Unavailable";
    const aiConfidence=ai.confidence!=null?`${esc(ai.confidence)}%`:"-";
    result.innerHTML=`
      <div class="email-analysis-primary-row">
        <section class="ai-ea-verdict">
          <div class="ai-ea-verdict-head"><div><div class="email-analysis-note"><h4 style="margin:0">Independent AI Analysis</h4>TRAINER-CALIBRATED · CURRENT CANDIDATE</div><div class="ai-ea-verdict-big">${esc(aiVerdict)} · ${aiConfidence}</div></div><span class="engine-status operational">SHADOW ONLY</span></div>
          <div class="ai-ea-modelbar"><div><span>Generation</span><b>${esc(trainer.generation_id||ai.generation_id||"-")}</b></div><div><span>Schema</span><b>v${esc(trainer.feature_schema||ai.feature_schema||"-")}</b></div><div><span>Candidate</span><b>${esc(candidate?.version||ai.model_version||"None")}</b></div><div><span>Active</span><b>${esc(active?.version||"None")}</b></div><div><span>Algorithm</span><b>${esc(ai.algorithm||candidate?.algorithm||"-")}</b></div><div><span>Decision source</span><b>${esc(ai.decision_source||"LEARNED_MODEL")}</b></div></div>
          <div class="ai-ea-engine-grid">
            <div class="ai-ea-engine"><h5>Message AI <span class="engine-status operational">OPERATIONAL</span></h5>NLP/text, stylometry, URLs/domains, MIME/attachments, authentication alignment and sender/header anomalies.<small>Schema-v4 local independent evidence.</small></div>
            <div class="ai-ea-engine"><h5>Infrastructure AI <span class="engine-status operational">LOCAL</span></h5>Score <b>${esc(data.threat_intelligence?.infrastructure?.score??"-")}</b>/100 · source ${esc(data.threat_intelligence?.infrastructure?.source_ip||"-")} · ${data.threat_intelligence?.infrastructure?.asn?`AS${esc(data.threat_intelligence.infrastructure.asn)}`:"ASN unavailable"}.<small>${esc((data.threat_intelligence?.infrastructure?.signals||[]).slice(0,3).map(x=>x.code).join(" · ")||"No elevated local infrastructure signal")}</small></div>
            <div class="ai-ea-engine"><h5>Campaign AI <span class="engine-status operational">LOCAL</span></h5>Score <b>${esc(data.threat_intelligence?.campaign?.score??"-")}</b>/100 · template observations ${esc(data.threat_intelligence?.campaign?.stats?.template_messages??0)}.<small>${esc((data.threat_intelligence?.campaign?.signals||[]).slice(0,3).map(x=>x.code).join(" · ")||"No local campaign cluster threshold crossed")}</small></div>
          </div>
          ${ai.semantic_intent?.available?`<details class="email-analysis-evidence" ${ai.semantic_intent.high_confidence?"open":""}><summary>Semantic impersonation / intent evidence</summary><div class="email-analysis-kv"><span>Relationship score</span><b>${esc(ai.semantic_intent.score??0)}</b><span>Suggested classification</span><b>${esc(ai.semantic_intent.suggested_classification||"-")}</b><span>Signals</span><b>${esc((ai.semantic_intent.signals||[]).join(" · ")||"No high-confidence chain")}</b><span>External action domains</span><b>${esc((ai.semantic_intent.external_action_domains||[]).join(" · ")||"-")}</b></div></details>`:""}
          <div class="ai-ea-separation">AI prediction is not ground truth. R1.1.53 may raise a SHADOW-only semantic SPAM proposal only when multiple raw-message relationship signals agree; it never writes a training label or alters delivery.</div>
        </section>
        <section id="emailAmavisDryRun" class="amavis-dryrun-card"><div class="ai-ea-verdict-head"><div><h4>Amavis / SpamAssassin Dry Run</h4><div class="email-analysis-note">Dedicated analysis-only helper · never production SMTP 10024</div></div><span class="amavis-dryrun-state">CHECKING</span></div><div class="email-analysis-note">Dry-run status will appear here.</div><div class="amavis-dryrun-safety">NO delivery · NO quarantine write · NO release · NO Bayes/sa-learn · NO AI ground truth · NO production queue insertion.</div></section>
      </div>
      <div id="emailAnalysisComparison" class="ea-comparison"><h4 style="margin:0 0 8px">AI vs Amavis Comparison</h4><div class="email-analysis-note">Waiting for dry-run evidence. Independent AI and Amavis/SpamAssassin remain separate evidence paths.</div></div>
      <div class="email-analysis-support-row">
        <section class="ai-ea-evidence"><h4>Authentication / Production Evidence</h4><div class="email-analysis-kv"><span>SPF</span><b>${esc(auth.spf||"none")}</b><span>DKIM</span><b>${esc(auth.dkim||"none")}</b><span>DMARC</span><b>${esc(auth.dmarc||"none")}</b><span>SpamAssassin</span><b>${esc(sa.score??"-")} / ${esc(sa.required_score??"-")} · ${esc(sa.verdict||"UNKNOWN")}</b><span>Persisted Amavis</span><b>${data.amavis_log?.matched?"MATCHED":"NO MATCH IN DATABASE"}</b></div><div class="ai-ea-separation">Observation only. These values are not independent AI training features or ground truth.</div></section>
        <section class="ai-ea-evidence"><h4>Campaign / MIME / Attachment</h4><div class="email-analysis-kv"><span>Campaign score</span><b>${esc(data.threat_intelligence?.campaign?.score??"-")}/100</b><span>Template seen</span><b>${esc(data.threat_intelligence?.campaign?.stats?.template_messages??0)} message(s)</b><span>URLs</span><b>${esc(data.urls?.length??0)}</b><span>Attachments</span><b>${esc(data.attachments?.length??0)}</b><span>Correlation</span><b>${esc(data.threat_intelligence?.correlation?.assessment||"Unavailable")}</b></div></section>
      </div>
      <div class="email-analysis-section"><h4>Message Identity</h4><div class="email-analysis-kv"><span>Format</span><b>${esc(data.source_format||"RFC822/EML")}</b><span>From</span><b>${esc(data.from||"-")}</b><span>To</span><b>${esc(data.to||"-")}</b><span>CC</span><b>${esc(data.cc||"-")}</b><span>Reply-To</span><b>${esc(data.reply_to||"-")}</b><span>Subject</span><b>${esc(data.subject||"-")}</b><span>Date</span><b>${esc(data.date||"-")}</b><span>Message-ID</span><b>${esc(data.message_id||"-")}</b></div></div>
      <div class="email-analysis-section"><h4>BEC / Impersonation Evidence</h4><div class="email-analysis-kv"><span>Overall suspicion</span><b>${esc(data.bec?.overall_suspicion||"LOW")}</b><span>Identity risk</span><b>${esc((data.bec?.identity_risk_score??0)+"%")}</b><span>Intent risk</span><b>${esc((data.bec?.intent_risk_score??0)+"%")}</b><span>Identity auth passes</span><b>${esc(data.bec?.technical_authentication_passes??0)} / 3 · neutral</b><span>Auth interpretation</span><b>${esc(data.bec?.authentication_interpretation||"IDENTITY ONLY")}</b><span>Recommended review</span><b>${esc(data.bec?.recommended_action||"REVIEW")}</b></div><details class="email-analysis-evidence"><summary>Why am I suspicious?</summary>${data.bec?.evidence?.length?`<ul class="email-analysis-list">${data.bec.evidence.map(e=>`<li><b>${esc(e.signal)}</b> — ${esc(e.severity)} — ${esc(e.detail||"")}</li>`).join("")}</ul>`:'<div class="ea-empty">No strong BEC/impersonation indicators detected.</div>'}<div class="email-analysis-note">${esc(data.bec?.note||"")}</div></details></div>
      <div class="email-analysis-section"><h4>Local Email Intelligence Repository <span class="geo-badge">SHADOW · EVIDENCE ONLY</span></h4><div class="email-analysis-kv"><span>Repository</span><b>${esc(data.fraud_intelligence?.repo_version||"-")}</b><span>Primary hypothesis</span><b>${esc(data.fraud_intelligence?.primary?.taxonomy_code||"None")}</b><span>Severity</span><b>${esc(data.fraud_intelligence?.primary?.severity||"-")}</b><span>Suggested classification</span><b>${esc(data.fraud_intelligence?.suggested_classification||"-")}</b></div>${data.fraud_intelligence?.hypotheses?.length?`<details class="email-analysis-evidence" open><summary>Matched fraud hypotheses</summary><ul class="email-analysis-list">${data.fraud_intelligence.hypotheses.map(h=>`<li><b>${esc(h.taxonomy_code)}</b> — ${esc(h.severity)} — score ${esc(h.score)}${h.evidence?.length?`<br><small>${esc(h.evidence.flatMap(e=>e.matched_phrases||[]).slice(0,8).join(" · ")||"structural evidence")}</small>`:""}</li>`).join("")}</ul></details>`:'<div class="ea-empty">No curated fraud hypothesis crossed the repository evidence threshold.</div>'}<div class="email-analysis-note">Repository findings are explainable evidence only. They never create Set-2 ground truth or alter Postfix/Amavis/SpamAssassin decisions.</div></div>
      <div class="email-analysis-section"><h4>URLs</h4>${data.urls?.length?`<ul class="email-analysis-list">${data.urls.slice(0,50).map(u=>`<li>${esc(u)}</li>`).join("")}</ul>`:'<div class="ea-empty">No URLs detected.</div>'}<h4 style="margin-top:12px">Attachments</h4>${data.attachments?.length?`<ul class="email-analysis-list">${data.attachments.map(a=>`<li>${esc(a.filename||"unnamed")} — ${esc(a.content_type||"unknown")} — ${esc(a.size??0)} bytes</li>`).join("")}</ul>`:'<div class="ea-empty">No attachments detected.</div>'}</div>
      <div class="email-analysis-section"><h4>Independent Network Observation <span class="geo-badge">OFFLINE</span></h4><div class="email-analysis-kv"><span>Observed source IP</span><b>${esc(geo.source_ip||"Not found")}</b><span>Country</span><b>${esc(geo.country||geo.reason||"Unavailable")}</b><span>Region / City</span><b>${esc([geo.region,geo.city].filter(Boolean).join(" / ")||"-")}</b><span>ASN</span><b>${geo.asn?`AS${esc(geo.asn)} — ${esc(geo.organization||"")}`:"-"}</b><span>Public hops</span><b>${esc((geo.observed_public_hops||[]).join(" → ")||"-")}</b></div><div class="email-analysis-note">Offline observation only; no live reputation or redirect-chain lookup is performed.</div></div>
      <div class="email-analysis-section"><h4>Three-Tier Correlation <span class="geo-badge">SHADOW ONLY</span></h4><div class="email-analysis-kv"><span>Assessment</span><b>${esc(data.threat_intelligence?.correlation?.assessment||"Unavailable")}</b><span>Correlation score</span><b>${esc(data.threat_intelligence?.correlation?.score??"-")}/100</b><span>Infrastructure</span><b>${esc(data.threat_intelligence?.infrastructure?.score??"-")}/100</b><span>Campaign</span><b>${esc(data.threat_intelligence?.campaign?.score??"-")}/100</b><span>Authority</span><b>NONE · SHADOW</b></div><div class="email-analysis-note">Local correlation only. Authentication success does not imply HAM; no third-party telemetry and no production blocking.</div></div>
      <div class="email-analysis-section"><details class="email-analysis-evidence"><summary>Production SpamAssassin / Amavis evidence</summary><h4>SpamAssassin rules</h4>${emailRuleRows(sa.top_positive||[])}<h4 style="margin-top:12px">Negative / trust rules</h4>${emailRuleRows(sa.top_negative||[])}<h4 style="margin-top:12px">Amavis matching evidence</h4>${(data.amavis_log?.recent_evidence||[]).length?`<pre class="qheader-pre">${esc((data.amavis_log.recent_evidence||[]).join("\n"))}</pre>`:'<div class="ea-empty">No matching persisted Amavis evidence in MariaDB.</div>'}</details></div>`;
    await loadAmavisDryRun(payload,data);
    message.textContent="Analysis complete. Message content was not persisted by this tool.";
  }catch(error){result.textContent=error.message||"Email analysis failed";message.textContent="Analysis failed.";}
}
async function loadAmavisDryRun(payload,baseData){
  const box=document.getElementById("emailAmavisDryRun");
  const cmp=document.getElementById("emailAnalysisComparison");
  if(!box)return;
  try{
    const response=await apiFetch("/api/email-analysis/amavis-dry-run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const d=await response.json();
    const state=String(d.status||"READY").toUpperCase();
    const sa=d.spamassassin||{};
    box.innerHTML=`<div class="ai-ea-verdict-head"><div><h4>Amavis / SpamAssassin Dry Run</h4><div class="email-analysis-note">Dedicated analysis-only helper</div></div><span class="amavis-dryrun-state ready">${esc(state)}</span></div><div class="email-analysis-kv"><span>Amavis verdict</span><b>${esc(d.amavis_verdict||"-")}</b><span>Spam score</span><b>${esc(sa.score??d.spam_score??"-")} / ${esc(sa.required_score??d.required_score??"-")}</b><span>SA verdict</span><b>${esc(sa.verdict||d.spamassassin_verdict||"-")}</b><span>Virus</span><b>${esc(d.virus||"-")}</b><span>Banned content</span><b>${esc(d.banned||"-")}</b><span>Processing time</span><b>${esc(d.processing_ms??"-")} ms</b><span>Policy bank</span><b>${esc(d.policy_bank||"DRY_RUN")}</b></div>${(d.rules||sa.rules||[]).length?`<details class="email-analysis-evidence"><summary>Matched SpamAssassin rules</summary>${emailRuleRows(d.rules||sa.rules||[])}</details>`:""}<div class="amavis-dryrun-safety">ANALYSIS ONLY · helper attested no delivery/quarantine/release/learning/queue side effects.</div>`;
    const aiVerdict=String(baseData?.ai?.prediction||baseData?.ai?.verdict||"UNKNOWN").toUpperCase();
    const avVerdict=String(d.amavis_verdict||sa.verdict||"UNKNOWN").toUpperCase();
    cmp.innerHTML=`<h4 style="margin:0 0 8px">AI vs Amavis Comparison</h4><div class="email-analysis-kv"><span>Independent AI</span><b>${esc(aiVerdict)}</b><span>Amavis / SA</span><b>${esc(avVerdict)}</b><span>Relationship</span><b>${esc(aiVerdict===avVerdict?"AGREEMENT":"REVIEW DIFFERENCE")}</b><span>Authority</span><b>NONE · ANALYSIS ONLY</b></div><div class="email-analysis-note">Comparison is operator evidence only. Neither path creates ground truth or changes mail flow.</div>`;
  }catch(error){
    let detail=error?.message||"Dry-run unavailable";
    box.innerHTML=`<div class="ai-ea-verdict-head"><div><h4>Amavis / SpamAssassin Dry Run</h4><div class="email-analysis-note">Dedicated analysis-only helper</div></div><span class="amavis-dryrun-state unavailable">NOT CONFIGURED</span></div><div class="email-analysis-note">${esc(detail)}</div><div class="amavis-dryrun-safety">Production Amavis SMTP port 10024 is intentionally never used for dry-run analysis. Configure the dedicated helper only after validating its no-side-effect policy.</div>`;
    if(cmp)cmp.innerHTML=`<h4 style="margin:0 0 8px">AI vs Amavis Comparison</h4><div class="email-analysis-note">Amavis dry-run evidence unavailable; independent AI result remains valid SHADOW evidence.</div>`;
  }
}

function clearEmailAnalysis(){emailAnalysisSelectedFile=null;document.getElementById("emailAnalysisRaw").value="";document.getElementById("emailAnalysisRaw").placeholder="Paste complete RFC822 message source here...";document.getElementById("emailAnalysisFile").value="";document.getElementById("emailAnalysisResult").textContent="No message analyzed yet.";document.getElementById("emailAnalysisMessage").textContent="";}

function qintelTableRows(rows,columns){
  if(!rows?.length) return '<div class="ea-empty">No records.</div>';
  return `<table class="qintel-table"><thead><tr>${columns.map(c=>`<th>${esc(c.label)}</th>`).join("")}</tr></thead><tbody>${rows.map(row=>`<tr>${columns.map(c=>`<td>${esc(row[c.key]??"-")}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

let currentQintelPdpId="";
async function openQuarantineIntelligence(pdpId){
  currentQintelPdpId=pdpId;
  const modal=document.getElementById("quarantineIntelModal");
  const body=document.getElementById("qintelBody");
  const subtitle=document.getElementById("qintelSubtitle");
  modal.classList.add("open");
  subtitle.textContent=pdpId;
  body.innerHTML='<div class="qintel-card">Loading Quarantine Intelligence…</div>';
  try{
    const response=await apiFetch(`/api/quarantine/intelligence?pdp_id=${encodeURIComponent(pdpId)}`);
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"Unable to load intelligence");
    const ai=data.ai||{};
    const aiProposal=data.ai_candidate_proposal||{};
    const fraudIntel=data.fraud_intelligence||{};
    const aiTrainer=data.ai_trainer||{};
    const proposedLabel=aiProposal.available?String(aiProposal.verdict||"").toUpperCase():String(fraudIntel.suggested_label||"").toUpperCase();
    const proposedClass=proposedLabel==="SPAM"?String(aiProposal.suggested_classification||fraudIntel.suggested_classification||"OTHER_SPAM").toUpperCase():(proposedLabel==="HAM"?"OTHER_HAM":"");
    const aiVerdict=ai.available?`${esc(ai.verdict||"-")} (${esc(ai.confidence??"-")}%)`:esc(ai.reason||"No active AI model");
    const aiActive=aiTrainer.active?.version||"None";
    const aiCandidate=aiTrainer.candidate?.version||"None";
    const aiMetrics=aiTrainer.candidate?.metrics||{};
    const canTrainAI=canAccess("quarantine","admin");
    const identity=data.message_identity||{};
    body.innerHTML=`
      <div class="qintel-grid">
        <section class="qintel-card qintel-identity"><h4>Current Message Identity</h4><div class="qintel-identity-grid">
          <div class="qintel-identity-cell"><span>Queue-ID / Quarantine item</span><b>${esc(identity.pdp_id||pdpId)}</b></div>
          <div class="qintel-identity-cell"><span>mail_id</span><b>${esc(identity.mail_id||"-")}</b></div>
          <div class="qintel-identity-cell"><span>Message-ID</span><b>${esc(identity.message_id||"-")}</b></div>
          <div class="qintel-identity-cell"><span>Time (IST)</span><b>${esc(identity.time||"-")}</b></div>
          <div class="qintel-identity-cell"><span>Sender</span><b>${esc(identity.sender||"-")}</b></div>
          <div class="qintel-identity-cell"><span>Recipient</span><b>${esc(identity.recipient||"-")}</b></div>
          <div class="qintel-identity-cell"><span>Final Status</span><b class="qintel-status-pill">${esc(identity.final_status||"QUARANTINED")}</b></div>
          <div class="qintel-identity-cell"><span>Size</span><b>${esc(identity.size||"-")}</b></div>
        </div></section>
        <div class="qintel-review-row${canTrainAI?"":" qintel-review-solo"}">
        <section class="qintel-card qintel-ai qintel-ai-primary"><h4>AI Shadow Intelligence <span id="aiLiveBadge" class="qintel-live-badge">LIVE · 10s</span></h4><div class="qintel-kv">
          <span>Mode</span><b>SHADOW ONLY</b>
          <span>AI Generation</span><b id="aiLiveGeneration">${esc(aiTrainer.generation_id||"independent-g1")}</b><span>Authentication policy</span><b id="aiLiveAuthPolicy">${esc(aiTrainer.authentication_policy||"identity-neutral-v1")}</b>
          <span>Prediction source</span><b>${aiProposal.available?(aiProposal.decision_source==="SEMANTIC_INTENT_OVERLAY"?`Semantic intent overlay + Candidate ${esc(aiCandidate)}`:`Candidate ${esc(aiCandidate)}`):(aiActive!=="None"?`Active ${esc(aiActive)}`:"No promoted model")}</b>
          <span>Prediction status</span><b>${aiVerdict}</b>
          <span>Active candidate model</span><b>${esc(aiCandidate)}</b>
          <span>Active model</span><b class="qintel-active-none">${esc(aiActive)}${aiActive==="None"?" (No promoted model)":""}</b>
          <span>Amavis AI hook</span><b id="aiLiveHook">${esc((aiTrainer.amavis_hook?.mode||"disabled").toUpperCase())} · RESERVED FOR LATER</b>
        </div>
        <div class="qintel-live-grid">
          <div class="qintel-live-panel">
            <div class="qintel-live-title"><span>Current Data</span><span class="qintel-live-badge">LIVE</span></div>
            <div class="qintel-kv">
              <span>Active model</span><b id="aiLiveActive">${esc(aiActive)}</b>
              <span>Candidate model</span><b id="aiLiveCandidate">${esc(aiCandidate)}</b>
              <span>Training labels</span><b id="aiLiveLabels">${esc(aiTrainer.dataset_samples??0)} (HAM ${esc(aiTrainer.ham_labels??0)} / SPAM ${esc(aiTrainer.spam_labels??0)})</b>
              <span>Hard-HAM labels</span><b id="aiLiveHardHam">${esc(aiTrainer.hard_ham_labels??0)} · weight ${esc(aiTrainer.hard_ham_weight??1)}</b>
              <span>Feature schema</span><b id="aiLiveSchema">v${esc(aiTrainer.feature_schema??1)} · ${esc((aiTrainer.feature_families||[]).length||0)} independent feature families</b><span>Training provenance</span><b id="aiLiveProvenance">ADMIN GROUND TRUTH ONLY · excluded ${esc(aiTrainer.training_eligibility?.excluded_non_authoritative_rows??0)} historical/non-authoritative rows</b>
              <span>Auto-train</span><b id="aiLiveAutoTrain">${aiTrainer.auto_train_after_new_labels>0?esc("Every "+aiTrainer.auto_train_after_new_labels+" new labels; next in "+aiTrainer.next_auto_train_in+(aiTrainer.auto_train_running?" — RUNNING":"")):"Disabled"}</b>
            </div>
            <div id="aiLiveCurrentUpdated" class="qintel-live-updated">Live feed initialized from current request.</div>
          </div>
          <div class="qintel-live-panel">
            <div class="qintel-live-title"><span>Metrics</span><span class="qintel-live-badge">LIVE</span></div>
            <div class="qintel-kv">
              <span>Candidate algorithm</span><b id="aiLiveAlgorithm">${esc(aiTrainer.candidate?.algorithm||"Not trained")}</b>
              <span>Candidate accuracy</span><b id="aiLiveAccuracy">${aiMetrics.accuracy==null?"N/A":esc(aiMetrics.accuracy+"%")}</b>
              <span>Balanced accuracy</span><b id="aiLiveBalanced">${aiMetrics.balanced_accuracy==null?"N/A":esc(aiMetrics.balanced_accuracy+"%")}</b>
              <span>HAM precision / recall / F1</span><b id="aiLiveHamMetrics">${aiMetrics.ham_precision==null?"N/A":esc(aiMetrics.ham_precision+"% / "+aiMetrics.ham_recall+"% / "+aiMetrics.ham_f1+"%")}</b>
              <span>SPAM precision / recall / F1</span><b id="aiLiveSpamMetrics">${aiMetrics.spam_precision==null?"N/A":esc(aiMetrics.spam_precision+"% / "+aiMetrics.spam_recall+"% / "+aiMetrics.spam_f1+"%")}</b>
              <span>HAM→SPAM false positive</span><b id="aiLiveFp">${aiMetrics.false_positive_rate==null?"N/A":esc(aiMetrics.false_positive_rate+"% ("+(aiMetrics.false_positive??0)+")")}</b>
              <span>SPAM→HAM false negative</span><b id="aiLiveFn">${aiMetrics.false_negative_rate==null?"N/A":esc(aiMetrics.false_negative_rate+"% ("+(aiMetrics.false_negative??0)+")")}</b>
              <span>Validation split</span><b id="aiLiveValidation">${aiTrainer.candidate?esc((aiMetrics.holdout_samples??0)+" samples (HAM "+(aiMetrics.holdout_ham??0)+" / SPAM "+(aiMetrics.holdout_spam??0)+")"):"N/A"}</b><span>Hard-HAM validation</span><b id="aiLiveHardHamValidation">${aiMetrics.holdout_hard_ham?esc((aiMetrics.hard_ham_correct??0)+" / "+aiMetrics.holdout_hard_ham+" correct · recall "+(aiMetrics.hard_ham_recall??"-")+"%") : "N/A"}</b>
            </div>
            <div id="aiLiveMetricsUpdated" class="qintel-live-updated">Metrics update automatically when a candidate is created.</div>
          </div>
        </div>
        <div class="qintel-ai-note">AI never controls Postfix, Amavis, SpamAssassin, release, or quarantine decisions. Explicit Mail Admin HAM/SPAM ground truth supplies AI labels independently of SpamAssassin/Amavis learning. Automatic retraining creates a candidate only; activation remains explicit and affects shadow prediction only.</div>
        ${aiProposal.semantic_intent?.available?`<div class="qintel-ai-metrics qintel-ai-metrics-single" style="margin-top:10px"><div class="qintel-ai-metric"><h4>Semantic Impersonation / Intent Intelligence</h4><div class="qintel-ai-grid"><span>Assessment</span><b>${aiProposal.semantic_intent.high_confidence?"HIGH-CONFIDENCE PHISHING PATTERN":"CONTEXTUAL"}</b><span>Suggested classification</span><b>${esc(aiProposal.semantic_intent.suggested_classification||"-")}</b><span>Relationship score</span><b>${esc(aiProposal.semantic_intent.score??0)}</b><span>Signals</span><b>${esc((aiProposal.semantic_intent.signals||[]).join(" · ")||"No multi-signal impersonation chain")}</b><span>Recipient domain(s)</span><b>${esc((aiProposal.semantic_intent.recipient_domains||[]).join(" · ")||"-")}</b><span>External action domain(s)</span><b>${esc((aiProposal.semantic_intent.external_action_domains||[]).join(" · ")||"-")}</b></div><div class="qintel-ai-note">R1.1.53 raw-message relationship analysis. A single phrase never forces SPAM; the shadow overlay requires external sender + recipient mail-service impersonation + release/action lure + an action URL external to both sender and recipient. No SpamAssassin/Amavis verdict is consumed.</div></div></div>`:""}
        ${aiProposal.attachment_intelligence?.available?`<div class="qintel-ai-metrics qintel-ai-metrics-single" style="margin-top:10px"><div class="qintel-ai-metric"><h4>Independent Attachment Intelligence</h4><div class="qintel-ai-grid"><span>Risk</span><b>${esc(aiProposal.attachment_intelligence.risk||"NORMAL")}</b><span>Nested archive</span><b>${aiProposal.attachment_intelligence.nested_archive?"YES":"NO"}</b><span>Archive depth</span><b>${esc(aiProposal.attachment_intelligence.archive_depth??0)}</b><span>Dangerous members</span><b>${esc(aiProposal.attachment_intelligence.dangerous_member_count??0)}</b><span>Detected</span><b>${esc((aiProposal.attachment_intelligence.dangerous_members||[]).map(x=>x.name).slice(0,8).join(" · ")||"None")}</b></div><div class="qintel-ai-note">Local-only bounded archive inspection. Members are never executed and no Amavis/SpamAssassin verdict is used as an AI feature.</div></div></div>`:""}
        <div class="qintel-ai-metrics" style="margin-top:10px"><div class="qintel-ai-metric"><h4>Infrastructure AI · LOCAL</h4><div class="qintel-ai-grid"><span>Score</span><b>${esc(data.threat_intelligence?.infrastructure?.score??"-")}/100</b><span>Source IP</span><b>${esc(data.threat_intelligence?.infrastructure?.source_ip||"-")}</b><span>Observed PTR/from</span><b>${esc(data.threat_intelligence?.infrastructure?.observed_reverse_name||"-")}</b><span>Observed HELO</span><b>${esc(data.threat_intelligence?.infrastructure?.observed_helo||"-")}</b><span>ASN</span><b>${data.threat_intelligence?.infrastructure?.asn?`AS${esc(data.threat_intelligence.infrastructure.asn)} — ${esc(data.threat_intelligence.infrastructure.asn_organization||"")}`:"-"}</b><span>Signals</span><b>${esc((data.threat_intelligence?.infrastructure?.signals||[]).map(x=>x.code).slice(0,5).join(" · ")||"No elevated signal")}</b></div></div><div class="qintel-ai-metric"><h4>Campaign AI · LOCAL</h4><div class="qintel-ai-grid"><span>Score</span><b>${esc(data.threat_intelligence?.campaign?.score??"-")}/100</b><span>Template seen</span><b>${esc(data.threat_intelligence?.campaign?.stats?.template_messages??0)} message(s)</b><span>Sender domains</span><b>${esc(data.threat_intelligence?.campaign?.stats?.template_distinct_sender_domains??0)}</b><span>Source IPs</span><b>${esc(data.threat_intelligence?.campaign?.stats?.template_distinct_source_ips??0)}</b><span>ASNs</span><b>${esc(data.threat_intelligence?.campaign?.stats?.template_distinct_asns??0)}</b><span>Signals</span><b>${esc((data.threat_intelligence?.campaign?.signals||[]).map(x=>x.code).slice(0,5).join(" · ")||"No cluster threshold crossed")}</b></div></div></div>
        <div class="qintel-ai-note" style="margin-top:8px">Three-tier correlation: <b>${esc(data.threat_intelligence?.correlation?.assessment||"Unavailable")}</b> · score <b>${esc(data.threat_intelligence?.correlation?.score??"-")}/100</b> · SHADOW ONLY · authority NONE. Local observations only; no third-party threat feed.</div>
        ${canTrainAI?`<div class="qintel-ai-actions"><button type="button" onclick="aiBackfillLabels()">Training Provenance Audit</button><button type="button" onclick="aiTrainCandidate()">Train Candidate</button><button id="aiLivePromoteButton" type="button" onclick="aiPromoteCandidate()" ${aiCandidate==="None"?"disabled":""}>Activate Candidate Model</button></div>`:""}
        </section>
        ${canTrainAI?`<section class="qintel-card qintel-ground-truth"><h4>Mail Admin Ground Truth <span class="geo-badge">AI ONLY</span></h4>
          <div id="aiGtSavedState" class="qintel-ai-note" style="margin-bottom:10px"></div>
          <div class="qintel-gt-top">
            <div class="qintel-proposal-box"><div class="qintel-section-label">AI Proposal (Pre-filled)</div><div class="qintel-kv"><span>AI proposed decision</span><b id="aiGtProposalLabel">${esc(proposedLabel||"NO PROPOSAL")}${aiProposal.available?` · ${esc(aiProposal.confidence??"-")}%`:""}</b>
            <span>AI proposed classification</span><b id="aiGtProposalClass">${esc(proposedClass||"-")}</b>
            <span>Source</span><b>${aiProposal.available?(aiProposal.decision_source==="SEMANTIC_INTENT_OVERLAY"?`Semantic intent overlay + Candidate ${esc(aiCandidate)}`:`Candidate ${esc(aiCandidate)}`):"Repository hypothesis only"}</b>
            <span>Local intelligence repository</span><b>${esc(fraudIntel.repo_version||"-")}</b>
            <span>Hypothesis</span><b>${esc(fraudIntel.primary?.taxonomy_code||"No harmful-email hypothesis triggered")}</b></div></div>
            <div class="qintel-gt-info">The AI proposal is pre-filled for administrator review. This is AI-only Ground Truth and does not call sa-learn, change Bayes, release quarantine, or alter Amavis/Postfix delivery.<br><br>Acknowledge if correct, or change decision/classification before saving.<br><br>Only explicit administrator action creates Set-2 Ground Truth.</div>
          </div>
          <div class="qintel-admin-box"><div class="qintel-section-label admin">Admin Decision (Required)</div><div class="qintel-form-grid">
            <label><span>Primary decision *</span><select id="aiGtLabel" onchange="updateAiGtClasses();updateAiGtActionState()"><option value="HAM">HAM</option><option value="SPAM">SPAM</option></select></label>
            <label><span>Classification *</span><select id="aiGtClass" onchange="updateAiGtActionState()"></select></label>
            <label><span>Review / reversal reason</span><select id="aiGtReason"><option value="">Select reason if changing proposal…</option><option value="AI_FALSE_POSITIVE">AI false positive</option><option value="AI_FALSE_NEGATIVE">AI false negative</option><option value="MISCLASSIFIED_SUBTYPE">Wrong classification/subtype</option><option value="EXPECTED_BUSINESS_CONTEXT">Expected business context</option><option value="UNSOLICITED_UCE">Unsolicited commercial email</option><option value="PHISHING_OR_FRAUD_EVIDENCE">Phishing/fraud evidence</option><option value="OTHER_REVIEWED_REASON">Other reviewed reason</option></select><small>Required for a HAM↔SPAM reversal against an existing human label.</small></label>
            <label><span>Notes (optional)</span><textarea id="aiGtNotes" maxlength="1000" rows="3" placeholder="Add admin notes here…"></textarea></label>
          </div>
          <div class="qintel-gt-actions"><button id="aiGtAckButton" class="qintel-ack" type="button" onclick="submitAiGroundTruth('ack')">Acknowledge AI Proposal</button><button id="aiGtSaveButton" type="button" onclick="submitAiGroundTruth('change')">Save Changed Ground Truth</button><button class="qintel-reset" type="button" onclick="resetAiGroundTruth()">Reset</button></div></div>
          <div class="qintel-conflict-note">If you change HAM → SPAM or SPAM → HAM against existing human labels, a conflict investigation will be created automatically and a reversal reason is required.</div>
        </section>`:""}
        </div>
        <div class="qintel-support-row">
        <section class="qintel-card qintel-support-pair"><h4>GEO-IP Intelligence <span class="geo-badge">OFFLINE</span></h4><div class="qintel-kv">
          <span>Observed source IP</span><b>${esc(data.geoip?.source_ip||"Not found")}</b>
          <span>Country</span><b>${esc(data.geoip?.country||data.geoip?.reason||"Unavailable")}</b>
          <span>Region / City</span><b>${esc([data.geoip?.region,data.geoip?.city].filter(Boolean).join(" / ")||"-")}</b>
          <span>ASN</span><b>${data.geoip?.asn?`AS${esc(data.geoip.asn)} — ${esc(data.geoip.organization||"")}`:"-"}</b>
          <span>Observed public hops</span><b>${esc((data.geoip?.observed_public_hops||[]).join(" → ")||"-")}</b>
        </div><div class="qintel-ai-note">Geo-IP uses only local MMDB data. No external lookup is performed. The source IP is the oldest public IP observed in Received headers and should be treated as evidence, not absolute sender identity.</div></section>
        <section class="qintel-card qintel-support-pair"><h4>Sender Policy</h4>${qintelTableRows(data.sender_policy||[],[
          {key:"username",label:"Scope"},{key:"preference",label:"Preference"},{key:"value",label:"Value"}
        ])}</section>
        </div>
        <section class="qintel-card qintel-wide"><h4>Amavis Current Message Trace <span class="geo-badge">READ ONLY</span></h4><div class="qintel-kv">
          <span>Log source</span><b>${esc(data.amavis_log?.path||"/host-amavis/logs/amavis.log")}</b>
          <span>Database storage</span><b>${esc(data.amavis_log?.storage||"MariaDB continuous evidence")}</b>
          <span>Ingest status</span><b>${esc(data.amavis_log?.ingestion?.status||"UNKNOWN")}</b>
          <span>Trace scope</span><b>${esc(data.amavis_log?.scope||"CURRENT_MESSAGE_ONLY")}</b><span>Matched by</span><b>${esc(data.amavis_log?.matched_by||"-")}</b><span>Evidence matched</span><b>${data.amavis_log?.matched?"YES":"NO"}</b>
          <span>Verdict hint</span><b>${esc(data.amavis_log?.verdict_hint||"-")}</b>
          <span>Release queue IDs</span><b>${esc((data.amavis_log?.queue_ids||[]).join(", ")||"-")}</b>
        </div><details class="email-analysis-evidence"><summary>Current message Amavis trace</summary>${(data.amavis_log?.recent_evidence||[]).length?`<pre class="qheader-pre">${esc((data.amavis_log.recent_evidence||[]).join("\n"))}</pre>`:'<div class="ea-empty">No correlated evidence is currently stored in MariaDB for this message. This does not mean Amavis never processed it; check ingestion status and correlation identifiers.</div>'}</details>
        <details class="email-analysis-evidence" open><summary>Amavis attachment content · MariaDB history (${esc(data.amavis_log?.attachment_history_count||0)})</summary>
          ${(data.amavis_log?.attachment_history||[]).length?`<div class="qintel-table-wrap"><table class="qintel-table"><thead><tr><th>Time</th><th>Attachment / member</th><th>Amavis log-derived content</th></tr></thead><tbody>${(data.amavis_log.attachment_history||[]).map(a=>`<tr><td>${esc(a.event_time||"-")}</td><td>${esc(a.attachment_name||"-")}</td><td><pre class="qheader-pre">${esc(a.content_text||"-")}</pre></td></tr>`).join("")}</tbody></table></div>`:'<div class="ea-empty">No attachment/archive content has been reported by Amavis for this current message.</div>'}
          <div class="qintel-ai-note">Attachment content shown here is evidence reported in the read-only Amavis log and retained in MariaDB for history. The dashboard does not open attachments, execute content, or extract archives.</div>
        </details></section>
        <section class="qintel-card qintel-wide"><h4>Dashboard Learning History</h4>${qintelTableRows(data.history||[],[
          {key:"learned_at",label:"Time"},{key:"learning_type",label:"Class"},{key:"learned_by",label:"User"},{key:"examined_count",label:"Examined"},{key:"learned_count",label:"Learned"}
        ])}</section>
      </div>`;
    initAiGroundTruthProposal(proposedLabel,proposedClass,data.admin_ground_truth||{});
  }catch(error){
    body.innerHTML=`<div class="qintel-card">${esc(error.message||"Unable to load intelligence")}</div>`;
  }
}


let aiTrainerLiveTimer=null;
let aiTrainerLiveRequestActive=false;
const AI_TRAINER_LIVE_INTERVAL_MS=10000;

function aiLiveSetText(id,value){
  const node=document.getElementById(id);
  if(node) node.textContent=value;
}

function aiLivePercent(value){
  return value==null?"N/A":`${value}%`;
}

function aiLiveTriple(metrics,prefix){
  const precision=metrics?.[`${prefix}_precision`];
  if(precision==null) return "N/A";
  return `${precision}% / ${metrics?.[`${prefix}_recall`]??"-"}% / ${metrics?.[`${prefix}_f1`]??"-"}%`;
}

function aiLiveApplyStatus(status){
  const metrics=status?.candidate?.metrics||{};
  const active=status?.active?.version||"None";
  const candidate=status?.candidate?.version||"None";
  aiLiveSetText("aiLiveGeneration",status?.generation_id||"independent-g1");
  aiLiveSetText("aiLiveAuthPolicy",status?.authentication_policy||"identity-neutral-v1");
  aiLiveSetText("aiLiveHook",`${String(status?.amavis_hook?.mode||"disabled").toUpperCase()} · RESERVED FOR LATER`);
  aiLiveSetText("aiLiveActive",active);
  aiLiveSetText("aiLiveCandidate",candidate);
  aiLiveSetText("aiLiveLabels",`${status?.dataset_samples??0} (HAM ${status?.ham_labels??0} / SPAM ${status?.spam_labels??0})`);
  aiLiveSetText("aiLiveHardHam",`${status?.hard_ham_labels??0} · weight ${status?.hard_ham_weight??1}`);
  aiLiveSetText("aiLiveSchema",`v${status?.feature_schema??1} · ${(status?.feature_families||[]).length||0} independent feature families`);
  aiLiveSetText("aiLiveProvenance",`ADMIN GROUND TRUTH ONLY · excluded ${status?.training_eligibility?.excluded_non_authoritative_rows??0} historical/non-authoritative rows`);
  aiLiveSetText("aiLiveAutoTrain",status?.auto_train_after_new_labels>0?`Every ${status.auto_train_after_new_labels} new labels; next in ${status.next_auto_train_in}${status.auto_train_running?" — RUNNING":""}`:"Disabled");
  aiLiveSetText("aiLiveAlgorithm",status?.candidate?.algorithm||"Not trained");
  aiLiveSetText("aiLiveAccuracy",aiLivePercent(metrics.accuracy));
  aiLiveSetText("aiLiveBalanced",aiLivePercent(metrics.balanced_accuracy));
  aiLiveSetText("aiLiveHamMetrics",aiLiveTriple(metrics,"ham"));
  aiLiveSetText("aiLiveSpamMetrics",aiLiveTriple(metrics,"spam"));
  aiLiveSetText("aiLiveFp",metrics.false_positive_rate==null?"N/A":`${metrics.false_positive_rate}% (${metrics.false_positive??0})`);
  aiLiveSetText("aiLiveFn",metrics.false_negative_rate==null?"N/A":`${metrics.false_negative_rate}% (${metrics.false_negative??0})`);
  aiLiveSetText("aiLiveValidation",status?.candidate?`${metrics.holdout_samples??0} samples (HAM ${metrics.holdout_ham??0} / SPAM ${metrics.holdout_spam??0})`:"N/A");
  aiLiveSetText("aiLiveHardHamValidation",metrics.holdout_hard_ham?`${metrics.hard_ham_correct??0} / ${metrics.holdout_hard_ham} correct · recall ${metrics.hard_ham_recall??"-"}%`:"N/A");
  const updated=new Date().toLocaleString(undefined,{hour12:false});
  aiLiveSetText("aiLiveCurrentUpdated",`Last updated: ${updated}`);
  aiLiveSetText("aiLiveMetricsUpdated",`Last updated: ${updated}`);
  const badge=document.getElementById("aiLiveBadge");
  if(badge){badge.classList.remove("stale");badge.textContent="LIVE · 10s";}
  const promote=document.getElementById("aiLivePromoteButton");
  if(promote) promote.disabled=candidate==="None";
}

async function refreshAiTrainerLiveStatus(){
  if(aiTrainerLiveRequestActive||!document.getElementById("quarantineIntelModal")?.classList.contains("open")) return;
  aiTrainerLiveRequestActive=true;
  try{
    const response=await apiFetch("/api/ai-trainer/status");
    const status=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(status.detail||"Live AI status unavailable");
    aiLiveApplyStatus(status);
  }catch(error){
    const badge=document.getElementById("aiLiveBadge");
    if(badge){badge.classList.add("stale");badge.textContent="LIVE FEED DEGRADED";}
    const detail=`Last refresh failed: ${error.message||"status unavailable"}`;
    const current=document.getElementById("aiLiveCurrentUpdated");
    const metrics=document.getElementById("aiLiveMetricsUpdated");
    if(current){current.textContent=detail;current.classList.add("qintel-live-error");}
    if(metrics){metrics.textContent=detail;metrics.classList.add("qintel-live-error");}
  }finally{
    aiTrainerLiveRequestActive=false;
  }
}

function startAiTrainerLiveFeed(){
  stopAiTrainerLiveFeed();
  refreshAiTrainerLiveStatus();
  aiTrainerLiveTimer=window.setInterval(refreshAiTrainerLiveStatus,AI_TRAINER_LIVE_INTERVAL_MS);
}

function stopAiTrainerLiveFeed(){
  if(aiTrainerLiveTimer){window.clearInterval(aiTrainerLiveTimer);aiTrainerLiveTimer=null;}
}

const AI_GT_CLASSES={HAM:["LEGITIMATE_BUSINESS","EXPECTED_TRANSACTIONAL","APPROVED_NEWSLETTER","INTERNAL_OR_TRUSTED","PERSONAL_OR_DIRECT","OTHER_HAM"],SPAM:["UCE_AUTHENTICATED","UCE_UNAUTHENTICATED","PHISHING","CREDENTIAL_PHISHING","SPEAR_PHISHING","WHALING","BEC","INVOICE_FRAUD","ADVANCE_FEE_INVESTMENT","INHERITANCE_419","LOTTERY_PRIZE","FAKE_JOB","CHARITY_FRAUD","TECH_SUPPORT","CALLBACK_PHISHING","FAKE_ECOMMERCE","SEO_DIRECTORY","BOTNET","BPH","SNOWSHOE","MALWARE","OTHER_SPAM"]};
let currentAiGtProposal={label:"",classification:""};
let currentAiGtSaved={};
function updateAiGtClasses(preferred=""){
  const label=document.getElementById("aiGtLabel"), cls=document.getElementById("aiGtClass");
  if(!label||!cls)return;
  const previous=preferred||cls.value||"";
  const values=AI_GT_CLASSES[label.value]||[];
  cls.innerHTML=values.map(v=>`<option value="${v}">${v.replaceAll("_"," ")}</option>`).join("");
  if(values.includes(previous))cls.value=previous;
  updateAiGtActionState();
}
function initAiGroundTruthProposal(label,classification,saved={}){
  currentAiGtProposal={label:String(label||"").toUpperCase(),classification:String(classification||"").toUpperCase()};
  currentAiGtSaved=saved||{};
  const savedLabel=String(currentAiGtSaved.label||"").toUpperCase();
  const savedClass=String(currentAiGtSaved.classification||"").toUpperCase();
  const labelEl=document.getElementById("aiGtLabel");
  const effectiveLabel=["HAM","SPAM"].includes(savedLabel)?savedLabel:currentAiGtProposal.label;
  const effectiveClass=savedLabel?savedClass:currentAiGtProposal.classification;
  if(labelEl&&["HAM","SPAM"].includes(effectiveLabel))labelEl.value=effectiveLabel;
  updateAiGtClasses(effectiveClass);
  const reason=document.getElementById("aiGtReason"),notes=document.getElementById("aiGtNotes");
  if(reason) reason.value=String(currentAiGtSaved.review_reason||"");
  if(notes) notes.value=String(currentAiGtSaved.admin_notes||"");
  const state=document.getElementById("aiGtSavedState");
  if(state){
    state.innerHTML=savedLabel?`<b>Saved Admin Ground Truth:</b> ${esc(savedLabel)} / ${esc(savedClass||"-")} · ${esc(currentAiGtSaved.reviewer||"-")} · ${esc(currentAiGtSaved.created_at||currentAiGtSaved.updated_at||"")}`:`<b>Saved Admin Ground Truth:</b> None yet. AI proposal is pre-filled for review.`;
  }
}
function updateAiGtActionState(){
  const label=document.getElementById("aiGtLabel")?.value||"";
  const cls=document.getElementById("aiGtClass")?.value||"";
  const same=Boolean(currentAiGtProposal.label)&&label===currentAiGtProposal.label&&cls===currentAiGtProposal.classification;
  const ack=document.getElementById("aiGtAckButton"), save=document.getElementById("aiGtSaveButton");
  if(ack){ack.disabled=!same;ack.textContent=`Acknowledge AI Proposal${same&&label?` (Accept as ${label})`:""}`;}
  if(save)save.disabled=same;
}
function resetAiGroundTruth(){
  // Reset unsaved edits to the persisted administrator state (or AI proposal if no saved state exists).
  initAiGroundTruthProposal(currentAiGtProposal.label,currentAiGtProposal.classification,currentAiGtSaved);
  updateAiGtActionState();
}
async function submitAiGroundTruth(mode="auto"){
  const label=document.getElementById("aiGtLabel")?.value||"";
  const classification=document.getElementById("aiGtClass")?.value||"";
  const review_reason=document.getElementById("aiGtReason")?.value||"";
  const admin_notes=document.getElementById("aiGtNotes")?.value||"";
  if(!currentQintelPdpId||!label)return;
  const same=Boolean(currentAiGtProposal.label)&&label===currentAiGtProposal.label&&classification===currentAiGtProposal.classification;
  if(mode==="ack"&&!same){alert("The current decision differs from the AI proposal. Use Save Changed Ground Truth.");return;}
  if(mode==="change"&&same){alert("No decision/classification change is present. Use Acknowledge AI Proposal.");return;}
  const action=same?"Acknowledge the AI proposal":"Save the changed administrator ground truth";
  if(!window.confirm(`${action}: ${label} / ${classification}? Only this explicit administrator action becomes AI ground truth.`))return;
  try{
    const response=await apiFetch("/api/ai-trainer/ground-truth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({pdp_id:currentQintelPdpId,label,classification,review_reason,admin_notes})});
    const data=await response.json().catch(()=>({})); if(!response.ok)throw new Error(data.detail||"Ground-truth save failed");
    let msg=data.admin_acknowledged_ai?`AI proposal acknowledged and stored as administrator ground truth: ${label} / ${classification}.`:`Administrator ground truth saved: ${label} / ${classification}.`;
    if(data.reversal?.reversed)msg+=` Previous ${data.reversal.previous_label} label is retained as SUPERSEDED audit history.`;
    if(data.conflict_investigation_id)msg+=` AI conflict reverse engineering stored as investigation #${data.conflict_investigation_id}.`;
    if(data.calibration_id)msg+=` Calibration record #${data.calibration_id} stored.`;
    // Use the row read back from MariaDB, not a browser-only reconstruction.
    currentAiGtSaved=data.admin_ground_truth||{label,classification,review_reason,admin_notes,reviewer:data.reviewer||"current admin",created_at:new Date().toLocaleString(undefined,{hour12:false})};
    const state=document.getElementById("aiGtSavedState");
    if(state)state.innerHTML=`<b>Saved Admin Ground Truth:</b> ${esc(currentAiGtSaved.label||label)} / ${esc(currentAiGtSaved.classification||classification||"-")} · persisted in MariaDB`;
    alert(msg); await refreshAiTrainerLiveStatus();
  }catch(error){alert(error.message||"Ground-truth save failed");}
}

async function aiBackfillLabels(){
  try{
    const response=await apiFetch("/api/ai-trainer/backfill",{method:"POST"});
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"Training provenance audit failed");
    alert(data.reason||"Legacy learning labels are preserved for audit and excluded from AI training.");
    await refreshAiTrainerLiveStatus();
  }catch(error){ alert(error.message||"Training provenance audit failed"); }
}

async function aiTrainCandidate(){
  if(!window.confirm("Train a new AI candidate from authoritative administrator Ground Truth only? Legacy/sa-learn labels remain audit-only. The active model and mail flow will not change.")) return;
  const body=document.getElementById("qintelBody");
  try{
    const response=await apiFetch("/api/ai-trainer/train",{method:"POST"});
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"AI candidate training failed");
    alert(`Candidate ${data.candidate?.version||"model"} trained. It is not active until explicitly promoted.`);
    await refreshAiTrainerLiveStatus();
  }catch(error){ alert(error.message||"AI candidate training failed"); }
}

async function aiPromoteCandidate(){
  if(!window.confirm("Promote the current candidate as the ACTIVE SHADOW model? This still cannot affect mail delivery.")) return;
  try{
    const response=await apiFetch("/api/ai-trainer/promote",{method:"POST"});
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"AI model promotion failed");
    alert(`Active shadow model: ${data.active_version||"updated"}`);
    await refreshAiTrainerLiveStatus();
  }catch(error){ alert(error.message||"AI model promotion failed"); }
}

function closeQuarantineIntelligence(){
  stopAiTrainerLiveFeed();
  document.getElementById("quarantineIntelModal")?.classList.remove("open");
}

document.getElementById("quarantineIntelModal")?.addEventListener("click",event=>{
  if(event.target?.id==="quarantineIntelModal") closeQuarantineIntelligence();
});

function qPage(direction){
  qp=Math.min(qtp,Math.max(1,qp+direction));
  loadQuarantine(qp);
}

document.getElementById("qSearch").oninput=()=>loadQuarantine(1);
document.getElementById("qSearchField").onchange=()=>loadQuarantine(1);
document.getElementById("qSearchOperator").onchange=()=>loadQuarantine(1);
document.getElementById("qDate").onchange=()=>loadQuarantine(1);


document.getElementById("qSelectAllVisible")?.addEventListener("change",event=>{
  const checked=Boolean(event.target.checked);
  qVisibleEligible.forEach(id=>{
    if(checked)qSelected.add(id); else qSelected.delete(id);
  });
  updateBulkSelectionUI();
});
document.getElementById("qBulkRelease")?.addEventListener("click",()=>quarantineBulkAction("release"));
document.getElementById("qBulkSpam")?.addEventListener("click",()=>quarantineBulkAction("spam"));



document.querySelectorAll(".qmetric-filter").forEach(card=>{
  card.addEventListener("click",()=>{
    quarantineCategory=card.dataset.qfilter||"all";
    document.querySelectorAll(".qmetric-filter").forEach(x=>{
      x.classList.toggle("active",x===card);
    });
    loadQuarantine(1);
  });
});


let ap=1,atp=1;
let AUDIT_PAGE_SIZE=50;

async function loadAudit(pageNumber=ap){
  ap=Math.max(1,pageNumber);

  const query=new URLSearchParams({
    q:document.getElementById("auditSearch").value,
    q_operator:document.getElementById("auditSearchOperator").value,
    action:document.getElementById("auditAction").value,
    date_from:document.getElementById("auditDateFrom").value,
    date_to:document.getElementById("auditDateTo").value,
    page:ap,
    page_size:AUDIT_PAGE_SIZE
  });

  const response=await apiFetch(
    "/api/quarantine/audit/records?"+query
  );
  const data=await response.json();

  if(!response.ok){
    document.getElementById("auditMessage").textContent=
      data.detail||"Unable to load audit.";
    return;
  }

  ap=data.page||1;
  atp=data.total_pages||1;
  updateAuditUx();
  uxSetRefresh("auditLastRefresh");

  document.getElementById("auditRows").innerHTML=
    (data.rows||[]).map(row=>{
      const actionLabels={
        RELEASE:"RELEASED",
        RELEASE_FAILED:"RELEASE FAILED",
        SPAM_FLG:"MARKED SPAM",
        SPAM_MARK_FAILED:"SPAM MARK FAILED",
        LOGIN_SUCCESS:"LOGIN SUCCESS",
        LOGIN_FAILED:"LOGIN FAILED",
        LOGOUT:"LOGOUT",
        AUTO_LOGOUT_INACTIVITY:"INACTIVITY TIMEOUT",
        ACL_USER_CREATE:"ACL USER CREATE",
        ACL_USER_UPDATE:"ACL USER UPDATE",
        ACL_USER_DELETE:"ACL USER DELETE",
        SPAMLIST_CREATE:"WHITELIST/BLACKLIST CREATE",
        SPAMLIST_UPDATE:"WHITELIST/BLACKLIST UPDATE",
        SPAMLIST_DELETE:"WHITELIST/BLACKLIST DELETE",
        SPAMLIST_BULK_DELETE:"WHITELIST/BLACKLIST BULK DELETE",
        SPAMLIST_IMPORT:"WHITELIST/BLACKLIST IMPORT",
        SPAMLIST_EXPORT:"WHITELIST/BLACKLIST EXPORT"
      };
      const label=actionLabels[row.action]||row.action;

      return `
        <tr>
          <td>${esc(row.timestamp)}</td>
          <td class="audit-action">${esc(label)}</td>
          <td>${esc(row.user||"-")}</td>
          <td class="audit-ip">${esc(row.ip||"-")}</td>
          <td>${esc(row.from||"-")}</td>
          <td>${esc(row.to||"-")}</td>
          <td>${esc(row.subject||"-")}</td>
          <td>${esc(row.score||"-")}</td>
          <td>${esc(row.pdp_id||"-")}</td>
          <td>${esc(row.detail||"-")}</td>
        </tr>
      `;
    }).join("")
    || '<tr><td class="ux-empty" colspan="10">No audit records match the current filters. <button type="button" onclick="clearAuditFilters()">Clear Filters</button></td></tr>';

  document.getElementById("auditMessage").textContent=
    `${data.total||0} audit records`;

  const auditPageText=`Page ${ap} of ${atp}`;
  document.getElementById("auditPg").textContent=auditPageText;
  document.getElementById("auditPgTop").textContent=auditPageText;
}

function auditPage(direction){
  ap=Math.min(atp,Math.max(1,ap+direction));
  loadAudit(ap);
}

document.getElementById("auditSearch").oninput=()=>loadAudit(1);
document.getElementById("auditSearchOperator").onchange=()=>loadAudit(1);
document.getElementById("auditDateFrom").onchange=()=>loadAudit(1);
document.getElementById("auditDateTo").onchange=()=>loadAudit(1);
document.getElementById("auditAction").onchange=()=>loadAudit(1);


let ACL_USERS=[];

function aclLevelBadge(level){
  const value=String(level||"none").toLowerCase();
  return `<span class="acl-level ${esc(value)}">${esc(value)}</span>`;
}

async function loadAclUsers(){
  if(!CURRENT_ACCESS.is_admin) return;
  const response=await apiFetch("/api/admin/users");
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    document.getElementById("aclMessage").textContent=data.detail||"Unable to load users.";
    return;
  }
  ACL_USERS=data.users||[];
  document.getElementById("aclMessage").textContent=`${ACL_USERS.length} dashboard user(s)`;
  document.getElementById("aclRows").innerHTML=ACL_USERS.map(user=>`
    <tr>
      <td><b>${esc(user.username)}</b></td>
      <td><span class="acl-status ${user.active?"active":"disabled"}">${user.active?"Active":"Disabled"}</span></td>
      <td>${user.is_admin?'<span class="acl-level admin">ADMINISTRATOR</span>':'User'}</td>
      <td>${aclLevelBadge(user.permissions?.delivery)}</td>
      <td>${aclLevelBadge(user.permissions?.summary)}</td>
      <td>${aclLevelBadge(user.permissions?.quarantine)}</td>
      <td>${aclLevelBadge(user.permissions?.spam_lists)}</td>
      <td>${aclLevelBadge(user.permissions?.mail_size)}</td>
      <td>${aclLevelBadge(user.permissions?.monitor)}</td>
      <td>${aclLevelBadge(user.permissions?.system)}</td>
      <td>${aclLevelBadge(user.permissions?.audit)}</td>
      <td>${aclLevelBadge(user.permissions?.mail_flow)}</td>
      <td>
        <div class="acl-actions">
          <button type="button" onclick='openAclEditor(${JSON.stringify(user.id)})'>Edit</button>
          <button type="button" ${user.username===CURRENT_ACCESS.username?"disabled":""}
            onclick='deleteAclUser(${JSON.stringify(user.id)})'>Delete</button>
        </div>
      </td>
    </tr>
  `).join("")||'<tr><td colspan="10">No users.</td></tr>';
}

function renderAclPermissionEditor(values={}){
  const container=document.getElementById("aclPermissionGrid");
  container.innerHTML=ACL_AREAS.map(([key,label])=>{
    const selected=String(values?.[key]||"none");
    return `
      <div class="acl-perm-row">
        <b>${esc(label)}</b>
        <select class="acl-perm-select" data-area="${esc(key)}">
          <option value="none" ${selected==="none"?"selected":""}>None</option>
          <option value="view" ${selected==="view"?"selected":""}>View</option>
          <option value="admin" ${selected==="admin"?"selected":""}>Admin</option>
        </select>
      </div>`;
  }).join("");
  syncAclAdminState();
}

function syncAclAdminState(){
  const admin=document.getElementById("aclIsAdmin").checked;
  document.querySelectorAll(".acl-perm-select").forEach(select=>{
    select.disabled=admin;
    if(admin) select.value="admin";
  });
}

function openAclEditor(userId=null){
  const user=userId==null?null:ACL_USERS.find(x=>Number(x.id)===Number(userId));
  document.getElementById("aclEditor").hidden=false;
  document.getElementById("aclEditorTitle").textContent=user?"Edit User":"Add User";
  document.getElementById("aclUserId").value=user?.id||"";
  document.getElementById("aclUsername").value=user?.username||"";
  document.getElementById("aclUsername").disabled=Boolean(user);
  document.getElementById("aclPassword").value="";
  document.getElementById("aclPassword").placeholder=user
    ?"Leave blank to keep current password"
    :"Minimum 10 characters";
  document.getElementById("aclActive").checked=user?Boolean(user.active):true;
  document.getElementById("aclIsAdmin").checked=user?Boolean(user.is_admin):false;
  document.getElementById("aclEditorMessage").textContent="";
  renderAclPermissionEditor(user?.permissions||{
    delivery:"view",summary:"view",quarantine:"view",
    spam_lists:"none",mail_size:"none",monitor:"view",system:"view",audit:"none",mail_flow:"view"
  });
}

function closeAclEditor(){
  document.getElementById("aclEditor").hidden=true;
}

document.getElementById("aclIsAdmin")?.addEventListener("change",syncAclAdminState);

async function saveAclUser(){
  const userId=document.getElementById("aclUserId").value;
  const username=document.getElementById("aclUsername").value.trim();
  const password=document.getElementById("aclPassword").value;
  const isAdmin=document.getElementById("aclIsAdmin").checked;
  const active=document.getElementById("aclActive").checked;
  const permissions={};
  document.querySelectorAll(".acl-perm-select").forEach(select=>{
    permissions[select.dataset.area]=select.value;
  });

  if(!userId && password.length<10){
    document.getElementById("aclEditorMessage").textContent="Password must be at least 10 characters.";
    return;
  }
  const payload={is_admin:isAdmin,active,permissions};
  if(!userId) payload.username=username;
  if(password) payload.password=password;

  const url=userId?`/api/admin/users/${encodeURIComponent(userId)}`:"/api/admin/users";
  const response=await apiFetch(url,{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(payload)
  });
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    document.getElementById("aclEditorMessage").textContent=data.detail||"Unable to save user.";
    return;
  }
  closeAclEditor();
  await loadAclUsers();
}

async function deleteAclUser(userId){
  const user=ACL_USERS.find(x=>Number(x.id)===Number(userId));
  if(!user) return;
  if(!window.confirm(`Delete dashboard user ${user.username}?`)) return;
  const response=await apiFetch(`/api/admin/users/${encodeURIComponent(userId)}`,{method:"DELETE"});
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    document.getElementById("aclMessage").textContent=data.detail||"Unable to delete user.";
    return;
  }
  await loadAclUsers();
}


let SL_PAGE=1,SL_TOTAL_PAGES=1,SL_ITEMS=[];
let SL_PAGE_SIZE=50;
let SL_SELECTED=new Set();
let SL_IMPORT_TEXT="";
let SL_IMPORT_PREVIEW=null;

function spamListKindLabel(preference){
  return String(preference||"").startsWith("blacklist_")?"Blacklist":"Whitelist";
}

function spamListScopeLabel(scope){
  return {global:"Global",domain:"Domain",user:"User"}[scope]||scope||"-";
}

async function loadSpamLists(pageNumber=SL_PAGE){
  SL_PAGE=Math.max(1,pageNumber);
  const query=new URLSearchParams({
    search:document.getElementById("slSearch").value,
    preference:document.getElementById("slPreference").value,
    scope:document.getElementById("slScope").value,
    page:SL_PAGE,
    page_size:SL_PAGE_SIZE
  });

  const response=await apiFetch("/api/spam-lists?"+query);
  const data=await response.json().catch(()=>({}));
  const message=document.getElementById("slMessage");

  if(!response.ok){
    message.textContent=data.detail||"Unable to load SpamAssassin preferences.";
    document.getElementById("slDbState").textContent="Unavailable";
    return;
  }

  SL_ITEMS=data.items||[];
  SL_PAGE=data.page||1;
  SL_TOTAL_PAGES=data.total_pages||1;
  updateSpamUx();
  uxSetRefresh("slLastRefresh");

  document.getElementById("slTotal").textContent=data.total||0;
  document.getElementById("slWhite").textContent=data.page_counts?.whitelist||0;
  document.getElementById("slBlack").textContent=data.page_counts?.blacklist||0;
  document.getElementById("slDbState").textContent=data.db_ready?"Connected":"Unavailable";

  const pageText=`Page ${SL_PAGE} of ${SL_TOTAL_PAGES}`;
  document.getElementById("slPg").textContent=pageText;
  document.getElementById("slPgTop").textContent=pageText;

  const canManage=canAccess("spam_lists","admin");
  SL_SELECTED=new Set([...SL_SELECTED].filter(id=>SL_ITEMS.some(item=>Number(item.prefid)===Number(id))));
  document.getElementById("slRows").innerHTML=SL_ITEMS.map(item=>`
    <tr>
      <td class="sl-select-cell"><input class="sl-row-check" type="checkbox" ${canManage?"":"disabled"} ${SL_SELECTED.has(Number(item.prefid))?"checked":""} onchange='toggleSpamListSelection(${JSON.stringify(item.prefid)},this.checked)'></td>
      <td>${esc(item.prefid)}</td>
      <td><span class="sl-kind ${item.kind}">${esc(spamListKindLabel(item.preference))}</span></td>
      <td><span class="sl-scope">${esc(spamListScopeLabel(item.scope))}</span></td>
      <td title="${esc(item.username)}">${esc(item.username)}</td>
      <td><code>${esc(item.preference)}</code></td>
      <td title="${esc(item.value)}">${esc(item.value)}</td>
      <td>
        <div class="sl-actions">
          <button type="button" ${canManage?"":"disabled"} onclick='openSpamListEditor(${JSON.stringify(item.prefid)})'>Edit</button>
          <button type="button" class="danger" ${canManage?"":"disabled"} onclick='deleteSpamListEntry(${JSON.stringify(item.prefid)})'>Delete</button>
        </div>
      </td>
    </tr>
  `).join("")||'<tr><td class="ux-empty" colspan="8">No whitelist / blacklist entries match the current filters. <button type="button" onclick="clearSpamListSearch()">Clear Filters</button></td></tr>';

  updateSpamListSelectionUi();
  message.textContent=`${data.total||0} matching SpamAssassin preference(s)`;
}

function spamListPage(direction){
  SL_PAGE=Math.min(SL_TOTAL_PAGES,Math.max(1,SL_PAGE+direction));
  loadSpamLists(SL_PAGE);
}

function updateSpamListSelectionUi(){
  const count=SL_SELECTED.size;
  const countEl=document.getElementById("slSelectedCount");
  const deleteButton=document.getElementById("slBulkDelete");
  const visible=document.getElementById("slSelectVisible");
  if(countEl) countEl.textContent=`${count} selected`;
  if(deleteButton) deleteButton.disabled=count===0 || !canAccess("spam_lists","admin");
  if(visible){
    const selectable=SL_ITEMS.map(item=>Number(item.prefid));
    const selectedVisible=selectable.filter(id=>SL_SELECTED.has(id)).length;
    visible.checked=selectable.length>0 && selectedVisible===selectable.length;
    visible.indeterminate=selectedVisible>0 && selectedVisible<selectable.length;
    visible.disabled=!canAccess("spam_lists","admin") || selectable.length===0;
  }
}

function toggleSpamListSelection(prefid,checked){
  const id=Number(prefid);
  if(checked) SL_SELECTED.add(id); else SL_SELECTED.delete(id);
  updateSpamListSelectionUi();
}

function toggleSpamListVisible(checked){
  if(!canAccess("spam_lists","admin")) return;
  SL_ITEMS.forEach(item=>{
    const id=Number(item.prefid);
    if(checked) SL_SELECTED.add(id); else SL_SELECTED.delete(id);
  });
  document.querySelectorAll(".sl-row-check").forEach(box=>{if(!box.disabled) box.checked=checked;});
  updateSpamListSelectionUi();
}

async function bulkDeleteSpamLists(){
  if(!canAccess("spam_lists","admin")) return;
  const ids=[...SL_SELECTED];
  if(!ids.length) return;
  if(ids.length>100){
    document.getElementById("slMessage").textContent="Maximum 100 entries per bulk delete.";
    return;
  }
  if(!window.confirm(`Delete ${ids.length} selected whitelist / blacklist entr${ids.length===1?"y":"ies"}?`)) return;

  const response=await apiFetch("/api/spam-lists/bulk/delete",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({prefids:ids})
  });
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    document.getElementById("slMessage").textContent=data.detail||"Bulk delete failed.";
    return;
  }
  SL_SELECTED.clear();
  document.getElementById("slMessage").textContent=`Deleted ${data.deleted||0} SpamAssassin preference(s).`;
  await loadSpamLists(SL_PAGE);
}

function clearSpamListSearch(){
  document.getElementById("slSearch").value="";
  document.getElementById("slPreference").value="all";
  document.getElementById("slScope").value="all";
  SL_SELECTED.clear();
  loadSpamLists(1);
}

function exportSpamLists(){
  const query=new URLSearchParams({
    search:document.getElementById("slSearch").value,
    preference:document.getElementById("slPreference").value,
    scope:document.getElementById("slScope").value
  });
  window.location.href="/api/spam-lists/export?"+query;
}

function updateSpamImportScope(){
  const scope=document.getElementById("slImportScope").value;
  const input=document.getElementById("slImportPrincipal");
  const label=document.getElementById("slImportPrincipalLabel");
  if(scope==="global"){
    label.childNodes[0].nodeValue="Global scope ";
    input.value="";
    input.placeholder="@GLOBAL";
    input.disabled=true;
  }else if(scope==="domain"){
    label.childNodes[0].nodeValue="Domain ";
    input.disabled=false;
    input.placeholder="example.com";
  }else{
    label.childNodes[0].nodeValue="User ";
    input.disabled=false;
    input.placeholder="user@example.com";
  }
  SL_IMPORT_PREVIEW=null;
  document.getElementById("slImportCommit").disabled=true;
}

function openSpamListImport(){
  if(!canAccess("spam_lists","admin")) return;
  document.getElementById("spamListImport").hidden=false;
  document.getElementById("slImportScope").value="global";
  document.getElementById("slImportPrincipal").value="";
  document.getElementById("slImportFile").value="";
  document.getElementById("slImportMessage").textContent="";
  document.getElementById("slImportPreview").hidden=true;
  document.getElementById("slImportCommit").disabled=true;
  SL_IMPORT_TEXT="";
  SL_IMPORT_PREVIEW=null;
  updateSpamImportScope();
}

function closeSpamListImport(){
  document.getElementById("spamListImport").hidden=true;
}

async function readSpamImportFile(){
  const file=document.getElementById("slImportFile").files?.[0];
  if(!file) throw new Error("Choose a .cf or .txt file first.");
  if(file.size>2*1024*1024) throw new Error("Import file exceeds the 2 MB limit.");
  SL_IMPORT_TEXT=await file.text();
  return SL_IMPORT_TEXT;
}

function spamImportRequestPayload(commit){
  const scope=document.getElementById("slImportScope").value;
  const principal=document.getElementById("slImportPrincipal").value.trim();
  if(scope!=="global" && !principal){
    throw new Error(scope==="domain"?"Domain is required.":"User is required.");
  }
  return {text:SL_IMPORT_TEXT,scope,principal,commit};
}

function renderSpamImportPreview(data){
  SL_IMPORT_PREVIEW=data;
  document.getElementById("slImportPreview").hidden=false;
  document.getElementById("slImportAdd").textContent=data.added||0;
  document.getElementById("slImportDup").textContent=data.duplicates||0;
  document.getElementById("slImportInvalid").textContent=data.invalid||0;
  document.getElementById("slImportSkipped").textContent=data.skipped||0;

  const rows=[];
  (data.preview_rows||[]).slice(0,300).forEach(row=>rows.push(`
    <div class="sl-import-row">
      <span>L${esc(row.line)}</span><code>${esc(row.preference)}</code>
      <span title="${esc(row.value)}">${esc(row.value)}</span><b class="${esc(row.status)}">${esc(row.status)}</b>
    </div>`));
  (data.invalid_rows||[]).slice(0,100).forEach(row=>rows.push(`
    <div class="sl-import-row">
      <span>L${esc(row.line)}</span><code>invalid</code>
      <span title="${esc(row.text)}">${esc(row.text)}</span><b class="invalid">${esc(row.reason)}</b>
    </div>`));
  document.getElementById("slImportRows").innerHTML=rows.join("")||'<div style="padding:14px;text-align:center;color:#94a3b8;font-size:10px">No importable entries found.</div>';
  document.getElementById("slImportCommit").disabled=Number(data.added||0)<=0;
}

async function previewSpamListImport(){
  const message=document.getElementById("slImportMessage");
  try{
    await readSpamImportFile();
    const payload=spamImportRequestPayload(false);
    message.textContent="Validating import...";
    const response=await apiFetch("/api/spam-lists/bulk/import",{
      method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)
    });
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"Import preview failed.");
    renderSpamImportPreview(data);
    message.textContent=`Preview complete: ${data.added||0} add, ${data.duplicates||0} duplicate, ${data.invalid||0} invalid.`;
  }catch(error){
    message.textContent=error.message||"Import preview failed.";
    document.getElementById("slImportCommit").disabled=true;
  }
}

async function commitSpamListImport(){
  if(!SL_IMPORT_PREVIEW || Number(SL_IMPORT_PREVIEW.added||0)<=0) return;
  if(!window.confirm(`Import ${SL_IMPORT_PREVIEW.added} new SpamAssassin preference(s)?`)) return;
  const message=document.getElementById("slImportMessage");
  try{
    const payload=spamImportRequestPayload(true);
    const response=await apiFetch("/api/spam-lists/bulk/import",{
      method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)
    });
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"Import failed.");
    message.textContent=`Import complete: ${data.added||0} added, ${data.duplicates||0} duplicate, ${data.invalid||0} invalid, ${data.skipped||0} skipped.`;
    renderSpamImportPreview(data);
    document.getElementById("slImportCommit").disabled=true;
    await loadSpamLists(1);
  }catch(error){
    message.textContent=error.message||"Import failed.";
  }
}

function updateSpamScopeForm(){
  const scope=document.getElementById("slEditScope").value;
  const input=document.getElementById("slEditPrincipal");
  const label=document.getElementById("slPrincipalLabel");

  if(scope==="global"){
    label.childNodes[0].nodeValue="Global scope ";
    input.value="";
    input.placeholder="@GLOBAL";
    input.disabled=true;
  }else if(scope==="domain"){
    label.childNodes[0].nodeValue="Domain ";
    input.disabled=false;
    input.placeholder="example.com";
  }else{
    label.childNodes[0].nodeValue="User ";
    input.disabled=false;
    input.placeholder="user@example.com";
  }
}

function openSpamListEditor(prefid=null){
  if(!canAccess("spam_lists","admin")) return;
  const item=SL_ITEMS.find(x=>Number(x.prefid)===Number(prefid));
  document.getElementById("spamListEditor").hidden=false;
  document.getElementById("slEditorTitle").textContent=item
    ?"Edit Whitelist / Blacklist Entry"
    :"Add Whitelist / Blacklist Entry";
  document.getElementById("slPrefId").value=item?.prefid||"";
  document.getElementById("slEditScope").value=item?.scope||"global";
  document.getElementById("slEditPrincipal").value=item?.principal||"";
  document.getElementById("slEditPreference").value=item?.preference||"whitelist_auth";
  document.getElementById("slEditValue").value=item?.value||"";
  document.getElementById("slEditorMessage").textContent="";
  updateSpamScopeForm();
}

function closeSpamListEditor(){
  document.getElementById("spamListEditor").hidden=true;
}

async function saveSpamListEntry(){
  const prefid=document.getElementById("slPrefId").value;
  const scope=document.getElementById("slEditScope").value;
  const principal=document.getElementById("slEditPrincipal").value.trim();
  const preference=document.getElementById("slEditPreference").value;
  const value=document.getElementById("slEditValue").value.trim();
  const message=document.getElementById("slEditorMessage");

  if(scope!=="global" && !principal){
    message.textContent=scope==="domain"?"Domain is required.":"User is required.";
    return;
  }
  if(!value){
    message.textContent="Value is required.";
    return;
  }

  const payload={scope,principal,preference,value};
  const url=prefid
    ?`/api/spam-lists/${encodeURIComponent(prefid)}`
    :"/api/spam-lists";

  const response=await apiFetch(url,{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(payload)
  });
  const data=await response.json().catch(()=>({}));

  if(!response.ok){
    message.textContent=data.detail||"Unable to save SpamAssassin preference.";
    return;
  }

  closeSpamListEditor();
  await loadSpamLists(prefid?SL_PAGE:1);
}

async function deleteSpamListEntry(prefid){
  if(!canAccess("spam_lists","admin")) return;
  const item=SL_ITEMS.find(x=>Number(x.prefid)===Number(prefid));
  if(!item) return;
  if(!window.confirm(`Delete ${item.preference} ${item.value}?`)) return;

  const response=await apiFetch(`/api/spam-lists/${encodeURIComponent(prefid)}`,{
    method:"DELETE"
  });
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    document.getElementById("slMessage").textContent=data.detail||"Unable to delete SpamAssassin preference.";
    return;
  }
  await loadSpamLists(SL_PAGE);
}

document.getElementById("slSearch")?.addEventListener("keydown",event=>{if(event.key==="Enter")loadSpamLists(1);});
document.getElementById("slPreference")?.addEventListener("change",()=>loadSpamLists(1));
document.getElementById("slScope")?.addEventListener("change",()=>loadSpamLists(1));
document.getElementById("slImportFile")?.addEventListener("change",()=>{SL_IMPORT_PREVIEW=null;document.getElementById("slImportPreview").hidden=true;document.getElementById("slImportCommit").disabled=true;document.getElementById("slImportMessage").textContent="";});


let MAIL_SIZE_COOLDOWN_TIMER=null;

function mailSizeRequiredLimit(value){
  const wanted=parseFloat(value);
  if(Number.isNaN(wanted) || wanted<=0) return 0;
  return Math.min(99,Math.ceil(wanted*1.34)+1);
}

function updateMailSizeCalculator(){
  const input=document.getElementById("mailSizeWanted");
  const result=document.getElementById("mailSizeRequired");
  if(!input || !result) return;
  result.textContent=mailSizeRequiredLimit(input.value);
}


function mailSizeProfileMarkup(profileKey,profile,data){
  const cooldown=Number(data?.cooldown_remaining||0);
  const disabled=cooldown>0?"disabled":"";
  const current=Number(profile?.mb||25);
  const active=Boolean(profile?.custom);
  const line=profile?.line ? `master.cf line ${profile.line}` : "Global default active";
  return `
    <div class="ms-limit ${active?"":"warning"}">
      <div class="ms-limit-current">
        <span class="ms-limit-label">${active?"Active custom limit":"Global default active"}</span>
        <div class="ms-current-value"><strong>${current}</strong><span>MB</span></div>
        <small>${esc(line)}</small>
      </div>
      <div class="ms-limit-edit">
        <label for="mailSize-${profileKey}">New Limit</label>
        <div class="ms-limit-form">
          <input id="mailSize-${profileKey}" type="number" min="1" max="99" inputmode="numeric" aria-label="New mail size limit in MB" value="${current}">
          <b>MB</b>
          <button ${disabled} onclick='mailSizeApply(${JSON.stringify(profileKey)})'>
            ${cooldown>0?"Wait":"Update"}
          </button>
        </div>
      </div>
    </div>`;
}

function renderMailSizeManager(data){
  document.getElementById("mailSizeOutlook").innerHTML=
    mailSizeProfileMarkup("outlook",data.profiles?.outlook||{},data);
  document.getElementById("mailSizeWebmail").innerHTML=
    mailSizeProfileMarkup("webmail",data.profiles?.webmail||{},data);

  document.getElementById("mailSizeBackups").innerHTML=
    (data.backups||[]).map(row=>`
      <div class="ms-backup-row">
        <div><b>${esc(row.display_time||row.file||"-")}</b><small>${esc(row.file||"")}</small></div>
        <button class="ms-revert" onclick='mailSizeRevert(${JSON.stringify(row.file||"")})'>Revert</button>
      </div>`).join("")
    || '<div class="ms-empty">No backups found.</div>';

  document.getElementById("mailSizeAudit").innerHTML=
    (data.audit||[]).map(line=>`<div class="ms-audit-item">${esc(line)}</div>`).join("")
    || '<div class="ms-empty">No Mail Size audit records.</div>';

  startMailSizeCooldown(Number(data.cooldown_remaining||0));
}

function startMailSizeCooldown(seconds){
  if(MAIL_SIZE_COOLDOWN_TIMER){
    clearInterval(MAIL_SIZE_COOLDOWN_TIMER);
    MAIL_SIZE_COOLDOWN_TIMER=null;
  }
  const el=document.getElementById("mailSizeCooldown");
  if(!el) return;
  let remaining=Math.max(0,Math.floor(seconds||0));
  if(remaining<=0){
    el.hidden=true;
    return;
  }
  el.hidden=false;
  const paint=()=>{
    el.textContent=`Next configuration update available in ${remaining}s`;
    document.querySelectorAll(".ms-limit-form button").forEach(button=>{
      button.disabled=remaining>0;
      button.textContent=remaining>0?"Wait":"Update";
    });
  };
  paint();
  MAIL_SIZE_COOLDOWN_TIMER=setInterval(()=>{
    remaining=Math.max(0,remaining-1);
    paint();
    if(remaining<=0){
      clearInterval(MAIL_SIZE_COOLDOWN_TIMER);
      MAIL_SIZE_COOLDOWN_TIMER=null;
      el.hidden=true;
    }
  },1000);
}

async function loadMailSizeManager(){
  const message=document.getElementById("mailSizeMessage");
  if(message) message.textContent="Loading Mail Size configuration...";
  try{
    const response=await apiFetch("/api/mail-size/status");
    const data=await response.json().catch(()=>({}));
    if(!response.ok) throw new Error(data.detail||"Unable to load Mail Size configuration");
    renderMailSizeManager(data);
    if(message) message.textContent="";
  }catch(error){
    if(message) message.textContent=error.message||"Unable to load Mail Size configuration";
  }
}

async function mailSizeApply(profile){
  const input=document.getElementById(`mailSize-${profile}`);
  if(!input) return;
  const mb=Number(input.value);
  if(!Number.isInteger(mb) || mb<1 || mb>99){
    document.getElementById("mailSizeMessage").textContent="Mail Size must be between 1 and 99 MB.";
    return;
  }

  const message=document.getElementById("mailSizeMessage");
  message.textContent=`Applying ${mb} MB limit...`;
  const response=await apiFetch("/api/mail-size/limit",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({profile,mb})
  });
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    message.textContent=data.detail||"Mail Size update failed";
    return;
  }
  message.textContent=data.message||"Mail Size updated.";
  await loadMailSizeManager();
}

async function mailSizeRevert(backupFile){
  if(!backupFile) return;
  if(!window.confirm(`Restore Mail Size backup ${backupFile}?`)) return;

  const message=document.getElementById("mailSizeMessage");
  message.textContent="Restoring backup...";
  const response=await apiFetch("/api/mail-size/revert",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({backup_file:backupFile})
  });
  const data=await response.json().catch(()=>({}));
  if(!response.ok){
    message.textContent=data.detail||"Backup restore failed";
    return;
  }
  message.textContent=data.message||"Backup restored.";
  await loadMailSizeManager();
}

document.getElementById("mailSizeWanted")?.addEventListener("input",updateMailSizeCalculator);
updateMailSizeCalculator();




const SIDEBAR_PIN_KEY="postfix-dashboard-sidebar-pinned";

function applySidebarState(){
  hideSidebarTooltip?.();
  const isMobile=window.matchMedia("(max-width:820px)").matches;
  if(isMobile){
    document.body.classList.remove("sidebar-collapsed");
    return;
  }

  const pinned=localStorage.getItem(SIDEBAR_PIN_KEY)!=="false";
  document.body.classList.toggle("sidebar-collapsed",!pinned);

  const pin=document.getElementById("sidebarPin");
  if(pin){
    pin.textContent=pinned?"📌":"📍";
    pin.title=pinned?"Unpin sidebar":"Pin sidebar";
  }
}

function toggleSidebarPin(){
  const currentlyPinned=localStorage.getItem(SIDEBAR_PIN_KEY)!=="false";
  localStorage.setItem(SIDEBAR_PIN_KEY,String(!currentlyPinned));
  applySidebarState();
}

function openMobileSidebar(){
  document.body.classList.add("sidebar-mobile-open");
}

function closeMobileSidebar(){
  document.body.classList.remove("sidebar-mobile-open");
}

document.getElementById("sidebarPin")?.addEventListener("click",toggleSidebarPin);
document.getElementById("mobileMenuBtn")?.addEventListener("click",openMobileSidebar);
document.getElementById("sidebarBackdrop")?.addEventListener("click",closeMobileSidebar);

window.addEventListener("resize",()=>{
  applySidebarState();
  if(!window.matchMedia("(max-width:820px)").matches){
    closeMobileSidebar();
  }
});



const sidebarTooltipPortal=document.getElementById("sidebarTooltipPortal");
function hideSidebarTooltip(){
  if(!sidebarTooltipPortal)return;
  sidebarTooltipPortal.classList.remove("show");
  sidebarTooltipPortal.setAttribute("aria-hidden","true");
}
function showSidebarTooltip(button){
  if(!sidebarTooltipPortal || !document.body.classList.contains("sidebar-collapsed") || window.matchMedia("(max-width:820px)").matches)return;
  const label=button?.dataset?.tooltip||button?.querySelector("span:last-child")?.textContent||"";
  if(!label)return;
  const rect=button.getBoundingClientRect();
  sidebarTooltipPortal.textContent=label;
  sidebarTooltipPortal.style.left=`${Math.round(rect.right+12)}px`;
  sidebarTooltipPortal.style.top=`${Math.round(rect.top+rect.height/2)}px`;
  sidebarTooltipPortal.classList.add("show");
  sidebarTooltipPortal.setAttribute("aria-hidden","false");
}
document.querySelectorAll(".side-nav .tabbtn").forEach(btn=>{
  btn.addEventListener("mouseenter",()=>showSidebarTooltip(btn));
  btn.addEventListener("mouseleave",hideSidebarTooltip);
  btn.addEventListener("focus",()=>showSidebarTooltip(btn));
  btn.addEventListener("blur",hideSidebarTooltip);
  btn.addEventListener("click",hideSidebarTooltip);
});

applySidebarState();

function updateSideClock(){
  const el=document.getElementById("sideClock");
  if(!el) return;
  const now=new Date();
  el.textContent=now.toLocaleString();
}
updateSideClock();
setInterval(updateSideClock,1000);

function openFlowTabTarget(tabId,status=""){
  const button=document.querySelector(`.tabbtn[data-tab="${tabId}"]`);
  if(!button || button.hidden) return;
  activateTab(button);
  if(tabId==="deliveryTab" && status){
    const filter=document.getElementById("filter");
    if(filter){filter.value=status;p=1;load();}
  }
}

function bindMailFlowSvgNavigation(){
  const svg=document.getElementById("mailFlowSvg");
  if(!svg || svg.dataset.navBound==="1") return;
  svg.dataset.navBound="1";
  svg.querySelectorAll(".svg-click[data-flow-target]").forEach(node=>{
    const navigate=()=>openFlowTabTarget(node.dataset.flowTarget,node.dataset.flowStatus||"");
    node.addEventListener("click",event=>{ event.stopPropagation(); navigate(); });
    node.addEventListener("keydown",event=>{
      if(event.key==="Enter" || event.key===" "){
        event.preventDefault();
        navigate();
      }
    });
  });
}
function dynamicFlowRecipient(row){
  const list=row?.recipients||[];
  return list.length?list.map(x=>x.recipient||"-").join(", "):"-";
}
async function loadDynamicMailFlow(){
  bindMailFlowSvgNavigation();
  const message=document.getElementById("flowMessage");
  const refreshButton=document.getElementById("mailFlowRefreshBtn");
  if(!message)return;
  const label=refreshButton?.textContent||"Refresh";
  if(refreshButton){refreshButton.disabled=true;refreshButton.textContent="Refreshing…";refreshButton.setAttribute("aria-busy","true");}
  try{
    const nonce=Date.now();
    const [sr,qr,sumr]=await Promise.all([
      apiFetch(`/api/statistics?_=${nonce}`),
      apiFetch(`/api/quarantine?page=1&page_size=10&_=${nonce}`),
      apiFetch(`/api/summary?_=${nonce}`)
    ]);
    const stats=await sr.json().catch(()=>({}));
    const quarantine=await qr.json().catch(()=>({}));
    const summary=await sumr.json().catch(()=>({}));
    if(!sr.ok)throw new Error(stats.detail||"Unable to load mail statistics");
    if(!qr.ok)throw new Error(quarantine.detail||"Unable to load quarantine statistics");
    if(!sumr.ok)throw new Error(summary.detail||"Unable to load mail summary");
    const delivered=Number(stats.delivered||0), deferred=Number(stats.deferred||0), bounced=Number(stats.bounced||0);
    const blocked=Number(stats.blocked||0), rejected=Number(stats.rejected||0), total=Number(stats.total||0), blockedAll=blocked+rejected;
    const qTotal=Number(quarantine.total_items??quarantine.total??stats.spam??stats.quarantined??0);
    const counts=quarantine.counts||quarantine.category_counts||{};
    const qSpam=Number(counts.Spam??counts.spam??0);
    const qVirus=Number(counts.Virus??counts.virus??0)+Number(counts.Banned??counts.banned??0);
    const sent=Number(summary.emails_sent??summary.home_to_external??0), received=Number(summary.emails_received??summary.external_to_home??0);
    const outbound=Number(summary.home_to_external||0);
    const set=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=Number(value||0).toLocaleString();};
    set("svgInboundPassed",Math.max(0,total-blockedAll)); set("svgBlocked",blockedAll); set("svgInboundClean",delivered); set("svgInboundHeld",qTotal);
    set("svgInboundDelivered",delivered); set("svgDeferred",deferred); set("svgOutboundClean",outbound); set("svgOutboundHeld",qTotal);
    set("svgQuarantineTotal",qTotal); set("svgQuarantineSpam",qSpam); set("svgQuarantineVirus",qVirus); set("svgDelivered",delivered);
    set("svgDeferredOps",deferred); set("svgBounced",bounced); set("svgBlockedOps",blockedAll); set("svgQuarantineOps",qTotal); set("svgQueue",deferred);
    set("svgRbl",blockedAll); set("svgTotal",total); set("svgModuleQuarantine",qTotal); set("svgModuleBlocked",blockedAll);
    const es=document.getElementById("svgEmailsSent"); if(es)es.textContent=`Sent ${sent.toLocaleString()}`;
    const er=document.getElementById("svgEmailsReceived"); if(er)er.textContent=`Recv ${received.toLocaleString()}`;
    const mq=document.getElementById("svgModuleQuarantine"); if(mq)mq.textContent=`${qTotal.toLocaleString()} items`;
    const mb=document.getElementById("svgModuleBlocked"); if(mb)mb.textContent=`${blockedAll.toLocaleString()} blocked`;
    const now=new Date().toLocaleTimeString();
    const h=document.getElementById("flowLastUpdated"); if(h)h.textContent=`Last Updated: ${now}`;
    const u=document.getElementById("svgFlowUpdated"); if(u)u.textContent=`Updated: ${now}`;
    message.textContent="";
  }catch(error){message.textContent=error.message||"Unable to load Mail Flow";}
  finally{if(refreshButton){refreshButton.disabled=false;refreshButton.textContent=label;refreshButton.removeAttribute("aria-busy");}}
}

function toggleMailFlowFullscreen(){
  const target=document.getElementById("approvedMailFlowFrame")||document.getElementById("mailFlowSvg");
  if(!target)return;
  if(document.fullscreenElement){const result=document.exitFullscreen?.();if(result&&typeof result.catch==="function")result.catch(()=>{});return;}
  if(typeof target.requestFullscreen!=="function"){const message=document.getElementById("flowMessage");if(message)message.textContent="Full screen is not supported by this browser.";return;}
  const result=target.requestFullscreen();
  if(result&&typeof result.catch==="function")result.catch(error=>{const message=document.getElementById("flowMessage");if(message)message.textContent=`Unable to enter full screen: ${error.message||error}`;});
}
function syncMailFlowFullscreenButton(){const button=document.getElementById("mailFlowFullscreenBtn");if(button)button.textContent=document.fullscreenElement?"Exit Full Screen":"Full Screen";}


function formatBytes(n){n=Number(n||0);if(!n)return "0 B";const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return `${n.toFixed(i?1:0)} ${u[i]}`;}




function openHelpVisualization(tabId){
  if(tabId==="flowTab" && !canAccess("mail_flow","view")) return;
  const pane=document.getElementById(tabId);
  if(!pane) return;
  closeMobileSidebar();
  document.querySelectorAll(".tabpane").forEach(x=>x.classList.remove("active"));
  pane.classList.add("active");
  document.querySelectorAll(".tabbtn").forEach(x=>x.classList.remove("active"));
  document.querySelector('.tabbtn[data-tab="helpTab"]')?.classList.add("active");
  if(tabId==="flowTab") loadDynamicMailFlow();
  if(tabId==="aiTrainerFlowTab" || tabId==="aiIntelligenceTab") ensureAIArchitectureLive();
  else stopAIArchitectureLive();
}

function returnToHelp(){
  stopAIArchitectureLive();
  const button=document.querySelector('.tabbtn[data-tab="helpTab"]');
  if(button) activateTab(button);
}

function activateTab(button){
  if(!button || button.hidden) return;
  stopAIArchitectureLive();
  closeMobileSidebar();
  document.querySelectorAll(".tabbtn").forEach(x=>x.classList.remove("active"));
  document.querySelectorAll(".tabpane").forEach(x=>x.classList.remove("active"));
  button.classList.add("active");
  document.getElementById(button.dataset.tab)?.classList.add("active");

  if(button.dataset.tab==="flowTab") loadDynamicMailFlow();
  if(button.dataset.tab==="deliveryTab") load();
  if(button.dataset.tab==="summaryTab") loadSummary();
  if(button.dataset.tab==="quarantineTab") loadQuarantine(1);
  if(button.dataset.tab==="spamListsTab") loadSpamLists(1);
  if(button.dataset.tab==="mailSizeTab") loadMailSizeManager();
  if(button.dataset.tab==="monitorTab") loadMonitor();
  if(button.dataset.tab==="systemTab") loadHealth();
  if(button.dataset.tab==="auditTab") loadAudit(1);
  if(button.dataset.tab==="aclTab") loadAclUsers();
}

document.querySelectorAll(".tabbtn").forEach(button=>{
  button.addEventListener("click",()=>activateTab(button));
});

function initMailFlowControls(){
  const refresh=document.getElementById("mailFlowRefreshBtn");
  const fullscreen=document.getElementById("mailFlowFullscreenBtn");
  if(refresh && refresh.dataset.bound!=="1"){refresh.dataset.bound="1";refresh.addEventListener("click",()=>loadDynamicMailFlow());}
  if(fullscreen && fullscreen.dataset.bound!=="1"){fullscreen.dataset.bound="1";fullscreen.addEventListener("click",()=>toggleMailFlowFullscreen());}
  if(document.documentElement.dataset.mailFlowFullscreenBound!=="1"){
    document.documentElement.dataset.mailFlowFullscreenBound="1";
    document.addEventListener("fullscreenchange",syncMailFlowFullscreenButton);
  }
  syncMailFlowFullscreenButton();
}


function initUxPack(){
  restoreUxFilters();
  const changeMap={deliveryPageSize:()=>{DELIVERY_PAGE_SIZE=Number(deliveryPageSize.value);p=1;saveUxFilters();load();},qPageSize:()=>{QUARANTINE_PAGE_SIZE=Number(qPageSize.value);qp=1;saveUxFilters();loadQuarantine(1);},slPageSize:()=>{SL_PAGE_SIZE=Number(slPageSize.value);SL_PAGE=1;saveUxFilters();loadSpamLists(1);},auditPageSize:()=>{AUDIT_PAGE_SIZE=Number(auditPageSize.value);ap=1;saveUxFilters();loadAudit(1);}};
  Object.entries(changeMap).forEach(([id,fn])=>document.getElementById(id)?.addEventListener("change",fn));
  ["searchField","searchOperator","dateFrom","dateTo","filter"].forEach(id=>document.getElementById(id)?.addEventListener("change",()=>{p=1;updateDeliveryUx();}));
  ["qSearchField","qSearchOperator","qDate"].forEach(id=>document.getElementById(id)?.addEventListener("change",()=>{qp=1;updateQuarantineUx();}));
  ["slPreference","slScope"].forEach(id=>document.getElementById(id)?.addEventListener("change",()=>{SL_PAGE=1;updateSpamUx();loadSpamLists(1);}));
  ["auditSearchOperator","auditDateFrom","auditDateTo","auditAction"].forEach(id=>document.getElementById(id)?.addEventListener("change",()=>{ap=1;updateAuditUx();}));
  document.getElementById("search")?.addEventListener("keydown",e=>{if(e.key==="Enter"){p=1;load();}});
  document.getElementById("qSearch")?.addEventListener("keydown",e=>{if(e.key==="Enter")loadQuarantine(1);});
  document.getElementById("auditSearch")?.addEventListener("keydown",e=>{if(e.key==="Enter")loadAudit(1);});
  document.addEventListener("keydown",e=>{if(e.key==="Escape"){closeFlow();closeBounceDetail();}});
  updateDeliveryUx();updateQuarantineUx();updateSpamUx();updateAuditUx();
}

async function bootstrapDashboard(){
  await loadCurrentAccess();
  initUxPack();
initMailFlowControls();

  document.querySelectorAll(".tabbtn").forEach(x=>x.classList.remove("active"));
  document.querySelectorAll(".tabpane").forEach(x=>x.classList.remove("active"));

  const preferred=[
    "deliveryTab","summaryTab","monitorTab","quarantineTab","emailAnalysisTab","spamListsTab","mailSizeTab",
    "systemTab","auditTab","aclTab","helpTab"
  ];
  const first=preferred
    .map(tab=>document.querySelector(`.tabbtn[data-tab="${tab}"]`))
    .find(button=>button && !button.hidden);
  activateTab(first);

  let dashboardRefreshTick=0;
  setInterval(()=>{
    dashboardRefreshTick++;
    const active=document.querySelector(".tabbtn.active")?.dataset.tab;
    if(active==="flowTab") loadDynamicMailFlow();
    if(active==="deliveryTab" && canAccess("delivery","view")) load();
    if(active==="summaryTab" && canAccess("summary","view") && dashboardRefreshTick%2===0) loadSummary();
  },15000);
}

bootstrapDashboard().catch(()=>{
  window.location="/login";
});
</script>
</main>
</body>
</html>"""


LOGIN_HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Postfix Delivery Login</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f7fb;font-family:Inter,system-ui,sans-serif;color:#0f172a}
.login{width:min(420px,calc(100% - 32px));background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:28px;box-shadow:0 16px 42px rgba(15,23,42,.12)}
h2{margin:0 0 6px}.sub{color:#64748b;margin-bottom:20px}label{display:block;margin:12px 0 6px;font-weight:700}input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #cbd5e1;border-radius:9px;font:inherit}button{width:100%;margin-top:18px;padding:11px;border:0;border-radius:9px;background:#0f172a;color:#fff;font-weight:800;cursor:pointer}.err{min-height:20px;color:#b91c1c;margin-top:12px}




.awb-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0}
.awb-import-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:14px 0}
.awb-card{border:1px solid #dbe3ee;border-radius:12px;padding:16px;background:#fff;box-shadow:0 4px 14px rgba(15,23,42,.05)}
.awb-card h3{margin:0 0 6px;color:#0f2f52}.awb-card p{font-size:12px;color:#64748b;line-height:1.5}
.awb-card input[type=file]{width:100%;margin:8px 0}.awb-actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.awb-preview{font-size:12px;line-height:1.5;padding:10px;border-radius:8px;background:#f8fafc;border:1px solid #e2e8f0;min-height:38px}
.awb-single{display:flex;gap:10px;align-items:end;flex-wrap:wrap;margin:12px 0;padding:12px;border:1px solid #e2e8f0;border-radius:10px;background:#f8fafc}.awb-single label{display:grid;gap:5px;font-size:11px;font-weight:800;color:#475569}.awb-single input{min-width:320px}
.awb-controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.awb-controls input{min-width:280px}
.awb-policy-W{color:#166534;font-weight:850}.awb-policy-B{color:#991b1b;font-weight:850}
@media(max-width:900px){.awb-kpis{grid-template-columns:1fr 1fr}.awb-import-grid{grid-template-columns:1fr}.awb-single input,.awb-controls input{min-width:0;width:100%}}

/* R1.1.17 Monitor DB reports + sidebar scroll correction */
.sidebar{overflow:hidden!important}
.side-nav{flex:1 1 auto!important;min-height:0!important;overflow-y:auto!important;overflow-x:hidden!important;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:rgba(191,219,254,.45) transparent}
.side-nav::-webkit-scrollbar{width:7px}.side-nav::-webkit-scrollbar-thumb{background:rgba(191,219,254,.38);border-radius:999px}.side-nav::-webkit-scrollbar-track{background:transparent}
body.sidebar-collapsed .side-nav{overflow-y:auto!important;overflow-x:hidden!important}
.monitor-protocol-tabs{display:flex;gap:8px;margin:0 0 12px}.monitor-protocol-tabs button{background:#fff;border:1px solid #cbd5e1;color:#334155}.monitor-protocol-tabs button.active{background:#2563eb;border-color:#2563eb;color:#fff}
.monitor-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.monitor-panel-head .monitor-cards{margin:0;min-width:240px;grid-template-columns:repeat(2,minmax(100px,1fr))}
.monitor-user-link{border:0;background:transparent;padding:0;color:#1d4ed8;font-weight:800;text-decoration:underline;cursor:pointer}.monitor-user-link:hover{color:#6d28d9}.good-num{color:#15803d;font-weight:800}.bad-num{color:#b91c1c;font-weight:800}.monitor-geo small{display:block;color:#64748b;margin-top:2px}.monitor-detail-panel{width:min(1180px,96vw)!important}.monitor-detail-grid{display:grid;grid-template-columns:.85fr 1.15fr;gap:16px;padding-top:6px}.monitor-detail-grid h3{margin:0 0 8px}.monitor-detail-grid .monitor-table-wrap{max-height:58vh}
@media(max-width:1000px){.monitor-detail-grid{grid-template-columns:1fr}.monitor-panel-head{flex-direction:column}.monitor-panel-head .monitor-cards{width:100%}}


.ai-graph-shell{border:1px solid #dbe3ee;border-radius:14px;background:linear-gradient(180deg,#f8fbff 0,#eef4fa 100%);padding:16px;overflow:auto}.ai-flow-grid{display:grid;grid-template-columns:repeat(7,minmax(145px,1fr));gap:28px;align-items:stretch;min-width:1180px}.ai-flow-step{position:relative;border:1px solid #cbd5e1;border-radius:13px;padding:14px 12px;background:#fff;box-shadow:0 5px 15px rgba(15,23,42,.06);min-height:112px}.ai-flow-step:not(:last-child)::after{content:"→";position:absolute;right:-23px;top:42%;font-size:24px;font-weight:900;color:#4f46e5}.ai-flow-step b,.ai-flow-step span,.ai-flow-step small{display:block}.ai-flow-step span{margin-top:7px;color:#475569;font-size:12px;line-height:1.4}.ai-flow-step small{margin-top:9px;color:#0f766e;font-weight:800}.ai-flow-step.live{border-color:#86efac;box-shadow:0 0 0 2px rgba(34,197,94,.08)}.ai-flow-step.waiting{border-color:#fde68a}.ai-flow-step.none{border-color:#cbd5e1}.ai-stage-no{display:inline-flex!important;align-items:center;justify-content:center;width:23px;height:23px;border-radius:50%;background:#1d4ed8;color:#fff;font-size:11px;margin-bottom:7px}.ai-metric-strip{display:grid;grid-template-columns:repeat(6,minmax(115px,1fr));gap:9px;margin-top:13px}.ai-live-chip{border:1px solid #dbe3ee;background:#fff;border-radius:10px;padding:9px 10px;min-width:0}.ai-live-chip span{display:block;font-size:10px;color:#64748b;text-transform:uppercase;font-weight:800;letter-spacing:.03em}.ai-live-chip b{display:block;margin-top:4px;font-size:15px;color:#0f172a;overflow-wrap:anywhere}.intel-graph{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:18px;position:relative}.intel-engine{position:relative;background:#fff;border:1px solid #cbd5e1;border-radius:14px;padding:16px;box-shadow:0 5px 16px rgba(15,23,42,.06)}.intel-engine h3{margin:0 0 10px}.intel-feature-list{display:grid;gap:7px}.intel-feature{display:flex;gap:8px;align-items:center;border-radius:8px;background:#f8fafc;padding:7px 9px;font-size:12px;color:#334155}.intel-feature::before{content:"◆";color:#4f46e5;font-size:9px}.intel-merge{display:flex;justify-content:center;align-items:center;margin:14px 0 4px}.intel-merge span{border:1px solid #a5b4fc;background:#eef2ff;color:#3730a3;border-radius:999px;padding:8px 16px;font-weight:900}.intel-verdict{max-width:580px;margin:0 auto;display:grid;grid-template-columns:1fr;gap:8px;text-align:center}.intel-shadow-node{border:2px solid #6366f1;background:#fff;border-radius:14px;padding:13px;font-weight:900}.intel-noaction{border:1px solid #fecaca;background:#fff7f7;color:#991b1b;border-radius:12px;padding:10px;font-weight:800}.shadow-boundary{margin-top:15px;border:2px dashed #ef4444;border-radius:13px;padding:12px 14px;background:#fff}.live-state-grid{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:9px}.live-state-grid .ai-live-chip{background:#fbfdff}.summary-count-link{min-width:42px;padding:3px 8px;border:1px solid #bfdbfe;border-radius:7px;background:#eff6ff;color:#1d4ed8;font-weight:800;cursor:pointer}.summary-count-link:hover{background:#dbeafe}.qintel-live-panel .qintel-kv{grid-template-columns:135px minmax(160px,1fr)}.qintel-live-panel .qintel-kv b{word-break:normal;overflow-wrap:anywhere}@media(max-width:900px){.intel-graph{grid-template-columns:1fr}.ai-metric-strip,.live-state-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style></head><body><form class="login" id="loginForm"><h2>Postfix Delivery Dashboard</h2><div class="sub"></div><label>Username</label><input id="username" autocomplete="username" required><label>Password</label><input id="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button><div id="err" class="err"></div></form><script>
document.getElementById("loginForm").addEventListener("submit",async e=>{e.preventDefault();const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:document.getElementById("username").value,password:document.getElementById("password").value})});const data=await r.json().catch(()=>({}));if(!r.ok){document.getElementById("err").textContent=data.detail||"Login failed";return;}window.location="/";});
</script></body></html>"""


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    if session_store.get(token):
        return RedirectResponse("/", status_code=303)
    return LOGIN_HTML


@app.post("/api/login")
async def login(request: Request):
    remote_addr = _client_ip(request)
    limited, retry_after = _login_rate_status(remote_addr)
    if limited:
        return JSONResponse(
            {"detail": "Too many failed login attempts. Try again later."},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid login request")

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    user_record = authenticate_dashboard_user(username, password)
    if not user_record:
        _record_login_failure(remote_addr)
        try:
            quarantine_write_audit("LOGIN_FAILED", "", remote_addr, username)
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Invalid credentials")

    username = user_record["username"]
    _clear_login_failures(remote_addr)
    token = session_store.create(username)
    try:
        quarantine_write_audit("LOGIN_SUCCESS", "", remote_addr, username)
    except Exception:
        pass

    response = JSONResponse({
        "ok": True,
        "timeout_minutes": SESSION_IDLE_TIMEOUT_MINUTES,
        "absolute_timeout_hours": SESSION_ABSOLUTE_TIMEOUT_HOURS,
    })
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        secure=SESSION_COOKIE_SECURE,
        max_age=SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        path="/",
    )
    return response


@app.post("/api/session/touch")
def session_touch(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    session = session_store.touch(token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    session = session_store.destroy(token)
    remote_addr = request.client.host if request.client else "unknown"
    if session:
        try:
            quarantine_write_audit("LOGOUT", "", remote_addr, session.username)
        except Exception:
            pass
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@app.post("/api/session/inactivity-timeout")
def session_inactivity_timeout(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    session = session_store.destroy(token)
    remote_addr = request.client.host if request.client else "unknown"
    if session:
        try:
            quarantine_write_audit("AUTO_LOGOUT_INACTIVITY", "", remote_addr, session.username)
        except Exception:
            pass
    response = JSONResponse({"ok": True, "reason": "inactivity", "timeout_minutes": SESSION_IDLE_TIMEOUT_MINUTES})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    session = session_store.get(token)
    if not session or not dashboard_user_access(session.username):
        if session:
            session_store.destroy(token)
        return RedirectResponse("/login", status_code=303)
    return (
        HTML
        .replace("__SESSION_IDLE_TIMEOUT_MS__", str(SESSION_IDLE_TIMEOUT_SECONDS * 1000))
            )
