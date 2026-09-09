import hashlib
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from .geoip_intelligence import enrich_ip

DOVECOT_MAIL_LOG = Path(os.getenv("DOVECOT_MAIL_LOG", "/host-dovecot/mail.log"))
ROUNDCUBE_LOGIN_LOG = Path(os.getenv("ROUNDCUBE_LOGIN_LOG", "/host-roundcube/userlogins.log"))
MAX_TAIL_BYTES = max(65536, int(os.getenv("MONITOR_LOG_TAIL_BYTES", "2097152")))
MAX_READ_BYTES = max(65536, int(os.getenv("MONITOR_INGEST_BATCH_BYTES", "1048576")))
MAX_SCAN_LINES = max(500, int(os.getenv("MONITOR_LOG_MAX_LINES", "10000")))
SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
DOVECOT_USER = re.compile(r"user=<(?P<user>[^>]*)>")
DOVECOT_RIP = re.compile(r"\brip=(?P<ip>[^,\s]+)")
DOVECOT_METHOD = re.compile(r"\bmethod=(?P<method>[^,\s]+)")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAILISH = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+")


def _status(line):
    x = line.lower()
    if any(t in x for t in ("auth failed", "login failed", "failed login", "authentication failed", "password mismatch")):
        return "FAILED"
    if "login:" in x or any(t in x for t in ("successful login", "login successful", "logged in")):
        return "SUCCESS"
    return "INFO"


def _syslog_datetime(ts):
    if not ts:
        return None
    now = datetime.now()
    try:
        parsed = datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S")
        if parsed > now + timedelta(days=7):
            parsed = parsed.replace(year=now.year - 1)
        return parsed
    except Exception:
        return None


def _roundcube_datetime(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    for fmt in ("%d-%b-%Y %H:%M:%S %z", "%d-%b-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            d = datetime.strptime(raw, fmt)
            return d.replace(tzinfo=None) if d.tzinfo else d
        except Exception:
            pass
    return _syslog_datetime(raw)


def _roundcube_user(line):
    m = EMAILISH.search(line)
    if m:
        return m.group(0)
    for pat in (r"(?:user|username)[=:]\s*[<\[]?([^,;\]\s>]+)", r"login for\s+([^\s,;]+)"):
        m = re.search(pat, line, re.I)
        if m:
            return m.group(1).strip("<>[]'\"")
    return ""


def _geo(ip):
    if not ip:
        return {
            "country": "", "country_code": "", "region": "", "city": "",
            "asn": None, "organization": "",
        }
    data = enrich_ip(ip)
    return {
        "country": data.get("country", "") or "",
        "country_code": data.get("country_code", "") or "",
        "region": data.get("region", "") or "",
        "city": data.get("city", "") or "",
        "asn": data.get("asn"),
        "organization": data.get("organization", "") or "",
    }


def _event_hash(protocol, status, user, ip, timestamp_text, line, source):
    material = "\0".join((protocol, status, user, ip, timestamp_text, line, source))
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def _base_event(protocol, status, user, ip, timestamp_text, line, source, event_time, auth_method=""):
    # GEO is intentionally deferred until MariaDB confirms this event hash is
    # new. Duplicate replay/restart protection therefore does not repeat MMDB
    # work for historical rows.
    return {
        "event_hash": _event_hash(protocol, status, user, ip, timestamp_text, line, source),
        "event_time": event_time,
        "timestamp_text": timestamp_text,
        "username": user,
        "protocol": protocol,
        "status": status,
        "remote_ip": ip,
        "auth_method": auth_method,
        "source": source,
        "raw_log": line,
        "country": "",
        "country_code": "",
        "region": "",
        "city": "",
        "asn": None,
        "organization": "",
    }


def parse_dovecot_events(lines):
    events = []
    for line in lines:
        x = line.lower()
        if "dovecot" not in x:
            continue
        if "pop3-login" in x:
            protocol = "POP3"
        else:
            # IMAP login events are intentionally ignored. Long-lived/refreshing
            # IMAP clients create high-volume authentication noise that is not
            # useful in the operational Monitor view. Existing DB rows are left
            # untouched for audit/history compatibility.
            continue
        if not any(t in x for t in ("login:", "auth failed", "authentication failed", "disconnected:")):
            continue
        tm = SYSLOG_TS.search(line)
        um = DOVECOT_USER.search(line)
        im = DOVECOT_RIP.search(line)
        mm = DOVECOT_METHOD.search(line)
        timestamp_text = tm.group("ts") if tm else ""
        status = _status(line)
        if status == "INFO":
            continue
        user = um.group("user") if um else ""
        ip = im.group("ip") if im else ""
        method = mm.group("method") if mm else ""
        events.append(_base_event(
            protocol, status, user, ip, timestamp_text, line, "dovecot",
            _syslog_datetime(timestamp_text), method,
        ))
    return events


def parse_roundcube_events(lines):
    events = []
    for line in lines:
        if not line.strip():
            continue
        x = line.lower()
        if not any(t in x for t in ("login", "logged", "auth", "user")):
            continue
        status = _status(line)
        if status == "INFO":
            continue
        ips = IPV4.findall(line)
        m = re.search(r"\[(?P<ts>[^\]]+)\]", line)
        sm = SYSLOG_TS.search(line)
        timestamp_text = m.group("ts") if m else (sm.group("ts") if sm else "")
        user = _roundcube_user(line)
        ip = ips[-1] if ips else ""
        events.append(_base_event(
            "WEBMAIL", status, user, ip, timestamp_text, line, "roundcube",
            _roundcube_datetime(timestamp_text), "",
        ))
    return events


def _load_ingest_state(source_key):
    from .db import conn
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT source_key,source_path,source_device,source_inode,source_offset,source_size,status,last_error "
                "FROM mail_login_ingest_state WHERE source_key=%s",
                (source_key,),
            )
            return cursor.fetchone() or None


def _source_has_history(source_name):
    from .db import conn
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 AS present FROM mail_login_events WHERE source=%s LIMIT 1",
                (source_name,),
            )
            return bool(cursor.fetchone())


def _source_info(path):
    return {
        "path": str(path), "exists": False, "readable": False, "error": "",
        "size": 0, "mtime": "", "device": 0, "inode": 0, "offset": 0,
        "mode": "unknown",
    }


def _read_incremental(source_key, source_name, path):
    """Read only bytes not covered by the durable MariaDB checkpoint."""
    info = _source_info(path)
    try:
        st = path.stat()
        info.update({
            "exists": True,
            "readable": True,
            "size": int(st.st_size),
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "device": int(st.st_dev),
            "inode": int(st.st_ino),
        })
    except FileNotFoundError:
        info["error"] = "Log file not found"
        return [], info, None
    except PermissionError:
        info["error"] = "Permission denied reading log file"
        return [], info, None
    except Exception as exc:
        info["error"] = f"Unable to stat log: {exc}"
        return [], info, None

    state = _load_ingest_state(source_key)
    info["state_exists"] = bool(state)
    info["previous_offset"] = int((state or {}).get("source_offset") or 0)
    if not state:
        if _source_has_history(source_name):
            # In-place upgrade: existing raw history is already populated. Adopt
            # current EOF so R1.1.44 does not replay/geo-enrich the old tail.
            info["mode"] = "adopt_existing_eof"
            info["offset"] = int(st.st_size)
            return [], info, int(st.st_size)
        start = max(0, int(st.st_size) - MAX_TAIL_BYTES)
        drop_first_partial = start > 0
        info["mode"] = "bootstrap_tail"
    else:
        old_dev = int(state.get("source_device") or 0)
        old_inode = int(state.get("source_inode") or 0)
        old_offset = int(state.get("source_offset") or 0)
        if old_dev == int(st.st_dev) and old_inode == int(st.st_ino):
            if int(st.st_size) < old_offset:
                start = 0
                info["mode"] = "file_shrunk"
            else:
                start = old_offset
                info["mode"] = "append"
        else:
            start = 0
            info["mode"] = "rotated"
        drop_first_partial = False

    if start >= int(st.st_size):
        info["offset"] = int(start)
        return [], info, int(start)

    try:
        with path.open("rb") as fh:
            fh.seek(start)
            raw = fh.read(min(MAX_READ_BYTES, int(st.st_size) - start))
    except PermissionError:
        info["readable"] = False
        info["error"] = "Permission denied reading log file"
        return [], info, None
    except Exception as exc:
        info["readable"] = False
        info["error"] = f"Unable to read log: {exc}"
        return [], info, None

    base = int(start)
    if drop_first_partial and raw:
        first_nl = raw.find(b"\n")
        if first_nl < 0:
            info["offset"] = base
            return [], info, base
        raw = raw[first_nl + 1:]
        base += first_nl + 1

    last_nl = raw.rfind(b"\n")
    if last_nl < 0:
        info["offset"] = base
        return [], info, base
    complete = raw[:last_nl + 1]
    next_offset = base + last_nl + 1
    lines = complete.decode("utf-8", errors="replace").splitlines()
    info["offset"] = int(next_offset)
    return lines, info, int(next_offset)


def _existing_hashes(cursor, events):
    hashes = [str(e.get("event_hash") or "") for e in events if e.get("event_hash")]
    existing = set()
    for i in range(0, len(hashes), 500):
        chunk = hashes[i:i + 500]
        if not chunk:
            continue
        ph = ",".join(["%s"] * len(chunk))
        cursor.execute(f"SELECT event_hash FROM mail_login_events WHERE event_hash IN ({ph})", tuple(chunk))
        existing.update(str(r.get("event_hash") or "") for r in (cursor.fetchall() or []))
    return existing


def _enrich_new_events(events):
    for event in events:
        event.update(_geo(event.get("remote_ip")))
    return events


def _insert_events_tx(cursor, events):
    if not events:
        return 0
    existing = _existing_hashes(cursor, events)
    new_events = [e for e in events if str(e.get("event_hash") or "") not in existing]
    _enrich_new_events(new_events)
    sql = """
    INSERT IGNORE INTO mail_login_events
      (event_hash,event_time,timestamp_text,username,protocol,status,remote_ip,auth_method,source,
       country,country_code,region,city,asn,organization,raw_log)
    VALUES
      (%(event_hash)s,%(event_time)s,%(timestamp_text)s,%(username)s,%(protocol)s,%(status)s,%(remote_ip)s,%(auth_method)s,%(source)s,
       %(country)s,%(country_code)s,%(region)s,%(city)s,%(asn)s,%(organization)s,%(raw_log)s)
    """
    summary_sql = """
    INSERT INTO mail_login_user_summary
      (protocol,username,success_count,failed_count,total_events,last_login,last_ip,last_country,last_city,last_asn,last_organization)
    VALUES
      (%(protocol)s,%(username)s,%(success_delta)s,%(failed_delta)s,1,%(event_time)s,%(remote_ip)s,%(country)s,%(city)s,%(asn)s,%(organization)s)
    ON DUPLICATE KEY UPDATE
      success_count=success_count+VALUES(success_count),
      failed_count=failed_count+VALUES(failed_count),
      total_events=total_events+1,
      last_ip=IF(last_login IS NULL OR (VALUES(last_login) IS NOT NULL AND VALUES(last_login)>=last_login),VALUES(last_ip),last_ip),
      last_country=IF(last_login IS NULL OR (VALUES(last_login) IS NOT NULL AND VALUES(last_login)>=last_login),VALUES(last_country),last_country),
      last_city=IF(last_login IS NULL OR (VALUES(last_login) IS NOT NULL AND VALUES(last_login)>=last_login),VALUES(last_city),last_city),
      last_asn=IF(last_login IS NULL OR (VALUES(last_login) IS NOT NULL AND VALUES(last_login)>=last_login),VALUES(last_asn),last_asn),
      last_organization=IF(last_login IS NULL OR (VALUES(last_login) IS NOT NULL AND VALUES(last_login)>=last_login),VALUES(last_organization),last_organization),
      last_login=IF(last_login IS NULL OR (VALUES(last_login) IS NOT NULL AND VALUES(last_login)>=last_login),VALUES(last_login),last_login)
    """
    inserted = 0
    for event in new_events:
        cursor.execute(sql, event)
        was_inserted = int(cursor.rowcount or 0)
        inserted += was_inserted
        if was_inserted and str(event.get("username") or ""):
            projection = dict(event)
            projection["success_delta"] = 1 if event.get("status") == "SUCCESS" else 0
            projection["failed_delta"] = 1 if event.get("status") == "FAILED" else 0
            cursor.execute(summary_sql, projection)
    return inserted


def _save_ingest_state(cursor, source_key, info, next_offset, status="OK", error=""):
    cursor.execute(
        """
        INSERT INTO mail_login_ingest_state
          (source_key,source_path,source_device,source_inode,source_offset,source_size,status,last_error)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          source_path=VALUES(source_path), source_device=VALUES(source_device),
          source_inode=VALUES(source_inode), source_offset=VALUES(source_offset),
          source_size=VALUES(source_size), status=VALUES(status), last_error=VALUES(last_error)
        """,
        (
            source_key, info.get("path") or "", int(info.get("device") or 0),
            int(info.get("inode") or 0), int(next_offset or 0), int(info.get("size") or 0),
            status, str(error or ""),
        ),
    )


def _commit_source_batch(source_key, info, next_offset, events):
    from .db import conn
    with conn() as connection:
        with connection.cursor() as cursor:
            inserted = _insert_events_tx(cursor, events)
            _save_ingest_state(cursor, source_key, info, next_offset, "OK", "")
        connection.commit()
    return inserted


def _record_source_error(source_key, info):
    from .db import conn
    state = _load_ingest_state(source_key)
    offset = int((state or {}).get("source_offset") or 0)
    with conn() as connection:
        with connection.cursor() as cursor:
            _save_ingest_state(cursor, source_key, info, offset, "ERROR", info.get("error") or "read error")
        connection.commit()


def sync_login_events():
    """Incrementally ingest Dovecot POP3 and Roundcube login events.

    R1.1.44 persists device/inode/offset per source. The checkpoint is advanced
    only after new raw events and the per-user summary projection commit.
    """
    specs = (
        ("dovecot-pop3", "dovecot", DOVECOT_MAIL_LOG, parse_dovecot_events),
        ("roundcube-webmail", "roundcube", ROUNDCUBE_LOGIN_LOG, parse_roundcube_events),
    )
    total_inserted = 0
    total_parsed = 0
    sources = {}
    for source_key, source_name, path, parser in specs:
        lines, info, next_offset = _read_incremental(source_key, source_name, path)
        sources[source_name] = info
        if next_offset is None:
            try:
                _record_source_error(source_key, info)
            except Exception:
                pass
            continue
        events = parser(lines) if info.get("readable") else []
        total_parsed += len(events)
        unchanged_idle = (
            bool(info.get("state_exists"))
            and info.get("mode") == "append"
            and int(next_offset or 0) == int(info.get("previous_offset") or 0)
            and not events
        )
        if not unchanged_idle:
            total_inserted += _commit_source_batch(source_key, info, next_offset, events)
    return {"inserted": total_inserted, "parsed": total_parsed, "sources": sources}


def monitor_source_status(source_key, path):
    """Cheap source status for compatibility callers; never rereads log tails."""
    info = _source_info(path)
    try:
        st = path.stat()
        info.update({
            "exists": True, "readable": os.access(path, os.R_OK), "size": int(st.st_size),
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "device": int(st.st_dev), "inode": int(st.st_ino),
        })
    except Exception as exc:
        info["error"] = str(exc)
    state = _load_ingest_state(source_key)
    if state:
        info["offset"] = int(state.get("source_offset") or 0)
        info["mode"] = str(state.get("status") or "UNKNOWN")
        if state.get("last_error"):
            info["error"] = str(state.get("last_error"))
    return info


def _where(protocol, search="", date_from="", date_to=""):
    clauses = ["protocol=%s"]
    params = [str(protocol or "").upper()]
    q = str(search or "").strip()
    if q:
        clauses.append("(username LIKE %s OR remote_ip LIKE %s OR country LIKE %s OR city LIKE %s OR organization LIKE %s)")
        like = f"%{q}%"
        params.extend([like, like, like, like, like])
    if date_from:
        clauses.append("event_time >= %s")
        params.append(f"{date_from} 00:00:00")
    if date_to:
        clauses.append("event_time < DATE_ADD(%s, INTERVAL 1 DAY)")
        params.append(f"{date_to} 00:00:00")
    return " AND ".join(clauses), params


def login_summary(protocol, search="", date_from="", date_to="", limit=500):
    # R1.1.42 live fast path: the normal POP3/Webmail summary does not aggregate
    # the entire raw event history.  It reads the incrementally maintained
    # per-user projection ordered by its protocol/time index.  Search/date
    # reports keep the historical analytical path so their semantics are
    # unchanged.
    protocol = str(protocol or "").upper()
    row_limit = max(1, min(int(limit), 2000))
    if not str(search or "").strip() and not date_from and not date_to:
        from .db import conn
        with conn() as connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT username,success_count,failed_count,last_login,last_ip,
                           last_country,last_city,last_asn AS asn,last_organization AS organization
                    FROM mail_login_user_summary
                    WHERE protocol=%s
                    ORDER BY last_login DESC,username
                    LIMIT %s
                """, (protocol, row_limit))
                rows = cursor.fetchall()
                cursor.execute("""
                    SELECT COALESCE(SUM(success_count),0) AS success_count,
                           COALESCE(SUM(failed_count),0) AS failed_count,
                           COALESCE(SUM(total_events),0) AS total_events,
                           COUNT(*) AS total_users
                    FROM mail_login_user_summary
                    WHERE protocol=%s
                """, (protocol,))
                stat_row = cursor.fetchone() or {}
        return {
            "protocol": protocol,
            "rows": rows,
            "total_users": int(stat_row.get("total_users") or 0),
            "stats": {
                "success": int(stat_row.get("success_count") or 0),
                "failed": int(stat_row.get("failed_count") or 0),
                "total": int(stat_row.get("total_events") or 0),
                "unresolved": 0,
            },
            "query_mode": "summary_projection_fastpath",
        }

    where, params = _where(protocol, search, date_from, date_to)
    sql = f"""
    SELECT username,
           SUM(status='SUCCESS') AS success_count,
           SUM(status='FAILED') AS failed_count,
           MAX(event_time) AS last_login,
           SUBSTRING_INDEX(GROUP_CONCAT(remote_ip ORDER BY event_time DESC SEPARATOR ','), ',', 1) AS last_ip,
           SUBSTRING_INDEX(GROUP_CONCAT(country ORDER BY event_time DESC SEPARATOR '||'), '||', 1) AS last_country,
           SUBSTRING_INDEX(GROUP_CONCAT(city ORDER BY event_time DESC SEPARATOR '||'), '||', 1) AS last_city
    FROM mail_login_events
    WHERE {where} AND username<>''
    GROUP BY username
    ORDER BY MAX(event_time) DESC, username
    LIMIT %s
    """
    stats_sql = f"""
    SELECT SUM(status='SUCCESS') AS success_count,
           SUM(status='FAILED') AS failed_count,
           COUNT(*) AS total_events,
           SUM(username IS NULL OR username='') AS unresolved_count
    FROM mail_login_events
    WHERE {where}
    """
    from .db import conn
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, tuple(params + [row_limit]))
            rows = cursor.fetchall()
            cursor.execute(stats_sql, tuple(params))
            stat_row = cursor.fetchone() or {}
    stats = {
        "success": int(stat_row.get("success_count") or 0),
        "failed": int(stat_row.get("failed_count") or 0),
        "total": int(stat_row.get("total_events") or 0),
        "unresolved": int(stat_row.get("unresolved_count") or 0),
    }
    return {"protocol": protocol, "rows": rows, "total_users": len(rows), "stats": stats, "query_mode": "historical_filter"}


def login_user_history(protocol, username, date_from="", date_to="", limit=500):
    where, params = _where(protocol, "", date_from, date_to)
    where += " AND username=%s"
    params.append(str(username or ""))
    event_sql = f"""
    SELECT event_time,timestamp_text,status,remote_ip,auth_method,country,country_code,region,city,asn,organization,source
    FROM mail_login_events WHERE {where}
    ORDER BY event_time DESC,id DESC LIMIT %s
    """
    ip_sql = f"""
    SELECT remote_ip,
           SUM(status='SUCCESS') AS success_count,
           SUM(status='FAILED') AS failed_count,
           MAX(event_time) AS last_seen,
           SUBSTRING_INDEX(GROUP_CONCAT(country ORDER BY event_time DESC SEPARATOR '||'), '||', 1) AS country,
           SUBSTRING_INDEX(GROUP_CONCAT(city ORDER BY event_time DESC SEPARATOR '||'), '||', 1) AS city,
           SUBSTRING_INDEX(GROUP_CONCAT(organization ORDER BY event_time DESC SEPARATOR '||'), '||', 1) AS organization,
           MAX(asn) AS asn
    FROM mail_login_events WHERE {where} AND remote_ip<>''
    GROUP BY remote_ip ORDER BY MAX(event_time) DESC
    """
    from .db import conn
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(event_sql, tuple(params + [max(1, min(int(limit), 2000))]))
            events = cursor.fetchall()
            cursor.execute(ip_sql, tuple(params))
            ips = cursor.fetchall()
    return {"protocol": str(protocol).upper(), "username": username, "events": events, "ips": ips}


def monitor_db_stats():
    from .db import conn
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT protocol,
                       COALESCE(SUM(success_count),0) AS success_count,
                       COALESCE(SUM(failed_count),0) AS failed_count
                FROM mail_login_user_summary
                GROUP BY protocol
            """)
            rows = cursor.fetchall()
    data = {"POP3": {"success": 0, "failed": 0}, "WEBMAIL": {"success": 0, "failed": 0}}
    for row in rows:
        p = row.get("protocol")
        if p in data:
            data[p]["success"] = int(row.get("success_count") or 0)
            data[p]["failed"] = int(row.get("failed_count") or 0)
    return data

# Compatibility endpoints retained for older clients/tests.
def dovecot_pop3_logins(search="", status="all", limit=200):
    summary = login_summary("POP3", search=search, limit=limit)
    return {"source": monitor_source_status("dovecot-pop3", DOVECOT_MAIL_LOG), "counts": monitor_db_stats()["POP3"], "matched": len(summary["rows"]), "entries": summary["rows"]}


def roundcube_logins(search="", status="all", limit=200):
    summary = login_summary("WEBMAIL", search=search, limit=limit)
    return {"source": monitor_source_status("roundcube-webmail", ROUNDCUBE_LOGIN_LOG), "counts": monitor_db_stats()["WEBMAIL"], "matched": len(summary["rows"]), "entries": summary["rows"]}
