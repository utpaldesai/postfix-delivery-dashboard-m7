import os
from email.utils import getaddresses

import pymysql
from pymysql.cursors import DictCursor

CFG = {
    "host": os.getenv("SPAM_PREF_DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("SPAM_PREF_DB_PORT", "3306")),
    "user": os.getenv("SPAM_PREF_DB_USER", "spam"),
    "password": os.getenv("SPAM_PREF_DB_PASSWORD", ""),
    "database": os.getenv("SPAM_PREF_DB_NAME", "maildb"),
    "charset": "utf8mb4",
    "cursorclass": DictCursor,
    "autocommit": True,
    "connect_timeout": 5,
    "read_timeout": 10,
    "write_timeout": 10,
}


def _conn(autocommit=True):
    cfg = dict(CFG)
    cfg["autocommit"] = bool(autocommit)
    return pymysql.connect(**cfg)


def _safe_email(value):
    values = getaddresses([str(value or "")])
    if not values:
        return ""
    return str(values[0][1] or "").strip().lower()


def _domain(addr):
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().lower().rstrip(".")


def _table_columns(cursor, table):
    cursor.execute(
        """
        SELECT COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s
        """,
        (CFG["database"], table),
    )
    return {str(row["COLUMN_NAME"]) for row in (cursor.fetchall() or [])}


def _sender_policy(cursor, sender):
    sender = _safe_email(sender)
    if not sender:
        return []
    columns = _table_columns(cursor, "userpref")
    if not {"username", "preference", "value"}.issubset(columns):
        return []
    domain = _domain(sender)
    values = [sender]
    if domain:
        values.extend([f"*@{domain}", f"@{domain}"])
    placeholders = ",".join(["%s"] * len(values))
    cursor.execute(
        f"""
        SELECT username, preference, value
        FROM userpref
        WHERE preference IN ('whitelist_from','whitelist_auth','blacklist_from')
          AND LOWER(value) IN ({placeholders})
        ORDER BY preference, username
        LIMIT 50
        """,
        tuple(v.lower() for v in values),
    )
    return list(cursor.fetchall() or [])


def _history(cursor, pdp_id, message_id):
    if not _table_columns(cursor, "dashboard_learning_history"):
        return []
    cols = _table_columns(cursor, "dashboard_learning_history")
    required = {"quarantine_id", "learning_type", "learned_at"}
    if not required.issubset(cols):
        return []
    selected = [c for c in ("learning_type", "learned_by", "client_ip", "learned_at", "sa_learn_rc", "examined_count", "learned_count", "sa_learn_output") if c in cols]
    where = ["quarantine_id=%s"]
    params = [pdp_id]
    if message_id and "message_id" in cols:
        where.append("message_id=%s")
        params.append(message_id)
    cursor.execute(
        f"SELECT {','.join(selected)} FROM dashboard_learning_history WHERE {' OR '.join(where)} ORDER BY learned_at DESC LIMIT 20",
        tuple(params),
    )
    return list(cursor.fetchall() or [])


def get_intelligence(pdp_id, message_id="", sender="", recipient=""):
    # Quarantine Intelligence intentionally excludes Bayes statistics and generic
    # host-maildb table inventory. Only message-relevant policy/history evidence
    # is queried here, reducing database work and UI noise.
    with _conn() as connection:
        with connection.cursor() as cursor:
            return {
                "connected": True,
                "sender_policy": _sender_policy(cursor, sender),
                "history": _history(cursor, pdp_id, message_id),
                "sender": _safe_email(sender),
                "recipient": _safe_email(recipient),
            }


def record_learning_best_effort(
    pdp_id,
    message_id,
    sender,
    recipient,
    mode,
    username,
    client_ip,
    sa_learn_rc,
    examined_count,
    learned_count,
    source_sha256,
    sa_learn_output,
):
    try:
        with _conn() as connection:
            with connection.cursor() as cursor:
                cols = _table_columns(cursor, "dashboard_learning_history")
                if not cols:
                    return False
                required = {
                    "quarantine_id", "learning_type", "learned_by",
                    "learned_at", "sa_learn_rc",
                }
                if not required.issubset(cols):
                    return False
                values = {
                    "quarantine_id": pdp_id,
                    "message_id": message_id,
                    "sender": sender,
                    "recipient": recipient,
                    "learning_type": str(mode).upper(),
                    "learned_by": username or "",
                    "client_ip": client_ip or "",
                    "sa_learn_rc": int(sa_learn_rc),
                    "examined_count": examined_count,
                    "learned_count": learned_count,
                    "source_sha256": source_sha256,
                    "sa_learn_output": str(sa_learn_output or "")[:4000],
                }
                insert_cols = [key for key in values if key in cols]
                placeholders = ",".join(["%s"] * len(insert_cols))
                cursor.execute(
                    f"INSERT INTO dashboard_learning_history ({','.join(insert_cols)}) VALUES ({placeholders})",
                    tuple(values[key] for key in insert_cols),
                )
                return True
    except Exception:
        return False
