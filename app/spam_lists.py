import os
import re

import pymysql
from pymysql.cursors import DictCursor


SPAM_PREFS = ("whitelist_auth", "whitelist_from", "blacklist_from")
SPAM_SCOPES = ("global", "domain", "user")

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


def _scope_from_username(username):
    username = str(username or "")
    if username == "@GLOBAL":
        return "global", ""
    if username.startswith("%"):
        return "domain", username[1:]
    return "user", username


def _username_from_scope(scope, principal):
    scope = str(scope or "").strip().lower()
    principal = str(principal or "").strip()

    if scope not in SPAM_SCOPES:
        raise ValueError("Invalid scope")

    if scope == "global":
        return "@GLOBAL"

    if scope == "domain":
        principal = principal.lower().lstrip("%@")
        if (
            not principal
            or len(principal) > 99
            or "@" in principal
            or any(ch.isspace() for ch in principal)
            or "." not in principal
        ):
            raise ValueError("Invalid domain")
        return "%" + principal

    if not principal or len(principal) > 100 or any(ch.isspace() for ch in principal):
        raise ValueError("Invalid user")
    return principal


def _validate_pref(preference):
    preference = str(preference or "").strip().lower()
    if preference not in SPAM_PREFS:
        raise ValueError("Invalid SpamAssassin preference")
    return preference


def _validate_value(value):
    value = str(value or "").strip()
    if not value or len(value) > 100:
        raise ValueError("Value is required and must be at most 100 characters")
    if any(ch in value for ch in ("\r", "\n", "\x00")):
        raise ValueError("Invalid value")
    return value


def list_entries(search="", preference="all", scope="all", page=1, page_size=50):
    search = str(search or "").strip()
    preference = str(preference or "all").strip().lower()
    scope = str(scope or "all").strip().lower()
    page = max(1, int(page))
    page_size = max(10, min(200, int(page_size)))

    clauses = ["preference IN (%s,%s,%s)"]
    params = list(SPAM_PREFS)

    if preference != "all":
        preference = _validate_pref(preference)
        clauses.append("preference=%s")
        params.append(preference)

    if scope != "all":
        if scope not in SPAM_SCOPES:
            raise ValueError("Invalid scope")
        if scope == "global":
            clauses.append("username='@GLOBAL'")
        elif scope == "domain":
            clauses.append("LEFT(username,1)='%'")
        else:
            clauses.append("username <> '@GLOBAL' AND LEFT(username,1)<>'%'")

    if search:
        clauses.append("(username LIKE %s OR preference LIKE %s OR value LIKE %s)")
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern])

    where = " AND ".join(clauses)
    offset = (page - 1) * page_size

    with _conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) AS total FROM userpref WHERE {where}", params)
            total = int((cursor.fetchone() or {}).get("total", 0))

            cursor.execute(
                f"""
                SELECT prefid, username, preference, value
                FROM userpref
                WHERE {where}
                ORDER BY
                  CASE preference
                    WHEN 'whitelist_auth' THEN 1
                    WHEN 'whitelist_from' THEN 2
                    WHEN 'blacklist_from' THEN 3
                    ELSE 9
                  END,
                  username ASC,
                  prefid DESC
                LIMIT %s OFFSET %s
                """,
                params + [page_size, offset],
            )
            rows = cursor.fetchall() or []

    items = []
    counts = {"whitelist": 0, "blacklist": 0}
    for row in rows:
        row_scope, principal = _scope_from_username(row["username"])
        pref = row["preference"]
        kind = "blacklist" if pref == "blacklist_from" else "whitelist"
        counts[kind] += 1
        items.append({
            "prefid": int(row["prefid"]),
            "scope": row_scope,
            "principal": principal,
            "username": row["username"],
            "preference": pref,
            "value": row["value"],
            "kind": kind,
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
        "page_counts": counts,
    }


def _duplicate_exists(cursor, username, preference, value, exclude_prefid=None):
    sql = """
        SELECT prefid FROM userpref
        WHERE username=%s AND preference=%s AND value=%s
    """
    params = [username, preference, value]
    if exclude_prefid is not None:
        sql += " AND prefid<>%s"
        params.append(int(exclude_prefid))
    sql += " LIMIT 1"
    cursor.execute(sql, params)
    return cursor.fetchone() is not None


def create_entry(scope, principal, preference, value):
    username = _username_from_scope(scope, principal)
    preference = _validate_pref(preference)
    value = _validate_value(value)

    with _conn() as connection:
        with connection.cursor() as cursor:
            if _duplicate_exists(cursor, username, preference, value):
                raise ValueError("This SpamAssassin preference already exists")
            cursor.execute(
                "INSERT INTO userpref (username, preference, value) VALUES (%s,%s,%s)",
                (username, preference, value),
            )
            prefid = int(cursor.lastrowid)

    return {
        "prefid": prefid,
        "username": username,
        "preference": preference,
        "value": value,
    }


def update_entry(prefid, scope, principal, preference, value):
    prefid = int(prefid)
    username = _username_from_scope(scope, principal)
    preference = _validate_pref(preference)
    value = _validate_value(value)

    with _conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT prefid FROM userpref WHERE prefid=%s AND preference IN (%s,%s,%s)",
                [prefid, *SPAM_PREFS],
            )
            if cursor.fetchone() is None:
                raise KeyError("Preference entry not found")
            if _duplicate_exists(cursor, username, preference, value, prefid):
                raise ValueError("This SpamAssassin preference already exists")
            cursor.execute(
                """
                UPDATE userpref
                SET username=%s, preference=%s, value=%s
                WHERE prefid=%s
                """,
                (username, preference, value, prefid),
            )

    return {
        "prefid": prefid,
        "username": username,
        "preference": preference,
        "value": value,
    }


def delete_entry(prefid):
    prefid = int(prefid)
    with _conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT prefid, username, preference, value
                FROM userpref
                WHERE prefid=%s AND preference IN (%s,%s,%s)
                """,
                [prefid, *SPAM_PREFS],
            )
            row = cursor.fetchone()
            if row is None:
                raise KeyError("Preference entry not found")
            cursor.execute("DELETE FROM userpref WHERE prefid=%s", (prefid,))
    return row


def db_ready():
    try:
        with _conn() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 AS ok")
                return int((cursor.fetchone() or {}).get("ok", 0)) == 1
    except Exception:
        return False

MAX_BULK_DELETE = 100
MAX_IMPORT_LINES = 0  # 0 = unlimited
MAX_IMPORT_BYTES = 2 * 1024 * 1024
IMPORT_DIRECTIVES = SPAM_PREFS


def _clean_import_value(value):
    value = _validate_value(value)
    if "@" in value:
        local, domain = value.rsplit("@", 1)
        if not local or not domain:
            raise ValueError("Invalid email/domain pattern")
        domain = domain.strip().lower()
        if not domain or any(ch.isspace() for ch in domain):
            raise ValueError("Invalid email/domain pattern")
        value = f"{local}@{domain}"
    return value


def _parse_import_text(text):
    text = str(text or "")
    if len(text.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValueError("Import file exceeds the 2 MB limit")
    lines = text.splitlines()
    if MAX_IMPORT_LINES > 0 and len(lines) > MAX_IMPORT_LINES:
        raise ValueError(f"Import is limited to {MAX_IMPORT_LINES} lines")

    parsed = []
    invalid = []
    skipped = 0
    seen = set()

    for line_no, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            skipped += 1
            continue

        parts = line.split(None, 1)
        if len(parts) != 2:
            invalid.append({"line": line_no, "text": raw[:300], "reason": "Expected: directive value"})
            continue

        directive = parts[0].strip().lower()
        value = parts[1].strip()
        if directive not in IMPORT_DIRECTIVES:
            invalid.append({"line": line_no, "text": raw[:300], "reason": "Unsupported directive"})
            continue
        try:
            value = _clean_import_value(value)
        except ValueError as exc:
            invalid.append({"line": line_no, "text": raw[:300], "reason": str(exc)})
            continue

        dedupe_key = (directive, value.lower())
        if dedupe_key in seen:
            parsed.append({"line": line_no, "preference": directive, "value": value, "file_duplicate": True})
            continue
        seen.add(dedupe_key)
        parsed.append({"line": line_no, "preference": directive, "value": value, "file_duplicate": False})

    return parsed, invalid, skipped


def preview_import(text, scope="global", principal=""):
    username = _username_from_scope(scope, principal)
    parsed, invalid, skipped = _parse_import_text(text)

    duplicate_keys = set()
    unique_candidates = [x for x in parsed if not x["file_duplicate"]]
    if unique_candidates:
        with _conn() as connection:
            with connection.cursor() as cursor:
                for item in unique_candidates:
                    cursor.execute(
                        """
                        SELECT prefid FROM userpref
                        WHERE username=%s AND preference=%s AND LOWER(value)=LOWER(%s)
                        LIMIT 1
                        """,
                        (username, item["preference"], item["value"]),
                    )
                    if cursor.fetchone() is not None:
                        duplicate_keys.add((item["preference"], item["value"].lower()))

    preview_rows = []
    added = 0
    duplicates = 0
    for item in parsed:
        is_duplicate = item["file_duplicate"] or (
            item["preference"], item["value"].lower()
        ) in duplicate_keys
        if is_duplicate:
            duplicates += 1
            status = "duplicate"
        else:
            added += 1
            status = "add"
        preview_rows.append({
            "line": item["line"],
            "preference": item["preference"],
            "value": item["value"],
            "status": status,
        })

    return {
        "scope": scope,
        "principal": principal,
        "username": username,
        "total_lines": len(str(text or "").splitlines()),
        "added": added,
        "duplicates": duplicates,
        "invalid": len(invalid),
        "skipped": skipped,
        "invalid_rows": invalid[:100],
        "preview_rows": preview_rows[:500],
    }


def import_entries(text, scope="global", principal=""):
    username = _username_from_scope(scope, principal)
    parsed, invalid, skipped = _parse_import_text(text)

    inserted = []
    duplicates = 0
    seen = set()

    connection = _conn(autocommit=False)
    try:
        with connection.cursor() as cursor:
            for item in parsed:
                key = (item["preference"], item["value"].lower())
                if item["file_duplicate"] or key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                cursor.execute(
                    """
                    SELECT prefid FROM userpref
                    WHERE username=%s AND preference=%s AND LOWER(value)=LOWER(%s)
                    LIMIT 1
                    """,
                    (username, item["preference"], item["value"]),
                )
                if cursor.fetchone() is not None:
                    duplicates += 1
                    continue
                cursor.execute(
                    "INSERT INTO userpref (username, preference, value) VALUES (%s,%s,%s)",
                    (username, item["preference"], item["value"]),
                )
                inserted.append({
                    "prefid": int(cursor.lastrowid),
                    "username": username,
                    "preference": item["preference"],
                    "value": item["value"],
                })
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    return {
        "scope": scope,
        "principal": principal,
        "username": username,
        "total_lines": len(str(text or "").splitlines()),
        "added": len(inserted),
        "duplicates": duplicates,
        "invalid": len(invalid),
        "skipped": skipped,
        "invalid_rows": invalid[:100],
        "inserted": inserted,
    }


def bulk_delete_entries(prefids):
    if not isinstance(prefids, list):
        raise ValueError("prefids must be a list")

    clean = []
    seen = set()
    for raw in prefids:
        try:
            prefid = int(raw)
        except (TypeError, ValueError):
            raise ValueError("Invalid preference ID")
        if prefid <= 0:
            raise ValueError("Invalid preference ID")
        if prefid not in seen:
            seen.add(prefid)
            clean.append(prefid)

    if not clean:
        raise ValueError("Select at least one entry")
    if len(clean) > MAX_BULK_DELETE:
        raise ValueError(f"Maximum {MAX_BULK_DELETE} entries per bulk delete")

    placeholders = ",".join(["%s"] * len(clean))
    connection = _conn(autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT prefid, username, preference, value
                FROM userpref
                WHERE prefid IN ({placeholders})
                  AND preference IN (%s,%s,%s)
                ORDER BY prefid
                """,
                clean + list(SPAM_PREFS),
            )
            rows = cursor.fetchall() or []
            found_ids = {int(row["prefid"]) for row in rows}
            missing = [prefid for prefid in clean if prefid not in found_ids]
            if missing:
                raise KeyError("One or more preference entries were not found")
            cursor.execute(
                f"DELETE FROM userpref WHERE prefid IN ({placeholders})",
                clean,
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    return rows


def export_entries(search="", preference="all", scope="all", limit=10000):
    search = str(search or "").strip()
    preference = str(preference or "all").strip().lower()
    scope = str(scope or "all").strip().lower()
    limit = max(1, min(10000, int(limit)))

    clauses = ["preference IN (%s,%s,%s)"]
    params = list(SPAM_PREFS)

    if preference != "all":
        preference = _validate_pref(preference)
        clauses.append("preference=%s")
        params.append(preference)

    if scope != "all":
        if scope not in SPAM_SCOPES:
            raise ValueError("Invalid scope")
        if scope == "global":
            clauses.append("username='@GLOBAL'")
        elif scope == "domain":
            clauses.append("LEFT(username,1)='%' ")
        else:
            clauses.append("username <> '@GLOBAL' AND LEFT(username,1)<>'%'")

    if search:
        clauses.append("(username LIKE %s OR preference LIKE %s OR value LIKE %s)")
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern])

    where = " AND ".join(clauses)
    with _conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT prefid, username, preference, value
                FROM userpref
                WHERE {where}
                ORDER BY
                  CASE preference
                    WHEN 'whitelist_from' THEN 1
                    WHEN 'whitelist_auth' THEN 2
                    WHEN 'blacklist_from' THEN 3
                    ELSE 9
                  END,
                  value ASC,
                  prefid ASC
                LIMIT %s
                """,
                params + [limit],
            )
            rows = cursor.fetchall() or []

    grouped = {pref: [] for pref in SPAM_PREFS}
    for row in rows:
        grouped[row["preference"]].append(row["value"])

    output = []
    output.append("#### white list format email id is HAM whitout DKIM and SPF PASS")
    output.append("")
    for value in grouped["whitelist_from"]:
        output.append(f"whitelist_from {value}")
    output.append("")
    output.append("### DKIM and SPF Pass")
    output.append("")
    for value in grouped["whitelist_auth"]:
        output.append(f"whitelist_auth {value}")
    output.append("")
    output.append("### blacklist format")
    output.append("")
    for value in grouped["blacklist_from"]:
        output.append(f"blacklist_from {value}")
    output.append("")

    return "\n".join(output), len(rows)



def conflict_summary(limit=500):
    """Find same scope/value present in both whitelist and blacklist preferences."""
    limit = max(1, min(2000, int(limit)))
    with _conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT username, LOWER(value) AS value_key,
                       GROUP_CONCAT(DISTINCT preference ORDER BY preference SEPARATOR ',') AS preferences,
                       MIN(value) AS value,
                       COUNT(*) AS rows_count
                FROM userpref
                WHERE preference IN (%s,%s,%s)
                GROUP BY username, LOWER(value)
                HAVING SUM(preference='blacklist_from') > 0
                   AND SUM(preference IN ('whitelist_from','whitelist_auth')) > 0
                ORDER BY username ASC, value_key ASC
                LIMIT %s
                """,
                [*SPAM_PREFS, limit],
            )
            rows = cursor.fetchall() or []
            cursor.execute(
                """
                SELECT COUNT(*) AS total FROM (
                    SELECT username, LOWER(value) AS value_key
                    FROM userpref
                    WHERE preference IN (%s,%s,%s)
                    GROUP BY username, LOWER(value)
                    HAVING SUM(preference='blacklist_from') > 0
                       AND SUM(preference IN ('whitelist_from','whitelist_auth')) > 0
                ) conflicts
                """,
                list(SPAM_PREFS),
            )
            total = int((cursor.fetchone() or {}).get("total", 0))

    items=[]
    for row in rows:
        scope, principal = _scope_from_username(row.get("username"))
        items.append({
            "username": row.get("username", ""),
            "scope": scope,
            "principal": principal,
            "value": row.get("value", ""),
            "preferences": [x for x in str(row.get("preferences") or "").split(",") if x],
            "rows_count": int(row.get("rows_count") or 0),
        })
    return {"total": total, "items": items, "truncated": total > len(items)}
