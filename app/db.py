import os
import hashlib
import hmac
import json
import re
import secrets
import time
import queue
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta

import pymysql
from pymysql.cursors import DictCursor

CFG = dict(
    host=os.getenv("DB_HOST", "mariadb"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER", "postfix_app"),
    password=os.getenv("DB_PASSWORD", ""),
    database=os.getenv("DB_NAME", "postfix_reports"),
    charset="utf8mb4",
    cursorclass=DictCursor,
    autocommit=False,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS postfix_queue_metadata (
    queue_id VARCHAR(64) NOT NULL PRIMARY KEY,
    sender VARCHAR(320) NOT NULL DEFAULT '',
    message_size_bytes BIGINT UNSIGNED NULL,
    log_timestamp VARCHAR(32) NOT NULL DEFAULT '',
    raw_log TEXT NOT NULL,
    last_updated DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS postfix_delivery_final (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_hash CHAR(64) NOT NULL,
    queue_id VARCHAR(64) NOT NULL,
    recipient VARCHAR(320) NOT NULL DEFAULT '',
    sender VARCHAR(320) NOT NULL DEFAULT '',
    message_size_bytes BIGINT UNSIGNED NULL,
    final_status ENUM(
        'DELIVERED',
        'DEFERRED',
        'BOUNCED',
        'BLOCKED',
        'SPAM',
        'QUARANTINED',
        'REJECTED',
        'UNDELIVERED'
    ) NOT NULL,
    delivery_target VARCHAR(512) NOT NULL DEFAULT '',
    status_detail TEXT NOT NULL,
    log_timestamp VARCHAR(32) NOT NULL DEFAULT '',
    host VARCHAR(255) NOT NULL DEFAULT '',
    service VARCHAR(64) NOT NULL DEFAULT '',
    process_id VARCHAR(32) NOT NULL DEFAULT '',
    raw_log TEXT NOT NULL,
    first_seen DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_updated DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    is_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE KEY uq_queue_recipient(queue_id, recipient),
    UNIQUE KEY uq_event_hash(event_hash),
    KEY idx_status(final_status),
    KEY idx_updated(last_updated)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

POSTFIX_CONTINUOUS_EVIDENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS postfix_log_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_key VARCHAR(128) NOT NULL,
    source_path VARCHAR(512) NOT NULL,
    source_device BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_inode BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
    raw_log TEXT NOT NULL,
    event_sha256 CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_postfix_source_position(source_key, source_device, source_inode, source_offset),
    UNIQUE KEY uq_postfix_event_sha(event_sha256),
    KEY idx_postfix_event_created(created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS postfix_log_ingest_state (
    source_key VARCHAR(128) NOT NULL PRIMARY KEY,
    source_path VARCHAR(512) NOT NULL,
    source_device BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_inode BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    last_error TEXT NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS dashboard_audit (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_hash CHAR(64) NOT NULL,
    event_time DATETIME NOT NULL,
    action VARCHAR(64) NOT NULL,
    username VARCHAR(128) NOT NULL DEFAULT '',
    client_ip VARCHAR(64) NOT NULL DEFAULT '',
    pdp_id VARCHAR(512) NOT NULL DEFAULT '',
    sender VARCHAR(512) NOT NULL DEFAULT '',
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    category VARCHAR(64) NOT NULL DEFAULT '',
    score VARCHAR(64) NOT NULL DEFAULT '',
    detail TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_audit_event_hash(event_hash),
    KEY idx_audit_time(event_time),
    KEY idx_audit_action(action),
    KEY idx_audit_user(username),
    KEY idx_audit_ip(client_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""


USER_SCHEMA = """
CREATE TABLE IF NOT EXISTS dashboard_users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(128) NOT NULL,
    password_hash CHAR(64) NOT NULL,
    password_salt CHAR(32) NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    permissions_json TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_dashboard_user(username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""


CONFIG_SNAPSHOT_SCHEMA = """
CREATE TABLE IF NOT EXISTS dashboard_config_snapshots (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    snapshot_time DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    username VARCHAR(128) NOT NULL DEFAULT '',
    label VARCHAR(255) NOT NULL DEFAULT '',
    fingerprint CHAR(64) NOT NULL,
    config_json LONGTEXT NOT NULL,
    KEY idx_config_snapshot_time(snapshot_time),
    KEY idx_config_snapshot_user(username),
    KEY idx_config_snapshot_fingerprint(fingerprint)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

AI_GROUND_TRUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_ground_truth_history (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_sha256 CHAR(64) NOT NULL,
    pdp_id VARCHAR(512) NOT NULL DEFAULT '',
    label VARCHAR(8) NOT NULL,
    classification VARCHAR(64) NOT NULL DEFAULT '',
    review_reason VARCHAR(512) NOT NULL DEFAULT '',
    reviewer VARCHAR(128) NOT NULL DEFAULT '',
    label_source VARCHAR(64) NOT NULL DEFAULT 'admin-ground-truth',
    status VARCHAR(32) NOT NULL DEFAULT 'CURRENT',
    previous_label VARCHAR(8) NOT NULL DEFAULT '',
    reversal_count INT UNSIGNED NOT NULL DEFAULT 0,
    generation_id VARCHAR(64) NOT NULL DEFAULT '',
    feature_schema INT UNSIGNED NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_ai_gt_sha_status(source_sha256, status),
    KEY idx_ai_gt_pdp_status(pdp_id(191), status),
    KEY idx_ai_gt_label_time(label, created_at),
    KEY idx_ai_gt_class_time(classification, created_at),
    KEY idx_ai_gt_created(created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ai_ground_truth_calibration (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_sha256 CHAR(64) NOT NULL,
    pdp_id VARCHAR(512) NOT NULL DEFAULT '',
    ai_proposed_label VARCHAR(8) NOT NULL DEFAULT '',
    ai_proposed_classification VARCHAR(64) NOT NULL DEFAULT '',
    ai_confidence DECIMAL(7,3) NULL,
    admin_final_label VARCHAR(8) NOT NULL,
    admin_final_classification VARCHAR(64) NOT NULL DEFAULT '',
    admin_acknowledged_ai BOOLEAN NOT NULL DEFAULT FALSE,
    reviewer VARCHAR(128) NOT NULL DEFAULT '',
    generation_id VARCHAR(64) NOT NULL DEFAULT '',
    candidate_version VARCHAR(128) NOT NULL DEFAULT '',
    fraud_repo_version VARCHAR(128) NOT NULL DEFAULT '',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_ai_calibration_time(created_at),
    KEY idx_ai_calibration_agree(admin_acknowledged_ai, created_at),
    KEY idx_ai_calibration_labels(ai_proposed_label, admin_final_label, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ai_conflict_investigations (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_sha256 CHAR(64) NOT NULL,
    pdp_id VARCHAR(512) NOT NULL DEFAULT '',
    candidate_version VARCHAR(128) NOT NULL DEFAULT '',
    candidate_algorithm VARCHAR(128) NOT NULL DEFAULT '',
    ai_prediction VARCHAR(8) NOT NULL DEFAULT '',
    admin_label VARCHAR(8) NOT NULL DEFAULT '',
    classification VARCHAR(64) NOT NULL DEFAULT '',
    confidence DECIMAL(7,3) NULL,
    probabilities_json TEXT NOT NULL,
    forensic_json LONGTEXT NOT NULL,
    root_cause VARCHAR(512) NOT NULL DEFAULT '',
    review_status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_ai_conflict_sha_time(source_sha256, created_at),
    KEY idx_ai_conflict_type_time(ai_prediction, admin_label, created_at),
    KEY idx_ai_conflict_status_time(review_status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""


AI_TRAINER_STATUS_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_trainer_status_snapshot (
    generation_id VARCHAR(64) NOT NULL PRIMARY KEY,
    dataset_samples BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ham_labels BIGINT UNSIGNED NOT NULL DEFAULT 0,
    spam_labels BIGINT UNSIGNED NOT NULL DEFAULT 0,
    hard_ham_labels BIGINT UNSIGNED NOT NULL DEFAULT 0,
    legacy_feature_labels BIGINT UNSIGNED NOT NULL DEFAULT 0,
    dataset_mtime_ns BIGINT UNSIGNED NOT NULL DEFAULT 0,
    dataset_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""




AI_THREAT_INTELLIGENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_message_intelligence_observations (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_sha256 CHAR(64) NOT NULL,
    source_kind VARCHAR(32) NOT NULL DEFAULT 'quarantine',
    source_id VARCHAR(512) NOT NULL DEFAULT '',
    message_id VARCHAR(512) NOT NULL DEFAULT '',
    sender_domain VARCHAR(255) NOT NULL DEFAULT '',
    reply_domain VARCHAR(255) NOT NULL DEFAULT '',
    return_path_domain VARCHAR(255) NOT NULL DEFAULT '',
    message_id_domain VARCHAR(255) NOT NULL DEFAULT '',
    source_ip VARCHAR(64) NOT NULL DEFAULT '',
    observed_reverse_name VARCHAR(255) NOT NULL DEFAULT '',
    observed_helo VARCHAR(255) NOT NULL DEFAULT '',
    asn BIGINT UNSIGNED NULL,
    asn_organization VARCHAR(255) NOT NULL DEFAULT '',
    spf_result VARCHAR(32) NOT NULL DEFAULT '',
    dkim_result VARCHAR(32) NOT NULL DEFAULT '',
    dmarc_result VARCHAR(32) NOT NULL DEFAULT '',
    template_hash CHAR(64) NOT NULL,
    body_structure_hash CHAR(64) NOT NULL,
    url_domain_set_hash CHAR(64) NOT NULL,
    attachment_set_hash CHAR(64) NOT NULL,
    sender_path_hash CHAR(64) NOT NULL,
    campaign_hash CHAR(64) NOT NULL,
    url_domain_count INT UNSIGNED NOT NULL DEFAULT 0,
    attachment_count INT UNSIGNED NOT NULL DEFAULT 0,
    first_seen DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_ai_ti_source_sha(source_sha256),
    KEY idx_ai_ti_template_time(template_hash, last_seen),
    KEY idx_ai_ti_campaign_time(campaign_hash, last_seen),
    KEY idx_ai_ti_urlset_time(url_domain_set_hash, last_seen),
    KEY idx_ai_ti_sender_time(sender_domain, last_seen),
    KEY idx_ai_ti_ip_time(source_ip, last_seen),
    KEY idx_ai_ti_asn_time(asn, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

FRAUD_REPO_SCHEMA = """
CREATE TABLE IF NOT EXISTS fraud_repo_versions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    repo_version VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    source_policy VARCHAR(128) NOT NULL DEFAULT '',
    repo_sha256 CHAR(64) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    imported_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_fraud_repo_version(repo_version),
    KEY idx_fraud_repo_active_time(active, imported_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_taxonomy (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    taxonomy_code VARCHAR(64) NOT NULL,
    label VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    severity_default VARCHAR(16) NOT NULL DEFAULT 'MEDIUM',
    training_authority BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_fraud_taxonomy_code(taxonomy_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_intent_patterns (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    repo_version VARCHAR(128) NOT NULL,
    taxonomy_code VARCHAR(64) NOT NULL,
    pattern_key VARCHAR(128) NOT NULL,
    title VARCHAR(255) NOT NULL DEFAULT '',
    pattern_json LONGTEXT NOT NULL,
    weight DECIMAL(7,3) NOT NULL DEFAULT 1.000,
    suggested_classification VARCHAR(64) NOT NULL DEFAULT 'OTHER_SPAM',
    explanation TEXT NOT NULL,
    source_type VARCHAR(64) NOT NULL DEFAULT 'EXTERNAL_RESEARCH',
    training_authority BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    entry_hash CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_fraud_pattern_hash(repo_version, entry_hash),
    KEY idx_fraud_pattern_taxonomy(taxonomy_code, enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_mechanisms (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    mechanism_code VARCHAR(64) NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE KEY uq_fraud_mechanism(mechanism_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_counter_evidence (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    repo_version VARCHAR(128) NOT NULL,
    evidence_key VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    weight DECIMAL(7,3) NOT NULL DEFAULT -1.000,
    entry_hash CHAR(64) NOT NULL,
    UNIQUE KEY uq_fraud_counter_hash(repo_version, entry_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_sample_provenance (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    repo_version VARCHAR(128) NOT NULL,
    sample_ref VARCHAR(255) NOT NULL,
    source_type VARCHAR(64) NOT NULL DEFAULT 'EXTERNAL_RESEARCH',
    source_uri TEXT NOT NULL,
    taxonomy_code VARCHAR(64) NOT NULL DEFAULT '',
    sample_sha256 CHAR(64) NOT NULL,
    training_authority BOOLEAN NOT NULL DEFAULT FALSE,
    notes TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_fraud_sample_hash(repo_version, sample_sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_regression_cases (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    repo_version VARCHAR(128) NOT NULL,
    case_key VARCHAR(128) NOT NULL,
    expected_classification VARCHAR(64) NOT NULL,
    sample_text LONGTEXT NOT NULL,
    entry_hash CHAR(64) NOT NULL,
    UNIQUE KEY uq_fraud_regression_hash(repo_version, entry_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_corpus_sources (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_key VARCHAR(128) NOT NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(64) NOT NULL DEFAULT '',
    source_uri TEXT NOT NULL,
    license_note TEXT NOT NULL,
    safety_mode VARCHAR(64) NOT NULL DEFAULT 'OFFLINE_PARSE_ONLY',
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    training_authority BOOLEAN NOT NULL DEFAULT FALSE,
    metadata_sha256 CHAR(64) NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_fraud_corpus_source_key(source_key),
    KEY idx_fraud_corpus_category_enabled(category, enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_corpus_snapshots (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_key VARCHAR(128) NOT NULL,
    snapshot_ref VARCHAR(255) NOT NULL DEFAULT '',
    snapshot_sha256 CHAR(64) NOT NULL,
    file_count INT UNSIGNED NOT NULL DEFAULT 0,
    manifest_sha256 CHAR(64) NOT NULL DEFAULT '',
    import_status VARCHAR(32) NOT NULL DEFAULT 'VERIFIED_ONLY',
    training_authority BOOLEAN NOT NULL DEFAULT FALSE,
    notes TEXT NOT NULL,
    recorded_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_fraud_corpus_snapshot(source_key, snapshot_sha256),
    KEY idx_fraud_corpus_snapshot_time(source_key, recorded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS fraud_repo_import_audit (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    repo_version VARCHAR(128) NOT NULL,
    repo_sha256 CHAR(64) NOT NULL,
    inserted_patterns INT UNSIGNED NOT NULL DEFAULT 0,
    skipped_patterns INT UNSIGNED NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'OK',
    detail TEXT NOT NULL,
    imported_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_fraud_import_version_time(repo_version, imported_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

MONITOR_SCHEMA = """
CREATE TABLE IF NOT EXISTS mail_login_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_hash CHAR(64) NOT NULL,
    event_time DATETIME NULL,
    timestamp_text VARCHAR(128) NOT NULL DEFAULT '',
    username VARCHAR(320) NOT NULL DEFAULT '',
    protocol VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL,
    remote_ip VARCHAR(64) NOT NULL DEFAULT '',
    auth_method VARCHAR(64) NOT NULL DEFAULT '',
    source VARCHAR(32) NOT NULL DEFAULT '',
    country VARCHAR(128) NOT NULL DEFAULT '',
    country_code VARCHAR(8) NOT NULL DEFAULT '',
    region VARCHAR(128) NOT NULL DEFAULT '',
    city VARCHAR(128) NOT NULL DEFAULT '',
    asn BIGINT UNSIGNED NULL,
    organization VARCHAR(255) NOT NULL DEFAULT '',
    raw_log TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_mail_login_event_hash(event_hash),
    KEY idx_mail_login_protocol_user_time(protocol, username, event_time),
    KEY idx_mail_login_status_time(status, event_time),
    KEY idx_mail_login_ip_time(remote_ip, event_time),
    KEY idx_mail_login_protocol_time_id(protocol, event_time, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mail_login_user_summary (
    protocol VARCHAR(16) NOT NULL,
    username VARCHAR(320) NOT NULL,
    success_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    failed_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    total_events BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_login DATETIME NULL,
    last_ip VARCHAR(64) NOT NULL DEFAULT '',
    last_country VARCHAR(128) NOT NULL DEFAULT '',
    last_city VARCHAR(128) NOT NULL DEFAULT '',
    last_asn BIGINT UNSIGNED NULL,
    last_organization VARCHAR(255) NOT NULL DEFAULT '',
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY(protocol, username),
    KEY idx_mail_login_summary_protocol_time(protocol, last_login, username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mail_login_summary_state (
    state_key VARCHAR(64) PRIMARY KEY,
    state_value VARCHAR(255) NOT NULL DEFAULT '',
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mail_login_ingest_state (
    source_key VARCHAR(64) NOT NULL PRIMARY KEY,
    source_path VARCHAR(512) NOT NULL DEFAULT '',
    source_device BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_inode BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    last_error TEXT NOT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

BOUNCE_PROJECTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS postfix_bounce_projection (
    delivery_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    event_date DATE NULL,
    queue_id VARCHAR(64) NOT NULL,
    sender VARCHAR(320) NOT NULL DEFAULT '',
    recipient VARCHAR(320) NOT NULL DEFAULT '',
    sender_domain VARCHAR(255) NOT NULL DEFAULT '',
    recipient_domain VARCHAR(255) NOT NULL DEFAULT '',
    log_timestamp VARCHAR(32) NOT NULL DEFAULT '',
    status_detail TEXT NOT NULL,
    last_updated DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_bounce_sender_day_domain(sender_domain, event_date, recipient_domain),
    KEY idx_bounce_recipient_day_domain(recipient_domain, event_date, sender_domain),
    KEY idx_bounce_day(event_date),
    KEY idx_bounce_queue(queue_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS postfix_bounce_projection_state (
    state_key VARCHAR(64) NOT NULL PRIMARY KEY,
    state_value VARCHAR(255) NOT NULL DEFAULT '',
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

ACL_AREAS = (
    "delivery",
    "summary",
    "quarantine",
    "spam_lists",
    "mail_size",
    "monitor",
    "system",
    "audit",
    "mail_flow",
)
ACL_LEVELS = {"none": 0, "view": 1, "admin": 2}


def _normalize_permissions(value, is_admin=False):
    if is_admin:
        return {area: "admin" for area in ACL_AREAS}
    source = value if isinstance(value, dict) else {}
    result = {}
    for area in ACL_AREAS:
        level = str(source.get(area, "none")).strip().lower()
        result[area] = level if level in ACL_LEVELS else "none"
    return result


def _password_digest(password, salt_hex):
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac(
        "sha256",
        str(password).encode("utf-8"),
        salt,
        260000,
    ).hex()


def ensure_bootstrap_user(username, password):
    username = str(username or "").strip()
    password = str(password or "")
    if not username or not password:
        return
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM dashboard_users")
            if int(cursor.fetchone()["total"]) > 0:
                return
            salt = secrets.token_hex(16)
            digest = _password_digest(password, salt)
            perms = json.dumps(
                _normalize_permissions({}, is_admin=True),
                separators=(",", ":"),
            )
            cursor.execute(
                """
                INSERT INTO dashboard_users
                    (username,password_hash,password_salt,is_admin,permissions_json,active)
                VALUES (%s,%s,%s,TRUE,%s,TRUE)
                """,
                (username, digest, salt, perms),
            )
        connection.commit()


def authenticate_dashboard_user(username, password):
    username = str(username or "").strip()
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT username,password_hash,password_salt,is_admin,
                       permissions_json,active
                FROM dashboard_users
                WHERE username=%s
                """,
                (username,),
            )
            row = cursor.fetchone()
    if not row or not row.get("active"):
        return None
    candidate = _password_digest(password, row["password_salt"])
    if not hmac.compare_digest(candidate, row["password_hash"]):
        return None
    try:
        permissions = json.loads(row.get("permissions_json") or "{}")
    except Exception:
        permissions = {}
    is_admin = bool(row.get("is_admin"))
    return {
        "username": row["username"],
        "is_admin": is_admin,
        "permissions": _normalize_permissions(permissions, is_admin=is_admin),
    }


def dashboard_user_access(username):
    username = str(username or "").strip()
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT username,is_admin,permissions_json,active
                FROM dashboard_users
                WHERE username=%s
                """,
                (username,),
            )
            row = cursor.fetchone()
    if not row or not row.get("active"):
        return None
    try:
        permissions = json.loads(row.get("permissions_json") or "{}")
    except Exception:
        permissions = {}
    is_admin = bool(row.get("is_admin"))
    return {
        "username": row["username"],
        "is_admin": is_admin,
        "permissions": _normalize_permissions(permissions, is_admin=is_admin),
    }


def list_dashboard_users():
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id,username,is_admin,permissions_json,active,created_at,updated_at
                FROM dashboard_users
                ORDER BY username
                """
            )
            rows = cursor.fetchall()
    result = []
    for row in rows:
        try:
            permissions = json.loads(row.get("permissions_json") or "{}")
        except Exception:
            permissions = {}
        is_admin = bool(row.get("is_admin"))
        result.append({
            "id": int(row["id"]),
            "username": row["username"],
            "is_admin": is_admin,
            "active": bool(row.get("active")),
            "permissions": _normalize_permissions(permissions, is_admin=is_admin),
            "created_at": str(row.get("created_at") or ""),
            "updated_at": str(row.get("updated_at") or ""),
        })
    return result


def create_dashboard_user(username, password, is_admin=False, permissions=None, active=True):
    username = str(username or "").strip()
    password = str(password or "")
    if not username or len(username) > 128:
        raise ValueError("Username is required and must be at most 128 characters")
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters")
    is_admin = bool(is_admin)
    perms = _normalize_permissions(permissions or {}, is_admin=is_admin)
    salt = secrets.token_hex(16)
    digest = _password_digest(password, salt)
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO dashboard_users
                    (username,password_hash,password_salt,is_admin,permissions_json,active)
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                (
                    username,
                    digest,
                    salt,
                    is_admin,
                    json.dumps(perms, separators=(",", ":")),
                    bool(active),
                ),
            )
        connection.commit()


def update_dashboard_user(user_id, *, password=None, is_admin=None, permissions=None, active=None):
    updates = []
    params = []
    if password is not None and str(password) != "":
        if len(str(password)) < 10:
            raise ValueError("Password must be at least 10 characters")
        salt = secrets.token_hex(16)
        updates.extend(["password_hash=%s", "password_salt=%s"])
        params.extend([_password_digest(password, salt), salt])

    current = None
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT is_admin,permissions_json FROM dashboard_users WHERE id=%s",
                (int(user_id),),
            )
            current = cursor.fetchone()
    if not current:
        raise ValueError("User not found")

    next_admin = bool(current["is_admin"]) if is_admin is None else bool(is_admin)
    try:
        current_permissions = json.loads(current.get("permissions_json") or "{}")
    except Exception:
        current_permissions = {}
    next_permissions = (
        current_permissions if permissions is None else permissions
    )

    if is_admin is not None:
        updates.append("is_admin=%s")
        params.append(next_admin)
    if permissions is not None or is_admin is not None:
        updates.append("permissions_json=%s")
        params.append(json.dumps(
            _normalize_permissions(next_permissions, is_admin=next_admin),
            separators=(",", ":"),
        ))
    if active is not None:
        updates.append("active=%s")
        params.append(bool(active))
    if not updates:
        return

    params.append(int(user_id))
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE dashboard_users SET " + ",".join(updates) + " WHERE id=%s",
                tuple(params),
            )
        connection.commit()


def delete_dashboard_user(user_id):
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM dashboard_users WHERE id=%s", (int(user_id),))
            if cursor.rowcount != 1:
                raise ValueError("User not found")
        connection.commit()


ENUM_MIGRATION = """
ALTER TABLE postfix_delivery_final
MODIFY final_status ENUM(
    'DELIVERED',
    'DEFERRED',
    'BOUNCED',
    'BLOCKED',
    'SPAM',
    'QUARANTINED',
    'REJECTED',
    'UNDELIVERED'
) NOT NULL
"""
SPAM_TO_QUARANTINED_MIGRATION = """
UPDATE postfix_delivery_final
SET final_status = 'QUARANTINED',
    status_detail = CASE
        WHEN LOWER(status_detail) LIKE '%spam%'
        THEN 'Message quarantined as spam'
        ELSE status_detail
    END
WHERE final_status = 'SPAM'
"""



TERMINAL = {
    "DELIVERED",
    "BOUNCED",
    "BLOCKED",
    "SPAM",
    "QUARANTINED",
    "REJECTED",
    "UNDELIVERED",
}

DB_POOL_SIZE = max(2, int(os.getenv("DB_POOL_SIZE", "8")))
DB_POOL_WAIT_SECONDS = max(1.0, float(os.getenv("DB_POOL_WAIT_SECONDS", "10")))


class _ConnectionPool:
    """Small thread-safe PyMySQL pool for the single Uvicorn process.

    R1.1.44 avoids creating a fresh TCP/TLS-capable client context for every
    dashboard query/background iteration. Connections are reused exclusively
    by one caller at a time, rolled back on return, and health-checked before
    reuse. The populated MariaDB schema/data are untouched.
    """

    def __init__(self, maxsize):
        self.maxsize = max(2, int(maxsize))
        self._idle = queue.LifoQueue(maxsize=self.maxsize)
        self._lock = threading.Lock()
        self._created = 0

    def _new(self, reserved=False):
        if not reserved:
            with self._lock:
                if self._created >= self.maxsize:
                    raise RuntimeError("database connection pool exhausted")
                self._created += 1
        try:
            return pymysql.connect(**CFG)
        except Exception:
            with self._lock:
                self._created = max(0, self._created - 1)
            raise

    def _discard(self, connection):
        try:
            connection.close()
        except Exception:
            pass
        with self._lock:
            self._created = max(0, self._created - 1)

    def acquire(self):
        try:
            connection = self._idle.get_nowait()
        except queue.Empty:
            with self._lock:
                if self._created < self.maxsize:
                    self._created += 1
                    reserved = True
                else:
                    reserved = False
            if reserved:
                connection = self._new(reserved=True)
            else:
                connection = self._idle.get(timeout=DB_POOL_WAIT_SECONDS)

        try:
            connection.ping(reconnect=True)
            return connection
        except Exception:
            self._discard(connection)
            # One bounded replacement attempt. If the database itself is down,
            # the caller receives the original connection failure promptly.
            return self._new()

    def release(self, connection):
        if connection is None:
            return
        try:
            connection.rollback()
        except Exception:
            self._discard(connection)
            return
        try:
            self._idle.put_nowait(connection)
        except queue.Full:
            self._discard(connection)


_DB_POOL = _ConnectionPool(DB_POOL_SIZE)


@contextmanager
def conn():
    connection = _DB_POOL.acquire()
    try:
        yield connection
    finally:
        _DB_POOL.release(connection)

def init():
    last_error = None

    for _ in range(30):
        try:
            with conn() as connection:
                with connection.cursor() as cursor:
                    for statement in SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in POSTFIX_CONTINUOUS_EVIDENCE_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in AUDIT_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in USER_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in CONFIG_SNAPSHOT_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in MONITOR_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in BOUNCE_PROJECTION_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in AI_GROUND_TRUTH_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in AI_TRAINER_STATUS_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in AI_THREAT_INTELLIGENCE_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in FRAUD_REPO_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    cursor.execute(ENUM_MIGRATION)
                    cursor.execute(SPAM_TO_QUARANTINED_MIGRATION)
                    for statement in AMAVIS_EVIDENCE_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                    for statement in AMAVIS_CONTINUOUS_EVIDENCE_SCHEMA.split(";"):
                        if statement.strip():
                            cursor.execute(statement)
                connection.commit()
            # R1.1.42: build the POP3/Webmail user-summary projection once on
            # upgrade. Existing mail_login_events remain authoritative and are
            # never deleted, reset or rewritten.
            ensure_monitor_summary_projection()
            ensure_bounce_projection()
            seed_fraud_repository()
            return
        except Exception as exc:
            last_error = exc
            time.sleep(2)

    raise RuntimeError(last_error)

def upsert_metadata(event):
    sql = """
    INSERT INTO postfix_queue_metadata (
        queue_id,
        sender,
        message_size_bytes,
        log_timestamp,
        raw_log
    ) VALUES (
        %(queue_id)s,
        %(sender)s,
        %(message_size_bytes)s,
        %(timestamp)s,
        %(raw_log)s
    )
    ON DUPLICATE KEY UPDATE
        sender = COALESCE(NULLIF(VALUES(sender), ''), sender),
        message_size_bytes = COALESCE(
            VALUES(message_size_bytes),
            message_size_bytes
        ),
        log_timestamp = VALUES(log_timestamp),
        raw_log = VALUES(raw_log),
        last_updated = CURRENT_TIMESTAMP(6)
    """

    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, event)
        connection.commit()

def _metadata_for(queue_id):
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT sender, message_size_bytes
                FROM postfix_queue_metadata
                WHERE queue_id = %s
                """,
                (queue_id,),
            )
            return cursor.fetchone() or {}

def _mail_domain(value):
    value = str(value or "").strip().lower()
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[-1][:255]


def _log_event_date(value):
    raw = str(value or "").strip()
    for fmt in ("%Y %b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).date()
        except Exception:
            pass
    return None


def _upsert_bounce_projection(cursor, delivery_id, event):
    """Maintain the additive bounce-only search projection for a terminal bounce."""
    if str(event.get("final_status") or "").upper() != "BOUNCED":
        return
    cursor.execute(
        """
        INSERT INTO postfix_bounce_projection (
            delivery_id,event_date,queue_id,sender,recipient,sender_domain,recipient_domain,
            log_timestamp,status_detail,last_updated
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP(6))
        ON DUPLICATE KEY UPDATE
            event_date=VALUES(event_date), queue_id=VALUES(queue_id), sender=VALUES(sender),
            recipient=VALUES(recipient), sender_domain=VALUES(sender_domain),
            recipient_domain=VALUES(recipient_domain), log_timestamp=VALUES(log_timestamp),
            status_detail=VALUES(status_detail), last_updated=CURRENT_TIMESTAMP(6)
        """,
        (
            int(delivery_id),
            _log_event_date(event.get("timestamp")),
            str(event.get("queue_id") or ""),
            str(event.get("sender") or ""),
            str(event.get("recipient") or ""),
            _mail_domain(event.get("sender")),
            _mail_domain(event.get("recipient")),
            str(event.get("timestamp") or ""),
            str(event.get("status_detail") or ""),
        ),
    )


def upsert_delivery(event):
    metadata = _metadata_for(event["queue_id"])

    # Preserve sender/size from qmgr metadata when delivery lines omit them.
    if not event.get("sender"):
        event["sender"] = metadata.get("sender", "")

    if event.get("message_size_bytes") is None:
        event["message_size_bytes"] = metadata.get("message_size_bytes")

    sql = """
    INSERT INTO postfix_delivery_final (
        event_hash,
        queue_id,
        recipient,
        sender,
        message_size_bytes,
        final_status,
        delivery_target,
        status_detail,
        log_timestamp,
        host,
        service,
        process_id,
        raw_log,
        is_terminal
    ) VALUES (
        %(event_hash)s,
        %(queue_id)s,
        %(recipient)s,
        %(sender)s,
        %(message_size_bytes)s,
        %(final_status)s,
        %(delivery_target)s,
        %(status_detail)s,
        %(timestamp)s,
        %(host)s,
        %(service)s,
        %(pid)s,
        %(raw_log)s,
        %(is_terminal)s
    )
    ON DUPLICATE KEY UPDATE
        sender = COALESCE(NULLIF(sender, ''), VALUES(sender)),
        message_size_bytes = COALESCE(
            message_size_bytes,
            VALUES(message_size_bytes)
        ),
        final_status = IF(
            is_terminal,
            final_status,
            VALUES(final_status)
        ),
        delivery_target = IF(
            is_terminal,
            delivery_target,
            VALUES(delivery_target)
        ),
        status_detail = IF(
            is_terminal,
            status_detail,
            VALUES(status_detail)
        ),
        log_timestamp = IF(
            is_terminal,
            log_timestamp,
            VALUES(log_timestamp)
        ),
        host = IF(is_terminal, host, VALUES(host)),
        service = IF(is_terminal, service, VALUES(service)),
        process_id = IF(
            is_terminal,
            process_id,
            VALUES(process_id)
        ),
        raw_log = IF(is_terminal, raw_log, VALUES(raw_log)),
        event_hash = IF(
            is_terminal,
            event_hash,
            VALUES(event_hash)
        ),
        is_terminal = IF(
            is_terminal,
            TRUE,
            VALUES(is_terminal)
        ),
        last_updated = CURRENT_TIMESTAMP(6)
    """

    params = {
        **event,
        "is_terminal": event["final_status"] in TERMINAL,
    }

    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            changed = cursor.rowcount > 0
            if str(params.get("final_status") or "").upper() == "BOUNCED":
                cursor.execute(
                    "SELECT id,final_status,sender,recipient,log_timestamp,status_detail "
                    "FROM postfix_delivery_final WHERE queue_id=%s AND recipient=%s LIMIT 1",
                    (params.get("queue_id"), params.get("recipient") or ""),
                )
                final_row = cursor.fetchone() or {}
                if str(final_row.get("final_status") or "").upper() == "BOUNCED" and final_row.get("id"):
                    projection_event = dict(params)
                    projection_event.update({
                        "sender": final_row.get("sender") or params.get("sender") or "",
                        "recipient": final_row.get("recipient") or params.get("recipient") or "",
                        "timestamp": final_row.get("log_timestamp") or params.get("timestamp") or "",
                        "status_detail": final_row.get("status_detail") or params.get("status_detail") or "",
                        "final_status": "BOUNCED",
                    })
                    _upsert_bounce_projection(cursor, final_row["id"], projection_event)
        connection.commit()

    return changed

TEXT_FILTER_OPERATORS = {
    "equals",
    "not_equal",
    "begins_with",
    "ends_with",
    "contains",
    "does_not_contain",
}


def _text_filter_clause(fields, param_name, operator, value):
    operator = str(operator or "contains").strip().lower()
    if operator not in TEXT_FILTER_OPERATORS:
        raise ValueError("Invalid text filter operator")

    value = str(value or "")
    if operator == "equals":
        predicate = "COALESCE({field}, '') = %({param})s"
        joiner = " OR "
        pattern = value
    elif operator == "not_equal":
        predicate = "COALESCE({field}, '') <> %({param})s"
        joiner = " AND "
        pattern = value
    elif operator == "begins_with":
        predicate = "COALESCE({field}, '') LIKE %({param})s"
        joiner = " OR "
        pattern = value + "%"
    elif operator == "ends_with":
        predicate = "COALESCE({field}, '') LIKE %({param})s"
        joiner = " OR "
        pattern = "%" + value
    elif operator == "does_not_contain":
        predicate = "COALESCE({field}, '') NOT LIKE %({param})s"
        joiner = " AND "
        pattern = "%" + value + "%"
    else:
        predicate = "COALESCE({field}, '') LIKE %({param})s"
        joiner = " OR "
        pattern = "%" + value + "%"

    clause = "(" + joiner.join(
        predicate.format(field=field, param=param_name)
        for field in fields
    ) + ")"
    return clause, pattern


def _latest_queue_ids_fast(cursor, *, size, page, status="all"):
    """Return newest Queue-IDs without grouping the full delivery table.

    This is the hot path used by the live/unsearched Delivery view.  It walks
    the last_updated secondary index in bounded windows, de-duplicates Queue-IDs
    in Python, and stops as soon as the requested page plus one look-ahead row
    has been collected.  The historical analytical GROUP BY query remains the
    fallback for text/date filters where broad matching is explicitly requested.
    """
    page = max(1, int(page))
    size = max(1, int(size))
    needed = (page * size) + 1
    scan_window = max(256, min(4096, needed * 4))
    max_scan = max(scan_window, min(50000, needed * 20))
    scanned = 0
    row_offset = 0
    seen = set()
    ordered = []

    if status != "all":
        index_name = "idx_delivery_status_updated"
        where = "WHERE final_status=%s"
        args_prefix = [status]
    else:
        index_name = "idx_delivery_updated_queue"
        where = ""
        args_prefix = []

    while len(ordered) < needed and scanned < max_scan:
        cursor.execute(
            f"""
            SELECT queue_id, last_updated
            FROM postfix_delivery_final FORCE INDEX ({index_name})
            {where}
            ORDER BY last_updated DESC, queue_id DESC
            LIMIT %s OFFSET %s
            """,
            tuple(args_prefix + [scan_window, row_offset]),
        )
        batch = cursor.fetchall() or []
        if not batch:
            break
        for item in batch:
            qid = str(item.get("queue_id") or "")
            if not qid or qid in seen:
                continue
            seen.add(qid)
            ordered.append(qid)
            if len(ordered) >= needed:
                break
        count = len(batch)
        scanned += count
        row_offset += count
        if count < scan_window:
            break

    start = (page - 1) * size
    return ordered[start:start + size + 1]


def _group_selected_queue_ids(cursor, queue_ids, *, status="all"):
    """Aggregate only the small Queue-ID set selected by the live fast path."""
    if not queue_ids:
        return []
    placeholders = ",".join(["%s"] * len(queue_ids))
    params = list(queue_ids)
    status_clause = ""
    if status != "all":
        status_clause = " AND final_status=%s"
        params.append(status)

    cursor.execute(
        f"""
        SELECT
            queue_id,
            MIN(log_timestamp) AS timestamp,
            MAX(sender) AS sender,
            MAX(message_size_bytes) AS message_size_bytes,
            MAX(last_updated) AS newest_update,
            CASE
                WHEN SUM(final_status='BLOCKED') > 0 THEN 'BLOCKED'
                WHEN SUM(final_status='QUARANTINED') > 0 THEN 'QUARANTINED'
                WHEN SUM(final_status='SPAM') > 0 THEN 'QUARANTINED'
                WHEN SUM(final_status='REJECTED') > 0 THEN 'REJECTED'
                WHEN SUM(final_status='BOUNCED') > 0 THEN 'BOUNCED'
                WHEN SUM(final_status='UNDELIVERED') > 0 THEN 'UNDELIVERED'
                WHEN SUM(final_status='DEFERRED') > 0 THEN 'DEFERRED'
                ELSE 'DELIVERED'
            END AS queue_status,
            GROUP_CONCAT(
                CONCAT(
                    COALESCE(NULLIF(recipient,''), '-'),
                    '||', final_status,
                    '||', COALESCE(NULLIF(delivery_target,''), '-'),
                    '||', REPLACE(REPLACE(status_detail, '\\n', ' '), '\\r', ' ')
                )
                ORDER BY recipient SEPARATOR '##'
            ) AS recipient_details
        FROM postfix_delivery_final
        WHERE queue_id IN ({placeholders}){status_clause}
        GROUP BY queue_id
        """,
        tuple(params),
    )
    rows = cursor.fetchall() or []
    by_id = {str(r.get("queue_id") or ""): r for r in rows}
    # Preserve exact index-first ordering selected above; SQL IN has no order guarantee.
    return [by_id[qid] for qid in queue_ids if qid in by_id]


def grouped(page, size, status, search, search_operator='contains', search_field='all', date_from='', date_to='', include_total=True):
    clauses = []
    params = {}

    if status != "all":
        clauses.append("final_status = %(status)s")
        params["status"] = status

    if search:
        field_key = str(search_field or "all").strip().lower()
        field_map = {
            "all": ("queue_id", "sender", "recipient", "delivery_target", "status_detail"),
            "from": ("sender",),
            "to": ("recipient",),
        }
        if field_key not in field_map:
            raise ValueError("Invalid delivery search field")
        search_clause, search_value = _text_filter_clause(
            field_map[field_key],
            "s",
            search_operator,
            search,
        )
        clauses.append(search_clause)
        params["s"] = search_value

    if date_from:
        clauses.append(
            "STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s') >= %(date_from)s"
        )
        params["date_from"] = f"{date_from} 00:00:00"

    if date_to:
        clauses.append(
            "STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s') <= %(date_to)s"
        )
        params["date_to"] = f"{date_to} 23:59:59"

    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    fetch_size = size if include_total else size + 1
    params.update(limit=fetch_size, offset=(page - 1) * size)

    # R1.1.41 live fast path: no text/date filter means the UI only needs the
    # newest Queue-IDs.  Avoid GROUP BY/ORDER BY over the complete history.
    use_live_fast_path = (not search and not date_from and not date_to and not include_total and int(page) <= 100)

    with conn() as connection:
        with connection.cursor() as cursor:
            total = None
            if use_live_fast_path:
                selected = _latest_queue_ids_fast(cursor, size=size, page=page, status=status)
                has_more = len(selected) > size
                selected_page = selected[:size]
                rows = _group_selected_queue_ids(cursor, selected_page, status=status)
            else:
                if include_total:
                    cursor.execute(
                        f"""
                        SELECT COUNT(*) AS total
                        FROM (
                            SELECT queue_id
                            FROM postfix_delivery_final
                            {where}
                            GROUP BY queue_id
                        ) AS grouped_rows
                        """,
                        params,
                    )
                    total = cursor.fetchone()["total"]

                cursor.execute(
                    f"""
                    SELECT
                        queue_id,
                        MIN(log_timestamp) AS timestamp,
                        MAX(sender) AS sender,
                        MAX(message_size_bytes) AS message_size_bytes,
                        CASE
                            WHEN SUM(final_status='BLOCKED') > 0 THEN 'BLOCKED'
                            WHEN SUM(final_status='QUARANTINED') > 0 THEN 'QUARANTINED'
                            WHEN SUM(final_status='SPAM') > 0 THEN 'QUARANTINED'
                            WHEN SUM(final_status='REJECTED') > 0 THEN 'REJECTED'
                            WHEN SUM(final_status='BOUNCED') > 0 THEN 'BOUNCED'
                            WHEN SUM(final_status='UNDELIVERED') > 0 THEN 'UNDELIVERED'
                            WHEN SUM(final_status='DEFERRED') > 0 THEN 'DEFERRED'
                            ELSE 'DELIVERED'
                        END AS queue_status,
                        GROUP_CONCAT(
                            CONCAT(
                                COALESCE(NULLIF(recipient,''), '-'),
                                '||', final_status,
                                '||', COALESCE(NULLIF(delivery_target,''), '-'),
                                '||', REPLACE(REPLACE(status_detail, '\\n', ' '), '\\r', ' ')
                            )
                            ORDER BY recipient SEPARATOR '##'
                        ) AS recipient_details
                    FROM postfix_delivery_final
                    {where}
                    GROUP BY queue_id
                    ORDER BY MAX(last_updated) DESC
                    LIMIT %(limit)s OFFSET %(offset)s
                    """,
                    params,
                )
                rows = cursor.fetchall()
                has_more = False
                if not include_total and len(rows) > size:
                    has_more = True
                    rows = rows[:size]

    for row in rows:
        row.pop("newest_update", None)
        row["recipients"] = []
        for item in (row.pop("recipient_details") or "").split("##"):
            if not item:
                continue
            parts = (item.split("||", 3) + ["", "", "", ""])[:4]
            row["recipients"].append({
                "recipient": parts[0],
                "status": parts[1],
                "delivery_target": parts[2],
                "status_detail": parts[3],
            })

    return {"rows": rows, "total": total, "has_more": has_more}

def report(limit, status, search, search_operator='contains', search_field='all', date_from='', date_to=''):
    clauses = []
    params = {"limit": limit}

    if status != "all":
        clauses.append("final_status = %(status)s")
        params["status"] = status

    if search:
        field_key = str(search_field or "all").strip().lower()
        field_map = {
            "all": ("queue_id", "sender", "recipient", "delivery_target", "status_detail"),
            "from": ("sender",),
            "to": ("recipient",),
        }
        if field_key not in field_map:
            raise ValueError("Invalid delivery search field")
        search_clause, search_value = _text_filter_clause(
            field_map[field_key],
            "s",
            search_operator,
            search,
        )
        clauses.append(search_clause)
        params["s"] = search_value

    if date_from:
        clauses.append(
            "STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s') >= %(date_from)s"
        )
        params["date_from"] = f"{date_from} 00:00:00"

    if date_to:
        clauses.append(
            "STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s') <= %(date_to)s"
        )
        params["date_to"] = f"{date_to} 23:59:59"

    where = "WHERE " + " AND ".join(clauses) if clauses else ""

    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT
                    log_timestamp AS timestamp,
                    queue_id,
                    message_size_bytes,
                    final_status,
                    sender,
                    recipient,
                    delivery_target,
                    status_detail
                FROM postfix_delivery_final
                {where}
                ORDER BY last_updated DESC
                LIMIT %(limit)s
                """,
                params,
            )
            return cursor.fetchall()

def stats():
    """
    Dashboard counters use distinct queue IDs so they match category filters.
    """
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(DISTINCT queue_id) AS total,
                    COUNT(DISTINCT CASE
                        WHEN final_status='DELIVERED' THEN queue_id
                    END) AS delivered,
                    COUNT(DISTINCT CASE
                        WHEN final_status='DEFERRED' THEN queue_id
                    END) AS deferred,
                    COUNT(DISTINCT CASE
                        WHEN final_status='BOUNCED' THEN queue_id
                    END) AS bounced,
                    COUNT(DISTINCT CASE
                        WHEN final_status='BLOCKED' THEN queue_id
                    END) AS blocked,
                    COUNT(DISTINCT CASE
                        WHEN final_status='QUARANTINED' THEN queue_id
                    END) AS spam,
                    COUNT(DISTINCT CASE
                        WHEN final_status='REJECTED' THEN queue_id
                    END) AS rejected,
                    COUNT(DISTINCT CASE
                        WHEN final_status='UNDELIVERED' THEN queue_id
                    END) AS undelivered
                FROM postfix_delivery_final
                """
            )
            return cursor.fetchone()

def cleanup(days):
    cutoff = datetime.now() - timedelta(days=days)

    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM postfix_delivery_final
                WHERE last_updated < %s
                """,
                (cutoff,),
            )
            deleted_final = cursor.rowcount

            cursor.execute(
                """
                DELETE FROM postfix_queue_metadata
                WHERE last_updated < %s
                """,
                (cutoff,),
            )
            deleted_metadata = cursor.rowcount

        connection.commit()

    return deleted_final + deleted_metadata


def purge_internal_reinjection_rows() -> int:
    """Delete historical internal Postfix/Amavis reinjection rows."""
    sql = """
    DELETE FROM postfix_delivery_final
    WHERE final_status = 'DELIVERED'
      AND (
          delivery_target LIKE '127.0.0.1[127.0.0.1]:10024%'
          OR delivery_target LIKE '127.0.0.1[127.0.0.1]:10025%'
          OR delivery_target LIKE '127.0.0.1[127.0.0.1]:10026%'
          OR delivery_target LIKE 'localhost[127.0.0.1]:10024%'
          OR delivery_target LIKE 'localhost[127.0.0.1]:10025%'
          OR delivery_target LIKE 'localhost[127.0.0.1]:10026%'
      )
      AND status_detail LIKE '%queued as%'
      AND (
          status_detail LIKE '%from MTA(%'
          OR service LIKE '%amavis%'
      )
    """

    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql)
            deleted = cursor.rowcount
        connection.commit()

    return deleted


def direction_summary(home_domains, date_from="", date_to=""):
    domains = [d.strip().lower().lstrip("@") for d in home_domains if d.strip()]
    if not domains:
        raise ValueError("HOME_DOMAINS is required")

    ph = ",".join(["%s"] * len(domains))
    params = domains * 8

    date_sql = ""
    if date_from:
        safe = date_from.replace("'", "")
        date_sql += (
            " AND STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s') "
            f">= '{safe} 00:00:00'"
        )
    if date_to:
        safe = date_to.replace("'", "")
        date_sql += (
            " AND STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s') "
            f"<= '{safe} 23:59:59'"
        )

    sql = f"""
    SELECT
      SUM(CASE
        WHEN LOWER(SUBSTRING_INDEX(sender,'@',-1)) IN ({ph})
         AND LOWER(SUBSTRING_INDEX(recipient,'@',-1)) NOT IN ({ph})
         AND sender LIKE '%%@%%' AND recipient LIKE '%%@%%'
        THEN 1 ELSE 0 END) home_to_external,
      SUM(CASE
        WHEN LOWER(SUBSTRING_INDEX(sender,'@',-1)) NOT IN ({ph})
         AND LOWER(SUBSTRING_INDEX(recipient,'@',-1)) IN ({ph})
         AND sender LIKE '%%@%%' AND recipient LIKE '%%@%%'
        THEN 1 ELSE 0 END) external_to_home,
      SUM(CASE
        WHEN LOWER(SUBSTRING_INDEX(sender,'@',-1)) IN ({ph})
         AND LOWER(SUBSTRING_INDEX(recipient,'@',-1)) IN ({ph})
         AND sender LIKE '%%@%%' AND recipient LIKE '%%@%%'
        THEN 1 ELSE 0 END) home_to_home,
      SUM(CASE
        WHEN LOWER(SUBSTRING_INDEX(sender,'@',-1)) NOT IN ({ph})
         AND LOWER(SUBSTRING_INDEX(recipient,'@',-1)) NOT IN ({ph})
         AND sender LIKE '%%@%%' AND recipient LIKE '%%@%%'
        THEN 1 ELSE 0 END) external_to_external,
      COUNT(DISTINCT NULLIF(LOWER(sender), '')) unique_senders,
      COUNT(DISTINCT NULLIF(LOWER(recipient), '')) unique_recipients,
      COUNT(*) total_recipient_records
    FROM postfix_delivery_final
    WHERE 1=1 {date_sql}
    """

    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            row = cursor.fetchone() or {}

    home_to_external = int(row.get("home_to_external") or 0)
    external_to_home = int(row.get("external_to_home") or 0)
    home_to_home = int(row.get("home_to_home") or 0)
    external_to_external = int(row.get("external_to_external") or 0)

    # Message/delivery counts shown in the UI. These are deliberately not
    # distinct-address counts: if the same sender sends 11 messages, all 11
    # are counted.
    emails_sent = home_to_external + home_to_home
    emails_received = external_to_home + home_to_home

    return {
        "home_domains": domains,
        "home_to_external": home_to_external,
        "external_to_home": external_to_home,
        "home_to_home": home_to_home,
        "external_to_external": external_to_external,
        "emails_sent": emails_sent,
        "emails_received": emails_received,
        # Retained for API/backward compatibility only. The Summary UI no
        # longer labels these as message counts.
        "unique_senders": int(row.get("unique_senders") or 0),
        "unique_recipients": int(row.get("unique_recipients") or 0),
        "total_recipient_records": int(row.get("total_recipient_records") or 0),
    }



def released_quarantine_count():
    """Persistent release count from MariaDB audit evidence; release is not delivery proof."""
    sql = "SELECT COUNT(DISTINCT pdp_id) AS released FROM dashboard_audit WHERE action='RELEASE' AND pdp_id <> ''"
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql)
            row = cursor.fetchone() or {}
    return int(row.get("released") or 0)


def ensure_bounce_projection():
    """One-time forward-only bootstrap of indexed bounce projection from existing final rows."""
    state_key = "r1.1.44-bounce-projection-v1"
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT state_value FROM postfix_bounce_projection_state WHERE state_key=%s",
                (state_key,),
            )
            if cursor.fetchone():
                return False
            cursor.execute(
                """
                INSERT IGNORE INTO postfix_bounce_projection (
                    delivery_id,event_date,queue_id,sender,recipient,sender_domain,recipient_domain,
                    log_timestamp,status_detail,last_updated
                )
                SELECT id,
                       DATE(STR_TO_DATE(log_timestamp,'%%Y %%b %%d %%H:%%i:%%s')),
                       queue_id,sender,recipient,
                       LOWER(SUBSTRING_INDEX(sender,'@',-1)),
                       LOWER(SUBSTRING_INDEX(recipient,'@',-1)),
                       log_timestamp,status_detail,last_updated
                FROM postfix_delivery_final
                WHERE final_status = 'BOUNCED'
                  AND LOCATE('@',sender)>0 AND LOCATE('@',recipient)>0
                """
            )
            cursor.execute(
                "INSERT INTO postfix_bounce_projection_state(state_key,state_value) VALUES(%s,'ready')",
                (state_key,),
            )
        connection.commit()
    return True


def _daily_bounce_projection_summary(home_domains, date_from="", date_to=""):
    domains = [d.strip().lower().lstrip("@") for d in home_domains if d.strip()]
    if not domains:
        raise ValueError("HOME_DOMAINS is required")
    ph = ",".join(["%s"] * len(domains))
    date_sql = ""
    date_params = []
    if date_from:
        date_sql += " AND event_date >= %s"
        date_params.append(date_from)
    if date_to:
        date_sql += " AND event_date <= %s"
        date_params.append(date_to)

    sql = f"""
    SELECT day_iso, DATE_FORMAT(day_iso,'%%d-%%m-%%Y') AS display_date, domain,
           SUM(sent) AS sent, SUM(received) AS received
    FROM (
        SELECT event_date AS day_iso, recipient_domain AS domain, COUNT(*) AS sent, 0 AS received
        FROM postfix_bounce_projection
        WHERE sender_domain IN ({ph}) AND recipient_domain NOT IN ({ph})
          AND sender_domain<>'' AND recipient_domain<>'' {date_sql}
        GROUP BY event_date, recipient_domain
        UNION ALL
        SELECT event_date AS day_iso, sender_domain AS domain, 0 AS sent, COUNT(*) AS received
        FROM postfix_bounce_projection
        WHERE sender_domain NOT IN ({ph}) AND recipient_domain IN ({ph})
          AND sender_domain<>'' AND recipient_domain<>'' {date_sql}
        GROUP BY event_date, sender_domain
    ) traffic
    WHERE day_iso IS NOT NULL AND domain<>''
    GROUP BY day_iso, domain
    ORDER BY day_iso DESC, (SUM(sent)+SUM(received)) DESC, domain ASC
    """
    branch_params = domains + domains + date_params
    params = branch_params + branch_params
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            rows = cursor.fetchall() or []
    return [
        {
            "date": row.get("display_date") or "",
            "date_iso": str(row.get("day_iso") or ""),
            "domain": row.get("domain") or "",
            "sent": int(row.get("sent") or 0),
            "received": int(row.get("received") or 0),
        }
        for row in rows
    ]


def daily_domain_summary(
    home_domains,
    date_from="",
    date_to="",
    status_filter="",
):
    """
    Return daily external-domain traffic:
      Sent     = home domain -> external domain
      Received = external domain -> home domain

    When status_filter is supplied, only that final_status is counted.
    """
    if str(status_filter or "").upper() == "BOUNCED":
        return _daily_bounce_projection_summary(home_domains, date_from, date_to)

    domains = [
        d.strip().lower().lstrip("@")
        for d in home_domains
        if d.strip()
    ]
    if not domains:
        raise ValueError("HOME_DOMAINS is required")

    ph = ",".join(["%s"] * len(domains))

    date_conditions = []
    date_params = []

    if date_from:
        date_conditions.append(
            "STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s') "
            ">= %s"
        )
        date_params.append(f"{date_from} 00:00:00")

    if date_to:
        date_conditions.append(
            "STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s') "
            "<= %s"
        )
        date_params.append(f"{date_to} 23:59:59")

    status_sql = ""
    status_params = []
    if status_filter:
        status_sql = " AND final_status = %s"
        status_params.append(status_filter)

    date_sql = ""
    if date_conditions:
        date_sql = " AND " + " AND ".join(date_conditions)

    parsed_ts = (
        "STR_TO_DATE(log_timestamp, "
        "'%%Y %%b %%d %%H:%%i:%%s')"
    )

    sql = f"""
    SELECT
        day_iso,
        DATE_FORMAT(
            STR_TO_DATE(day_iso, '%%Y-%%m-%%d'),
            '%%d-%%m-%%Y'
        ) AS display_date,
        domain,
        SUM(sent) AS sent,
        SUM(received) AS received
    FROM (
        SELECT
            DATE_FORMAT({parsed_ts}, '%%Y-%%m-%%d') AS day_iso,
            LOWER(SUBSTRING_INDEX(recipient, '@', -1)) AS domain,
            COUNT(*) AS sent,
            0 AS received
        FROM postfix_delivery_final
        WHERE
            LOCATE('@', sender) > 0
            AND LOCATE('@', recipient) > 0
            AND LOWER(SUBSTRING_INDEX(sender, '@', -1))
                IN ({ph})
            AND LOWER(SUBSTRING_INDEX(recipient, '@', -1))
                NOT IN ({ph})
            {status_sql}
            {date_sql}
        GROUP BY day_iso, domain

        UNION ALL

        SELECT
            DATE_FORMAT({parsed_ts}, '%%Y-%%m-%%d') AS day_iso,
            LOWER(SUBSTRING_INDEX(sender, '@', -1)) AS domain,
            0 AS sent,
            COUNT(*) AS received
        FROM postfix_delivery_final
        WHERE
            LOCATE('@', sender) > 0
            AND LOCATE('@', recipient) > 0
            AND LOWER(SUBSTRING_INDEX(sender, '@', -1))
                NOT IN ({ph})
            AND LOWER(SUBSTRING_INDEX(recipient, '@', -1))
                IN ({ph})
            {status_sql}
            {date_sql}
        GROUP BY day_iso, domain
    ) AS traffic
    WHERE domain <> ''
    GROUP BY day_iso, domain
    ORDER BY
        day_iso DESC,
        (SUM(sent) + SUM(received)) DESC,
        domain ASC
    """

    # Each UNION branch uses:
    #   domains twice + optional status + optional date params.
    branch_params = (
        domains
        + domains
        + status_params
        + date_params
    )
    params = branch_params + branch_params

    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            rows = cursor.fetchall() or []

    return [
        {
            "date": row.get("display_date") or "",
            "date_iso": row.get("day_iso") or "",
            "domain": row.get("domain") or "",
            "sent": int(row.get("sent") or 0),
            "received": int(row.get("received") or 0),
        }
        for row in rows
    ]



def bounced_domain_details(
    home_domains,
    date_iso,
    domain,
    direction,
):
    """
    Return individual BOUNCED rows for one daily-domain summary cell.

    direction=sent:
      home sender -> selected external recipient domain

    direction=received:
      selected external sender domain -> home recipient

    Postfix final-delivery logs do not contain the original RFC Subject header,
    so subject is returned as an empty string unless a future ingestion source
    stores it explicitly.
    """
    domains = [
        d.strip().lower().lstrip("@")
        for d in home_domains
        if d.strip()
    ]
    if not domains:
        raise ValueError("HOME_DOMAINS is required")

    date_iso = str(date_iso or "").strip()
    domain = str(domain or "").strip().lower().lstrip("@")
    direction = str(direction or "").strip().lower()

    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date_iso):
        raise ValueError("Invalid date")
    if not domain or "@" in domain or len(domain) > 255:
        raise ValueError("Invalid domain")
    if direction not in {"sent", "received"}:
        raise ValueError("Invalid direction")

    ph = ",".join(["%s"] * len(domains))

    if direction == "sent":
        direction_sql = f"sender_domain IN ({ph}) AND recipient_domain = %s"
        params = domains + [domain, date_iso]
    else:
        direction_sql = f"sender_domain = %s AND recipient_domain IN ({ph})"
        params = [domain] + domains + [date_iso]

    sql = f"""
    SELECT
        log_timestamp AS timestamp,
        sender,
        recipient,
        '' AS subject,
        status_detail AS bounce_reason,
        queue_id
    FROM postfix_bounce_projection
    WHERE {direction_sql}
      AND event_date = %s
    ORDER BY event_date DESC, queue_id DESC
    LIMIT 2000
    """

    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            rows = cursor.fetchall() or []

    return [
        {
            "date": row.get("timestamp") or "",
            "from": row.get("sender") or "",
            "to": row.get("recipient") or "",
            "subject": row.get("subject") or "",
            "reason": row.get("bounce_reason") or "",
            "queue_id": row.get("queue_id") or "",
        }
        for row in rows
    ]


def db_ready():
    """Return True when MariaDB accepts a trivial query."""
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 AS ok")
            row = cursor.fetchone()
    return bool(row and row.get("ok") == 1)


def _audit_hash(record):
    payload = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def audit_insert(
    timestamp,
    action,
    username="",
    client_ip="",
    pdp_id="",
    sender="",
    recipient="",
    subject="",
    category="",
    score="",
    detail="",
):
    record = {
        "timestamp": str(timestamp or ""),
        "action": str(action or "UNKNOWN").upper(),
        "username": str(username or ""),
        "client_ip": str(client_ip or ""),
        "pdp_id": str(pdp_id or ""),
        "sender": str(sender or ""),
        "recipient": str(recipient or ""),
        "subject": str(subject or ""),
        "category": str(category or ""),
        "score": str(score or ""),
        "detail": str(detail or ""),
    }
    event_hash = _audit_hash(record)
    sql = """
    INSERT IGNORE INTO dashboard_audit (
        event_hash,event_time,action,username,client_ip,pdp_id,
        sender,recipient,subject,category,score,detail
    ) VALUES (
        %(event_hash)s,
        COALESCE(STR_TO_DATE(%(timestamp)s, '%%Y-%%m-%%d %%H:%%i:%%s'), NOW()),
        %(action)s,%(username)s,%(client_ip)s,%(pdp_id)s,
        %(sender)s,%(recipient)s,%(subject)s,%(category)s,%(score)s,%(detail)s
    )
    """
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, {**record, "event_hash": event_hash})
        connection.commit()
    return event_hash


def audit_import_jsonl(path):
    """Idempotently migrate existing append-only JSONL audit records into MariaDB."""
    from pathlib import Path as _Path
    audit_path = _Path(path)
    if not audit_path.is_file():
        return 0
    sql = """
    INSERT IGNORE INTO dashboard_audit (
        event_hash,event_time,action,username,client_ip,pdp_id,
        sender,recipient,subject,category,score,detail
    ) VALUES (
        %(event_hash)s,
        COALESCE(STR_TO_DATE(%(timestamp)s, '%%Y-%%m-%%d %%H:%%i:%%s'), NOW()),
        %(action)s,%(username)s,%(client_ip)s,%(pdp_id)s,
        %(sender)s,%(recipient)s,%(subject)s,%(category)s,%(score)s,%(detail)s
    )
    """
    inserted = 0
    batch = []
    with conn() as connection:
        with connection.cursor() as cursor:
            with audit_path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    record = {
                        "timestamp": str(row.get("timestamp", "")),
                        "action": str(row.get("action", "UNKNOWN")).upper(),
                        "username": str(row.get("user", row.get("username", "")) or ""),
                        "client_ip": str(row.get("ip", row.get("client_ip", "")) or ""),
                        "pdp_id": str(row.get("pdp_id", "") or ""),
                        "sender": str(row.get("from", row.get("sender", "")) or ""),
                        "recipient": str(row.get("to", row.get("recipient", "")) or ""),
                        "subject": str(row.get("subject", "") or ""),
                        "category": str(row.get("category", "") or ""),
                        "score": str(row.get("score", "") or ""),
                        "detail": str(row.get("detail", "") or ""),
                    }
                    record["event_hash"] = _audit_hash(record)
                    batch.append(record)
                    if len(batch) >= 1000:
                        cursor.executemany(sql, batch)
                        inserted += max(0, cursor.rowcount)
                        batch.clear()
                if batch:
                    cursor.executemany(sql, batch)
                    inserted += max(0, cursor.rowcount)
            connection.commit()
    return inserted


def audit_records(q="", q_operator="contains", action="all", date_from="", date_to="", page=1, page_size=50):
    clauses = []
    params = {}
    q = (q or "").strip()
    action = (action or "all").strip().upper()
    if q:
        search_clause, search_value = _text_filter_clause(
            (
                "username",
                "client_ip",
                "pdp_id",
                "sender",
                "recipient",
                "subject",
                "detail",
            ),
            "q",
            q_operator,
            q,
        )
        clauses.append(search_clause)
        params["q"] = search_value
    if action != "ALL":
        clauses.append("action = %(action)s")
        params["action"] = action
    if date_from:
        clauses.append("event_time >= %(date_from)s")
        params["date_from"] = f"{date_from} 00:00:00"
    if date_to:
        clauses.append("event_time <= %(date_to)s")
        params["date_to"] = f"{date_to} 23:59:59"
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    params.update(limit=page_size, offset=(page - 1) * page_size)
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) AS total FROM dashboard_audit {where}", params)
            total = cursor.fetchone()["total"]
            cursor.execute(
                f"""
                SELECT DATE_FORMAT(event_time,'%%Y-%%m-%%d %%H:%%i:%%s') AS timestamp,
                       action, username AS user, client_ip AS ip, pdp_id,
                       sender AS `from`, recipient AS `to`, subject, category, score, detail
                FROM dashboard_audit
                {where}
                ORDER BY event_time DESC, id DESC
                LIMIT %(limit)s OFFSET %(offset)s
                """,
                params,
            )
            rows = cursor.fetchall()
    return {
        "rows": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


def queue_timeline(queue_id):
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT queue_id,sender,message_size_bytes,log_timestamp,raw_log,last_updated
                   FROM postfix_queue_metadata WHERE queue_id=%s""",
                (queue_id,),
            )
            metadata = cursor.fetchone()
            cursor.execute(
                """SELECT queue_id,recipient,sender,message_size_bytes,final_status,
                          delivery_target,status_detail,log_timestamp,host,service,
                          process_id,raw_log,first_seen,last_updated
                   FROM postfix_delivery_final
                   WHERE queue_id=%s
                   ORDER BY first_seen ASC,id ASC""",
                (queue_id,),
            )
            rows = cursor.fetchall()
    events = []
    if metadata:
        events.append({
            "stage": "QUEUE_METADATA",
            "timestamp": metadata.get("log_timestamp", ""),
            "status": "QUEUED",
            "sender": metadata.get("sender", ""),
            "recipient": "",
            "target": "",
            "detail": "Queue metadata captured",
            "raw_log": metadata.get("raw_log", ""),
        })
    for row in rows:
        events.append({
            "stage": row.get("service", "") or "POSTFIX",
            "timestamp": row.get("log_timestamp", ""),
            "status": row.get("final_status", ""),
            "sender": row.get("sender", ""),
            "recipient": row.get("recipient", ""),
            "target": row.get("delivery_target", ""),
            "detail": row.get("status_detail", ""),
            "raw_log": row.get("raw_log", ""),
        })
    return {"queue_id": queue_id, "metadata": metadata, "events": events}


def create_config_snapshot(username, label, config):
    label = str(label or "").strip()[:255]
    config = config if isinstance(config, dict) else {}
    config_json = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    fingerprint = hashlib.sha256(config_json.encode("utf-8")).hexdigest()
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO dashboard_config_snapshots
                    (username,label,fingerprint,config_json)
                VALUES (%s,%s,%s,%s)
                """,
                (str(username or "")[:128], label, fingerprint, config_json),
            )
            snapshot_id = int(cursor.lastrowid)
        connection.commit()
    return {"id": snapshot_id, "label": label, "fingerprint": fingerprint}


def list_config_snapshots(limit=20):
    limit = max(1, min(100, int(limit)))
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id,
                       DATE_FORMAT(snapshot_time,'%%Y-%%m-%%d %%H:%%i:%%s') AS snapshot_time,
                       username,label,fingerprint,config_json
                FROM dashboard_config_snapshots
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall() or []
    result=[]
    for row in rows:
        item=dict(row)
        try:
            item["config"] = json.loads(item.pop("config_json") or "{}")
        except Exception:
            item["config"] = {}
            item.pop("config_json", None)
        result.append(item)
    return result

# R1.1.18 Fix7: retained read-only Amavis log evidence.
AMAVIS_EVIDENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS amavis_log_evidence (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_hash CHAR(64) NOT NULL,
    event_time DATETIME NULL,
    timestamp_text VARCHAR(64) NOT NULL DEFAULT '',
    queue_id VARCHAR(64) NOT NULL DEFAULT '',
    release_queue_id VARCHAR(64) NOT NULL DEFAULT '',
    message_id VARCHAR(512) NOT NULL DEFAULT '',
    mail_id VARCHAR(128) NOT NULL DEFAULT '',
    sender VARCHAR(512) NOT NULL DEFAULT '',
    recipient TEXT NOT NULL,
    verdict VARCHAR(32) NOT NULL DEFAULT '',
    spam_score VARCHAR(64) NOT NULL DEFAULT '',
    quarantine_file VARCHAR(1024) NOT NULL DEFAULT '',
    raw_log TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_amavis_evidence_hash(event_hash),
    KEY idx_amavis_evidence_queue(queue_id),
    KEY idx_amavis_evidence_release_queue(release_queue_id),
    KEY idx_amavis_evidence_mail(mail_id),
    KEY idx_amavis_evidence_time(event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

def ensure_amavis_evidence_schema():
    with conn() as connection:
        with connection.cursor() as cursor:
            for statement in AMAVIS_EVIDENCE_SCHEMA.split(';'):
                if statement.strip(): cursor.execute(statement)
        connection.commit()

def store_amavis_evidence(raw_line, **fields):
    raw_line = str(raw_line or '').rstrip('\n')
    event_hash = hashlib.sha256(raw_line.encode('utf-8', 'replace')).hexdigest()
    sql = """INSERT IGNORE INTO amavis_log_evidence
      (event_hash,event_time,timestamp_text,queue_id,release_queue_id,message_id,mail_id,sender,recipient,verdict,spam_score,quarantine_file,raw_log)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    vals=(event_hash, fields.get('event_time'), fields.get('timestamp_text',''), fields.get('queue_id',''), fields.get('release_queue_id',''), fields.get('message_id',''), fields.get('mail_id',''), fields.get('sender',''), fields.get('recipient',''), fields.get('verdict',''), fields.get('spam_score',''), fields.get('quarantine_file',''), raw_line)
    with conn() as connection:
        with connection.cursor() as cursor: cursor.execute(sql, vals)
        connection.commit()

def find_amavis_evidence(tokens, limit=40):
    toks=[str(x or '').strip().strip('<>') for x in tokens if str(x or '').strip()][:8]
    if not toks: return []
    clauses=[]; args=[]
    for tok in toks:
        like='%'+tok+'%'; clauses.append('(queue_id=%s OR release_queue_id=%s OR mail_id=%s OR message_id=%s OR raw_log LIKE %s)'); args.extend([tok,tok,tok,tok,like])
    sql='SELECT * FROM amavis_log_evidence WHERE '+ ' OR '.join(clauses) +' ORDER BY id DESC LIMIT %s'; args.append(int(limit))
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql,args); return cursor.fetchall()


# R1.1.27: continuous, forward-only Amavis evidence repository.
# The production Amavis log remains read-only.  This schema is additive and does
# not alter or delete the legacy amavis_log_evidence table.
AMAVIS_CONTINUOUS_EVIDENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS amavis_log_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_path VARCHAR(1024) NOT NULL DEFAULT '',
    source_device BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_inode BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
    event_hash CHAR(64) NOT NULL,
    event_time DATETIME NULL,
    timestamp_text VARCHAR(64) NOT NULL DEFAULT '',
    session_id VARCHAR(64) NOT NULL DEFAULT '',
    queue_id VARCHAR(64) NOT NULL DEFAULT '',
    release_queue_id VARCHAR(64) NOT NULL DEFAULT '',
    message_id VARCHAR(512) NOT NULL DEFAULT '',
    mail_id VARCHAR(128) NOT NULL DEFAULT '',
    sender VARCHAR(512) NOT NULL DEFAULT '',
    recipient TEXT NOT NULL,
    verdict VARCHAR(64) NOT NULL DEFAULT '',
    spam_score VARCHAR(64) NOT NULL DEFAULT '',
    quarantine_file VARCHAR(1024) NOT NULL DEFAULT '',
    virus_name VARCHAR(512) NOT NULL DEFAULT '',
    banned_name VARCHAR(512) NOT NULL DEFAULT '',
    attachment_evidence TEXT NOT NULL,
    raw_log LONGTEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_amavis_log_coordinate(source_device, source_inode, source_offset),
    KEY idx_amavis_events_queue(queue_id),
    KEY idx_amavis_events_release_queue(release_queue_id),
    KEY idx_amavis_events_mail(mail_id),
    KEY idx_amavis_events_message(message_id(191)),
    KEY idx_amavis_events_session(session_id),
    KEY idx_amavis_events_time(event_time),
    KEY idx_amavis_events_hash(event_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS amavis_log_ingest_state (
    source_key VARCHAR(191) PRIMARY KEY,
    source_path VARCHAR(1024) NOT NULL DEFAULT '',
    source_device BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_inode BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_offset BIGINT UNSIGNED NOT NULL DEFAULT 0,
    source_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'INITIALIZING',
    last_error TEXT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS amavis_attachment_history (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    source_event_hash CHAR(64) NOT NULL,
    event_time DATETIME NULL,
    session_id VARCHAR(64) NOT NULL DEFAULT '',
    queue_id VARCHAR(64) NOT NULL DEFAULT '',
    release_queue_id VARCHAR(64) NOT NULL DEFAULT '',
    message_id VARCHAR(512) NOT NULL DEFAULT '',
    mail_id VARCHAR(128) NOT NULL DEFAULT '',
    quarantine_file VARCHAR(1024) NOT NULL DEFAULT '',
    attachment_name VARCHAR(1024) NOT NULL DEFAULT '',
    evidence_type VARCHAR(64) NOT NULL DEFAULT 'LOG_ATTACHMENT',
    content_text LONGTEXT NOT NULL,
    raw_log LONGTEXT NOT NULL,
    attachment_hash CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_amavis_attachment_event_hash(source_event_hash, attachment_hash),
    KEY idx_amavis_attach_mail_id(mail_id, id),
    KEY idx_amavis_attach_queue_id(queue_id, id),
    KEY idx_amavis_attach_release_id(release_queue_id, id),
    KEY idx_amavis_attach_message_id(message_id(191), id),
    KEY idx_amavis_attach_session_id(session_id, id),
    KEY idx_amavis_attach_quarantine(quarantine_file(191), id),
    KEY idx_amavis_attach_time_id(event_time, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

def get_amavis_ingest_state(source_key):
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM amavis_log_ingest_state WHERE source_key=%s', (str(source_key),))
            return cursor.fetchone() or None

def set_amavis_ingest_state(source_key, source_path, device, inode, offset, size, status='RUNNING', last_error=''):
    sql = """INSERT INTO amavis_log_ingest_state
      (source_key,source_path,source_device,source_inode,source_offset,source_size,status,last_error)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
      ON DUPLICATE KEY UPDATE source_path=VALUES(source_path),source_device=VALUES(source_device),
      source_inode=VALUES(source_inode),source_offset=VALUES(source_offset),source_size=VALUES(source_size),
      status=VALUES(status),last_error=VALUES(last_error),updated_at=CURRENT_TIMESTAMP(6)"""
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, (str(source_key),str(source_path),int(device),int(inode),int(offset),int(size),str(status),str(last_error or '')[:4000]))
        connection.commit()

def store_amavis_events_batch(events):
    if not events:
        return 0
    sql = """INSERT IGNORE INTO amavis_log_events
      (source_path,source_device,source_inode,source_offset,event_hash,event_time,timestamp_text,session_id,
       queue_id,release_queue_id,message_id,mail_id,sender,recipient,verdict,spam_score,quarantine_file,
       virus_name,banned_name,attachment_evidence,raw_log)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    vals=[]
    for e in events:
        vals.append((e.get('source_path',''),int(e.get('source_device',0)),int(e.get('source_inode',0)),int(e.get('source_offset',0)),
          e.get('event_hash',''),e.get('event_time'),e.get('timestamp_text',''),e.get('session_id',''),e.get('queue_id',''),
          e.get('release_queue_id',''),e.get('message_id',''),e.get('mail_id',''),e.get('sender',''),e.get('recipient',''),
          e.get('verdict',''),e.get('spam_score',''),e.get('quarantine_file',''),e.get('virus_name',''),e.get('banned_name',''),
          e.get('attachment_evidence',''),e.get('raw_log','')))
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.executemany(sql, vals)
            affected=cursor.rowcount
        connection.commit()
    # Attachment/archive content reported by Amavis is persisted separately for
    # historical viewing. Failure here must not roll back the primary log event.
    try:
        store_amavis_attachment_history_batch(events)
    except Exception:
        pass
    return max(0, int(affected or 0))

def _attachment_rows_from_event(event):
    """Return normalized, log-derived attachment/archive evidence for one Amavis event.

    No attachment file is opened and no archive is extracted.  content_text is the
    Amavis-reported descriptor/content fragment and raw_log preserves the source line.
    """
    raw=str(event.get('raw_log') or '')
    names=[]
    direct=str(event.get('attachment_evidence') or '').strip()
    if direct:
        names.extend([x.strip() for x in direct.split('|') if x.strip()])
    # Common Amavis/decoder forms, including archive members when Amavis prints them.
    patterns=(
        r"(?:name|filename)=['\"]?([^,'\";]+)",
        r"(?:archive member|member name|part name)[:=]\s*['\"]?([^,'\";]+)",
        r"(?:BANNED name|banned name)[:=]\s*['\"]?([^,'\";]+)",
    )
    for pattern in patterns:
        for value in re.findall(pattern, raw, re.I):
            value=str(value or '').strip()
            if value:
                names.append(value)
    # Some attachment/archive evidence lines do not expose a parseable filename.
    attachmentish=bool(re.search(r'attachment|filename=|name=|archive|\bp\d{3}\b|mime part|banned name', raw, re.I))
    if not names and not attachmentish:
        return []
    names=list(dict.fromkeys(names)) or ['(log-derived attachment content)']
    rows=[]
    for name in names[:64]:
        content=raw[:16000]
        ah=hashlib.sha256((name+'\0'+content).encode('utf-8','replace')).hexdigest()
        rows.append({
            'source_event_hash':str(event.get('event_hash') or ''),
            'event_time':event.get('event_time'),
            'session_id':str(event.get('session_id') or ''),
            'queue_id':str(event.get('queue_id') or ''),
            'release_queue_id':str(event.get('release_queue_id') or ''),
            'message_id':str(event.get('message_id') or ''),
            'mail_id':str(event.get('mail_id') or ''),
            'quarantine_file':str(event.get('quarantine_file') or ''),
            'attachment_name':name[:1024],
            'evidence_type':'AMAVIS_LOG_CONTENT',
            'content_text':content,
            'raw_log':raw[:65535],
            'attachment_hash':ah,
        })
    return rows

def store_amavis_attachment_history_batch(events):
    rows=[]
    for event in events or []:
        rows.extend(_attachment_rows_from_event(event))
    if not rows:
        return 0
    sql="""INSERT IGNORE INTO amavis_attachment_history
      (source_event_hash,event_time,session_id,queue_id,release_queue_id,message_id,mail_id,quarantine_file,
       attachment_name,evidence_type,content_text,raw_log,attachment_hash)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    vals=[(r['source_event_hash'],r['event_time'],r['session_id'],r['queue_id'],r['release_queue_id'],r['message_id'],
           r['mail_id'],r['quarantine_file'],r['attachment_name'],r['evidence_type'],r['content_text'],r['raw_log'],r['attachment_hash'])
          for r in rows]
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.executemany(sql, vals)
            affected=cursor.rowcount
        connection.commit()
    return max(0,int(affected or 0))

def backfill_amavis_attachment_history(limit=5000):
    """Forward-only bounded backfill from retained amavis_log_events into attachment history."""
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""SELECT e.* FROM amavis_log_events e
                LEFT JOIN amavis_attachment_history a ON a.source_event_hash=e.event_hash
                WHERE a.id IS NULL AND (e.attachment_evidence<>'' OR e.raw_log REGEXP 'attachment|filename=|name=|archive|p[0-9][0-9][0-9]|mime part|banned name')
                ORDER BY e.id DESC LIMIT %s""", (int(limit),))
            events=cursor.fetchall() or []
    return store_amavis_attachment_history_batch(events)

def find_current_amavis_attachment_history(*, session_ids=None, mail_id='', queue_id='', release_queue_id='', message_id='', quarantine_file='', limit=100):
    clauses=[]; args=[]
    sessions=[str(x or '').strip() for x in (session_ids or []) if str(x or '').strip()]
    if sessions:
        clauses.append('session_id IN ('+','.join(['%s']*len(sessions))+')'); args.extend(sessions)
    # Use exact message identifiers only; never sender-only matching.
    for col,val in (('mail_id',mail_id),('queue_id',queue_id),('release_queue_id',release_queue_id),('message_id',message_id),('quarantine_file',quarantine_file)):
        val=str(val or '').strip().strip('<>')
        if val:
            clauses.append(col+'=%s'); args.append(val)
    if not clauses:
        return []
    sql='SELECT * FROM amavis_attachment_history WHERE ('+' OR '.join(clauses)+') ORDER BY id ASC LIMIT %s'
    args.append(int(limit))
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql,args)
            return cursor.fetchall() or []

def get_ai_trainer_status_snapshot(generation_id):
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT generation_id,dataset_samples,ham_labels,spam_labels,hard_ham_labels,legacy_feature_labels,dataset_mtime_ns,dataset_size,updated_at "
                "FROM ai_trainer_status_snapshot WHERE generation_id=%s LIMIT 1",
                (str(generation_id or ''),),
            )
            return cursor.fetchone()


def replace_ai_trainer_status_snapshot(*, generation_id, dataset_samples, ham_labels, spam_labels, hard_ham_labels, legacy_feature_labels, dataset_mtime_ns, dataset_size):
    sql = """
    INSERT INTO ai_trainer_status_snapshot
      (generation_id,dataset_samples,ham_labels,spam_labels,hard_ham_labels,legacy_feature_labels,dataset_mtime_ns,dataset_size)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    ON DUPLICATE KEY UPDATE
      dataset_samples=VALUES(dataset_samples),
      ham_labels=VALUES(ham_labels),
      spam_labels=VALUES(spam_labels),
      hard_ham_labels=VALUES(hard_ham_labels),
      legacy_feature_labels=VALUES(legacy_feature_labels),
      dataset_mtime_ns=VALUES(dataset_mtime_ns),
      dataset_size=VALUES(dataset_size),
      updated_at=CURRENT_TIMESTAMP(6)
    """
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, (str(generation_id or ''), int(dataset_samples or 0), int(ham_labels or 0), int(spam_labels or 0), int(hard_ham_labels or 0), int(legacy_feature_labels or 0), int(dataset_mtime_ns or 0), int(dataset_size or 0)))
        connection.commit()


def record_ai_ground_truth_history(*, source_sha256, pdp_id, label, classification='', review_reason='', reviewer='', label_source='admin-ground-truth', generation_id='', feature_schema=0):
    """Persist immutable label history; only one CURRENT row per message is maintained logically."""
    source_sha256=str(source_sha256 or '').strip()
    if not source_sha256:
        raise ValueError('source_sha256 is required')
    label=str(label or '').upper()
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id,label,reversal_count FROM ai_ground_truth_history WHERE source_sha256=%s AND status='CURRENT' ORDER BY id DESC LIMIT 1 FOR UPDATE",
                (source_sha256,),
            )
            prev=cursor.fetchone() or {}
            previous_label=str(prev.get('label') or '')
            reversal_count=int(prev.get('reversal_count') or 0)
            if previous_label and previous_label != label:
                reversal_count += 1
            if prev.get('id'):
                cursor.execute("UPDATE ai_ground_truth_history SET status='SUPERSEDED' WHERE id=%s", (prev['id'],))
            cursor.execute(
                """INSERT INTO ai_ground_truth_history
                (source_sha256,pdp_id,label,classification,review_reason,reviewer,label_source,status,previous_label,reversal_count,generation_id,feature_schema)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'CURRENT',%s,%s,%s,%s)""",
                (source_sha256,str(pdp_id or ''),label,str(classification or ''),str(review_reason or '')[:512],str(reviewer or ''),str(label_source or ''),previous_label,reversal_count,str(generation_id or ''),int(feature_schema or 0)),
            )
            row_id=cursor.lastrowid
        connection.commit()
    return {'id': row_id, 'previous_label': previous_label, 'reversal_count': reversal_count, 'reversed': bool(previous_label and previous_label != label)}

def record_ai_ground_truth_calibration(*, source_sha256, pdp_id='', ai_proposed_label='', ai_proposed_classification='', ai_confidence=None, admin_final_label='', admin_final_classification='', admin_acknowledged_ai=False, reviewer='', generation_id='', candidate_version='', fraud_repo_version=''):
    sql="""INSERT INTO ai_ground_truth_calibration
      (source_sha256,pdp_id,ai_proposed_label,ai_proposed_classification,ai_confidence,admin_final_label,admin_final_classification,admin_acknowledged_ai,reviewer,generation_id,candidate_version,fraud_repo_version)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    vals=(str(source_sha256 or ''),str(pdp_id or ''),str(ai_proposed_label or ''),str(ai_proposed_classification or ''),ai_confidence,str(admin_final_label or ''),str(admin_final_classification or ''),bool(admin_acknowledged_ai),str(reviewer or ''),str(generation_id or ''),str(candidate_version or ''),str(fraud_repo_version or ''))
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql,vals); row_id=cursor.lastrowid
        connection.commit()
    return row_id

def store_ai_conflict_investigation(*, source_sha256, pdp_id='', candidate_version='', candidate_algorithm='', ai_prediction='', admin_label='', classification='', confidence=None, probabilities=None, forensic=None, root_cause='', review_status='OPEN'):
    sql="""INSERT INTO ai_conflict_investigations
      (source_sha256,pdp_id,candidate_version,candidate_algorithm,ai_prediction,admin_label,classification,confidence,probabilities_json,forensic_json,root_cause,review_status)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
    vals=(str(source_sha256 or ''),str(pdp_id or ''),str(candidate_version or ''),str(candidate_algorithm or ''),str(ai_prediction or ''),str(admin_label or ''),str(classification or ''),confidence,json.dumps(probabilities or {},sort_keys=True),json.dumps(forensic or {},sort_keys=True),str(root_cause or '')[:512],str(review_status or 'OPEN'))
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, vals); row_id=cursor.lastrowid
        connection.commit()
    return row_id

def ai_ground_truth_current(source_sha256):
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM ai_ground_truth_history WHERE source_sha256=%s AND status='CURRENT' ORDER BY id DESC LIMIT 1", (str(source_sha256 or ''),))
            return cursor.fetchone() or None

def recent_ai_conflicts(limit=50):
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,pdp_id,candidate_version,ai_prediction,admin_label,classification,confidence,root_cause,review_status,created_at FROM ai_conflict_investigations ORDER BY id DESC LIMIT %s", (int(limit),))
            return cursor.fetchall() or []



def get_postfix_ingest_state(source_key):
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM postfix_log_ingest_state WHERE source_key=%s", (str(source_key),))
            return cursor.fetchone() or None


def set_postfix_ingest_state(source_key, source_path, device, inode, offset, size, status='RUNNING', last_error=''):
    sql = """INSERT INTO postfix_log_ingest_state
        (source_key,source_path,source_device,source_inode,source_offset,source_size,status,last_error)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE source_path=VALUES(source_path),source_device=VALUES(source_device),
        source_inode=VALUES(source_inode),source_offset=VALUES(source_offset),source_size=VALUES(source_size),
        status=VALUES(status),last_error=VALUES(last_error),updated_at=CURRENT_TIMESTAMP(6)"""
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql,(str(source_key),str(source_path),int(device),int(inode),int(offset),int(size),str(status),str(last_error)))
        connection.commit()


def postfix_delivery_projection_has_rows():
    """Cheap bootstrap guard for in-place upgrades with an existing populated projection."""
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 AS present FROM postfix_delivery_final LIMIT 1")
            return bool(cursor.fetchone())


def store_postfix_raw_events_batch(source_key, source_path, device, inode, events):
    """Persist immutable raw Postfix lines idempotently. events=(offset, raw_line)."""
    rows=[]
    for offset, raw_line in events:
        raw=str(raw_line or '').rstrip('\n')
        if not raw:
            continue
        digest=hashlib.sha256((f"{source_key}|{int(device)}|{int(inode)}|{int(offset)}|"+raw).encode('utf-8','replace')).hexdigest()
        rows.append((str(source_key),str(source_path),int(device),int(inode),int(offset),raw,digest))
    if not rows:
        return 0
    sql="""INSERT IGNORE INTO postfix_log_events
        (source_key,source_path,source_device,source_inode,source_offset,raw_log,event_sha256)
        VALUES(%s,%s,%s,%s,%s,%s,%s)"""
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.executemany(sql,rows)
            inserted=cursor.rowcount
        connection.commit()
    return int(inserted or 0)



def ai_ti_store_observation(row):
    """Idempotently persist privacy-reduced local campaign/infrastructure metadata."""
    sql = """INSERT INTO ai_message_intelligence_observations
      (source_sha256,source_kind,source_id,message_id,sender_domain,reply_domain,return_path_domain,message_id_domain,
       source_ip,observed_reverse_name,observed_helo,asn,asn_organization,spf_result,dkim_result,dmarc_result,
       template_hash,body_structure_hash,url_domain_set_hash,attachment_set_hash,sender_path_hash,campaign_hash,
       url_domain_count,attachment_count)
      VALUES(%(source_sha256)s,%(source_kind)s,%(source_id)s,%(message_id)s,%(sender_domain)s,%(reply_domain)s,%(return_path_domain)s,%(message_id_domain)s,
       %(source_ip)s,%(observed_reverse_name)s,%(observed_helo)s,%(asn)s,%(asn_organization)s,%(spf_result)s,%(dkim_result)s,%(dmarc_result)s,
       %(template_hash)s,%(body_structure_hash)s,%(url_domain_set_hash)s,%(attachment_set_hash)s,%(sender_path_hash)s,%(campaign_hash)s,
       %(url_domain_count)s,%(attachment_count)s)
      ON DUPLICATE KEY UPDATE source_kind=VALUES(source_kind),source_id=VALUES(source_id),message_id=VALUES(message_id),
       sender_domain=VALUES(sender_domain),reply_domain=VALUES(reply_domain),return_path_domain=VALUES(return_path_domain),
       message_id_domain=VALUES(message_id_domain),source_ip=VALUES(source_ip),observed_reverse_name=VALUES(observed_reverse_name),
       observed_helo=VALUES(observed_helo),asn=VALUES(asn),asn_organization=VALUES(asn_organization),spf_result=VALUES(spf_result),
       dkim_result=VALUES(dkim_result),dmarc_result=VALUES(dmarc_result),template_hash=VALUES(template_hash),
       body_structure_hash=VALUES(body_structure_hash),url_domain_set_hash=VALUES(url_domain_set_hash),
       attachment_set_hash=VALUES(attachment_set_hash),sender_path_hash=VALUES(sender_path_hash),campaign_hash=VALUES(campaign_hash),
       url_domain_count=VALUES(url_domain_count),attachment_count=VALUES(attachment_count),last_seen=CURRENT_TIMESTAMP(6)"""
    clean = {k: row.get(k) for k in (
        'source_sha256','source_kind','source_id','message_id','sender_domain','reply_domain','return_path_domain','message_id_domain',
        'source_ip','observed_reverse_name','observed_helo','asn','asn_organization','spf_result','dkim_result','dmarc_result',
        'template_hash','body_structure_hash','url_domain_set_hash','attachment_set_hash','sender_path_hash','campaign_hash',
        'url_domain_count','attachment_count')}
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql, clean)
            changed = cursor.rowcount
        connection.commit()
    return int(changed or 0)


def ai_ti_campaign_stats(*, template_hash='', campaign_hash='', url_set_hash='', sender_domain='', source_ip='', asn=0, window_days=30):
    since = max(1, min(3650, int(window_days)))
    result = {
        'template_messages': 0, 'template_distinct_sender_domains': 0,
        'template_distinct_source_ips': 0, 'template_distinct_asns': 0,
        'campaign_messages': 0, 'urlset_messages': 0,
    }
    with conn() as connection:
        with connection.cursor() as cursor:
            if template_hash:
                cursor.execute("""SELECT COUNT(*) AS messages,COUNT(DISTINCT NULLIF(sender_domain,'')) AS sender_domains,
                    COUNT(DISTINCT NULLIF(source_ip,'')) AS source_ips,COUNT(DISTINCT asn) AS asns
                    FROM ai_message_intelligence_observations
                    WHERE template_hash=%s AND last_seen >= NOW() - INTERVAL %s DAY""", (str(template_hash), since))
                row=cursor.fetchone() or {}
                result.update(template_messages=int(row.get('messages') or 0), template_distinct_sender_domains=int(row.get('sender_domains') or 0),
                              template_distinct_source_ips=int(row.get('source_ips') or 0), template_distinct_asns=int(row.get('asns') or 0))
            if campaign_hash:
                cursor.execute("SELECT COUNT(*) AS total FROM ai_message_intelligence_observations WHERE campaign_hash=%s AND last_seen >= NOW() - INTERVAL %s DAY", (str(campaign_hash), since))
                result['campaign_messages']=int((cursor.fetchone() or {}).get('total') or 0)
            if url_set_hash:
                cursor.execute("SELECT COUNT(*) AS total FROM ai_message_intelligence_observations WHERE url_domain_set_hash=%s AND last_seen >= NOW() - INTERVAL %s DAY", (str(url_set_hash), since))
                result['urlset_messages']=int((cursor.fetchone() or {}).get('total') or 0)
    return result


def ai_ti_infrastructure_stats(*, source_ip='', asn=0, sender_domain='', window_days=30):
    since = max(1, min(3650, int(window_days)))
    result={'source_ip_messages':0,'asn_messages':0,'sender_domain_messages':0,'sender_domain_distinct_ips':0,'sender_domain_distinct_asns':0}
    with conn() as connection:
        with connection.cursor() as cursor:
            if source_ip:
                cursor.execute("SELECT COUNT(*) AS total FROM ai_message_intelligence_observations WHERE source_ip=%s AND last_seen >= NOW() - INTERVAL %s DAY",(str(source_ip),since))
                result['source_ip_messages']=int((cursor.fetchone() or {}).get('total') or 0)
            if asn:
                cursor.execute("SELECT COUNT(*) AS total FROM ai_message_intelligence_observations WHERE asn=%s AND last_seen >= NOW() - INTERVAL %s DAY",(int(asn),since))
                result['asn_messages']=int((cursor.fetchone() or {}).get('total') or 0)
            if sender_domain:
                cursor.execute("""SELECT COUNT(*) AS total,COUNT(DISTINCT NULLIF(source_ip,'')) AS ips,COUNT(DISTINCT asn) AS asns
                    FROM ai_message_intelligence_observations WHERE sender_domain=%s AND last_seen >= NOW() - INTERVAL %s DAY""",(str(sender_domain),since))
                row=cursor.fetchone() or {}
                result['sender_domain_messages']=int(row.get('total') or 0)
                result['sender_domain_distinct_ips']=int(row.get('ips') or 0)
                result['sender_domain_distinct_asns']=int(row.get('asns') or 0)
    return result


def ai_ti_status():
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total,MIN(first_seen) AS first_seen,MAX(last_seen) AS last_seen FROM ai_message_intelligence_observations")
            row=cursor.fetchone() or {}
    return {'engine_version':'local-ti-v1','shadow_only':True,'network_lookup':False,'observations':int(row.get('total') or 0),'first_seen':row.get('first_seen'),'last_seen':row.get('last_seen')}

FRAUD_REPO_PREVIOUS_SEED = "LEGACY_ARCHIVED_NO_LONGER_BUNDLED"

def _fraud_repo_seed_path():
    from pathlib import Path
    override=str(os.getenv('FRAUD_REPO_SEED_FILE','')).strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / 'local-email-intelligence-repo' / 'local-email-intelligence-2026.09.03-v1.json'

def seed_fraud_repository():
    """Idempotently inject bundled curated intelligence into the EXISTING DB."""
    path=_fraud_repo_seed_path()
    if not path.is_file():
        return {'ok':False,'reason':'seed file missing'}
    raw=path.read_bytes(); repo_sha=hashlib.sha256(raw).hexdigest(); payload=json.loads(raw.decode('utf-8'))
    version=str(payload.get('version') or '').strip()
    if not version:
        raise ValueError('Fraud repository version is missing')
    inserted=skipped=0
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""INSERT INTO fraud_repo_versions(repo_version,description,source_policy,repo_sha256,active)
                VALUES(%s,%s,%s,%s,TRUE) ON DUPLICATE KEY UPDATE description=VALUES(description),source_policy=VALUES(source_policy),repo_sha256=VALUES(repo_sha256)""",
                (version,str(payload.get('description') or ''),str(payload.get('source_policy') or ''),repo_sha))
            # Preserve older repository rows for audit but make bundled version current.
            cursor.execute("UPDATE fraud_repo_versions SET active=(repo_version=%s)",(version,))
            for code,label,desc,severity in payload.get('taxonomies',[]):
                cursor.execute("""INSERT INTO fraud_taxonomy(taxonomy_code,label,description,severity_default,training_authority)
                    VALUES(%s,%s,%s,%s,FALSE) ON DUPLICATE KEY UPDATE label=VALUES(label),description=VALUES(description),severity_default=VALUES(severity_default)""",
                    (code,label,desc,severity))
            for item in payload.get('patterns',[]):
                spec={k:item.get(k) for k in ('phrases','min_hits','structural_any') if k in item}
                spec_json=json.dumps(spec,sort_keys=True,separators=(',',':'))
                entry_hash=hashlib.sha256(json.dumps(item,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                cursor.execute("SELECT id FROM fraud_intent_patterns WHERE repo_version=%s AND entry_hash=%s LIMIT 1",(version,entry_hash))
                if cursor.fetchone():
                    skipped+=1; continue
                cursor.execute("""INSERT INTO fraud_intent_patterns
                    (repo_version,taxonomy_code,pattern_key,title,pattern_json,weight,suggested_classification,explanation,source_type,training_authority,enabled,entry_hash)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'LOCAL_RULE_BASE',FALSE,TRUE,%s)""",
                    (version,item.get('taxonomy',''),item.get('key',''),item.get('title',''),spec_json,float(item.get('weight') or 1),item.get('classification','OTHER_SPAM'),item.get('explanation',''),entry_hash))
                inserted+=1
            for item in payload.get('counter_evidence',[]):
                eh=hashlib.sha256(json.dumps(item,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                cursor.execute("""INSERT IGNORE INTO fraud_counter_evidence(repo_version,evidence_key,description,weight,entry_hash) VALUES(%s,%s,%s,%s,%s)""",
                    (version,item.get('key',''),item.get('description',''),float(item.get('weight') or -1),eh))
            for item in payload.get('regression_cases',[]):
                eh=hashlib.sha256(json.dumps(item,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                cursor.execute("""INSERT IGNORE INTO fraud_regression_cases(repo_version,case_key,expected_classification,sample_text,entry_hash) VALUES(%s,%s,%s,%s,%s)""",
                    (version,item.get('case',''),item.get('expected',''),item.get('text',''),eh))
            for item in payload.get('external_sources',[]):
                metadata_sha=hashlib.sha256(json.dumps(item,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                cursor.execute("""INSERT INTO fraud_corpus_sources
                    (source_key,name,category,source_uri,license_note,safety_mode,enabled,training_authority,metadata_sha256)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,FALSE,%s)
                    ON DUPLICATE KEY UPDATE name=VALUES(name),category=VALUES(category),source_uri=VALUES(source_uri),license_note=VALUES(license_note),safety_mode=VALUES(safety_mode),enabled=VALUES(enabled),training_authority=FALSE,metadata_sha256=VALUES(metadata_sha256)""",
                    (item.get('source_key',''),item.get('name',''),item.get('category',''),item.get('source_uri',''),item.get('license_note',''),item.get('safety_mode','OFFLINE_PARSE_ONLY'),bool(item.get('enabled',False)),metadata_sha))
            cursor.execute("""INSERT INTO fraud_repo_import_audit(repo_version,repo_sha256,inserted_patterns,skipped_patterns,status,detail) VALUES(%s,%s,%s,%s,'OK',%s)""",
                (version,repo_sha,inserted,skipped,'Forward-only idempotent seed; no existing production rows deleted or replaced.'))
        connection.commit()
    return {'ok':True,'version':version,'sha256':repo_sha,'inserted_patterns':inserted,'skipped_patterns':skipped}

def fraud_repo_status():
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT repo_version,repo_sha256,imported_at FROM fraud_repo_versions WHERE active=TRUE ORDER BY id DESC LIMIT 1")
            row=cursor.fetchone() or {}
            version=str(row.get('repo_version') or '')
            count=0
            if version:
                cursor.execute("SELECT COUNT(*) AS total FROM fraud_intent_patterns WHERE repo_version=%s AND enabled=TRUE",(version,))
                count=int((cursor.fetchone() or {}).get('total') or 0)
    return {'active_version':version,'repo_sha256':row.get('repo_sha256',''),'imported_at':row.get('imported_at'),'entry_count':count}

def fraud_repo_patterns(repo_version=''):
    version=str(repo_version or '').strip()
    with conn() as connection:
        with connection.cursor() as cursor:
            if not version:
                cursor.execute("SELECT repo_version FROM fraud_repo_versions WHERE active=TRUE ORDER BY id DESC LIMIT 1")
                version=str((cursor.fetchone() or {}).get('repo_version') or '')
            if not version:
                return []
            cursor.execute("""SELECT taxonomy_code,pattern_key,title,pattern_json,weight,suggested_classification,explanation
                FROM fraud_intent_patterns WHERE repo_version=%s AND enabled=TRUE ORDER BY taxonomy_code,id""",(version,))
            return cursor.fetchall() or []


def ensure_monitor_summary_projection():
    """Forward-only bootstrap of the login-summary projection.

    The raw mail_login_events table remains the audit source of truth.  This
    projection is built once for an in-place upgrade and is then maintained in
    the same transaction as newly inserted login events.
    """
    state_key = "r1.1.42-login-user-summary-v1"
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT state_value FROM mail_login_summary_state WHERE state_key=%s",
                (state_key,),
            )
            if cursor.fetchone():
                return False
            cursor.execute("""
                INSERT INTO mail_login_user_summary
                  (protocol,username,success_count,failed_count,total_events,last_login,
                   last_ip,last_country,last_city,last_asn,last_organization)
                SELECT protocol,
                       username,
                       SUM(status='SUCCESS') AS success_count,
                       SUM(status='FAILED') AS failed_count,
                       COUNT(*) AS total_events,
                       MAX(event_time) AS last_login,
                       SUBSTRING_INDEX(GROUP_CONCAT(remote_ip ORDER BY event_time DESC,id DESC SEPARATOR '||'),'||',1) AS last_ip,
                       SUBSTRING_INDEX(GROUP_CONCAT(country ORDER BY event_time DESC,id DESC SEPARATOR '||'),'||',1) AS last_country,
                       SUBSTRING_INDEX(GROUP_CONCAT(city ORDER BY event_time DESC,id DESC SEPARATOR '||'),'||',1) AS last_city,
                       CAST(NULLIF(SUBSTRING_INDEX(GROUP_CONCAT(COALESCE(asn,'') ORDER BY event_time DESC,id DESC SEPARATOR '||'),'||',1),'') AS UNSIGNED) AS last_asn,
                       SUBSTRING_INDEX(GROUP_CONCAT(organization ORDER BY event_time DESC,id DESC SEPARATOR '||'),'||',1) AS last_organization
                FROM mail_login_events
                WHERE username<>''
                GROUP BY protocol,username
                ON DUPLICATE KEY UPDATE
                  success_count=VALUES(success_count),
                  failed_count=VALUES(failed_count),
                  total_events=VALUES(total_events),
                  last_login=VALUES(last_login),
                  last_ip=VALUES(last_ip),
                  last_country=VALUES(last_country),
                  last_city=VALUES(last_city),
                  last_asn=VALUES(last_asn),
                  last_organization=VALUES(last_organization)
            """)
            cursor.execute(
                "INSERT INTO mail_login_summary_state(state_key,state_value) VALUES(%s,'ready')",
                (state_key,),
            )
        connection.commit()
    return True

# R1.1.29: forward-only index tuning for current-message Amavis correlation and hot delivery views.
# Index creation is conditional through INFORMATION_SCHEMA so in-place upgrades are idempotent.
R1129_INDEX_SPECS = {
    'amavis_log_events': {
        'idx_amavis_mail_id_id': 'ALTER TABLE amavis_log_events ADD KEY idx_amavis_mail_id_id (mail_id, id)',
        'idx_amavis_queue_id_id': 'ALTER TABLE amavis_log_events ADD KEY idx_amavis_queue_id_id (queue_id, id)',
        'idx_amavis_release_queue_id_id': 'ALTER TABLE amavis_log_events ADD KEY idx_amavis_release_queue_id_id (release_queue_id, id)',
        'idx_amavis_message_id_id': 'ALTER TABLE amavis_log_events ADD KEY idx_amavis_message_id_id (message_id(191), id)',
        'idx_amavis_session_id_id': 'ALTER TABLE amavis_log_events ADD KEY idx_amavis_session_id_id (session_id, id)',
        'idx_amavis_quarantine_id': 'ALTER TABLE amavis_log_events ADD KEY idx_amavis_quarantine_id (quarantine_file(191), id)',
        'idx_amavis_event_time_id': 'ALTER TABLE amavis_log_events ADD KEY idx_amavis_event_time_id (event_time, id)',
    },
    'amavis_attachment_history': {
        'idx_amavis_attach_mail_id': 'ALTER TABLE amavis_attachment_history ADD KEY idx_amavis_attach_mail_id (mail_id, id)',
        'idx_amavis_attach_queue_id': 'ALTER TABLE amavis_attachment_history ADD KEY idx_amavis_attach_queue_id (queue_id, id)',
        'idx_amavis_attach_release_id': 'ALTER TABLE amavis_attachment_history ADD KEY idx_amavis_attach_release_id (release_queue_id, id)',
        'idx_amavis_attach_message_id': 'ALTER TABLE amavis_attachment_history ADD KEY idx_amavis_attach_message_id (message_id(191), id)',
        'idx_amavis_attach_session_id': 'ALTER TABLE amavis_attachment_history ADD KEY idx_amavis_attach_session_id (session_id, id)',
        'idx_amavis_attach_time_id': 'ALTER TABLE amavis_attachment_history ADD KEY idx_amavis_attach_time_id (event_time, id)',
    },
    'mail_login_events': {
        'idx_mail_login_protocol_time_id': 'ALTER TABLE mail_login_events ADD KEY idx_mail_login_protocol_time_id (protocol, event_time, id)',
    },
    'postfix_delivery_final': {
        'idx_delivery_status_updated': 'ALTER TABLE postfix_delivery_final ADD KEY idx_delivery_status_updated (final_status, last_updated)',
        'idx_delivery_queue_updated': 'ALTER TABLE postfix_delivery_final ADD KEY idx_delivery_queue_updated (queue_id, last_updated)',
        'idx_delivery_updated_queue': 'ALTER TABLE postfix_delivery_final ADD KEY idx_delivery_updated_queue (last_updated, queue_id)',
    },
    'dashboard_audit': {
        'idx_audit_pdp_time': 'ALTER TABLE dashboard_audit ADD KEY idx_audit_pdp_time (pdp_id(191), event_time)',
        'idx_audit_action_time': 'ALTER TABLE dashboard_audit ADD KEY idx_audit_action_time (action, event_time)',
    },
}

def ensure_r1129_indexes():
    """Add only missing secondary indexes; never rebuild/reset application tables."""
    applied=[]
    with conn() as connection:
        with connection.cursor() as cursor:
            for table, specs in R1129_INDEX_SPECS.items():
                cursor.execute(
                    "SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s",
                    (table,),
                )
                existing={str(r.get('INDEX_NAME') or '') for r in (cursor.fetchall() or [])}
                for name, ddl in specs.items():
                    if name in existing:
                        continue
                    cursor.execute(ddl)
                    applied.append(f'{table}.{name}')
        connection.commit()
    return applied

def find_current_amavis_trace(*, mail_id='', queue_id='', release_queue_id='', message_id='', quarantine_file='', limit=80):
    """Return only the trace correlated to one message using indexed exact identifiers.

    Correlation priority is mail_id -> Queue-ID/release Queue-ID -> Message-ID ->
    quarantine path.  No sender-only or broad raw-log match is used.  Once a seed
    event is found, only the same Amavis session(s) are expanded.
    """
    ids={
        'mail_id': str(mail_id or '').strip().strip('<>'),
        'queue_id': str(queue_id or '').strip().strip('<>'),
        'release_queue_id': str(release_queue_id or '').strip().strip('<>'),
        'message_id': str(message_id or '').strip().strip('<>'),
        'quarantine_file': str(quarantine_file or '').strip(),
    }
    priority=[
        ('mail_id', 'mail_id=%s'),
        ('queue_id', '(queue_id=%s OR release_queue_id=%s)'),
        ('release_queue_id', '(release_queue_id=%s OR queue_id=%s)'),
        ('message_id', 'message_id=%s'),
        ('quarantine_file', '(quarantine_file=%s OR quarantine_file LIKE %s)'),
    ]
    seed=[]; matched_by=''
    with conn() as connection:
        with connection.cursor() as cursor:
            for key, clause in priority:
                value=ids.get(key,'')
                if not value:
                    continue
                if key in {'queue_id','release_queue_id'}:
                    args=[value,value,int(limit)]
                elif key=='quarantine_file':
                    args=[value,'%/'+value,int(limit)]
                else:
                    args=[value,int(limit)]
                cursor.execute('SELECT * FROM amavis_log_events WHERE '+clause+' ORDER BY id DESC LIMIT %s', args)
                seed=cursor.fetchall() or []
                if seed:
                    matched_by=key
                    break
            if not seed:
                return {'rows': [], 'matched_by': ''}
            sessions=[]
            for row in seed:
                sid=str(row.get('session_id') or '')
                if sid and sid not in sessions:
                    sessions.append(sid)
            expanded=[]
            if sessions:
                placeholders=','.join(['%s']*len(sessions))
                cursor.execute(
                    'SELECT * FROM amavis_log_events WHERE session_id IN ('+placeholders+') ORDER BY id DESC LIMIT %s',
                    sessions+[int(limit)],
                )
                expanded=cursor.fetchall() or []
    merged=[]; seen=set()
    for row in list(seed)+list(expanded):
        rid=row.get('id')
        if rid in seen:
            continue
        seen.add(rid); merged.append(row)
    merged.sort(key=lambda r:int(r.get('id') or 0))
    return {'rows': merged[:int(limit)], 'matched_by': matched_by}

def find_continuous_amavis_evidence(tokens, limit=80):
    toks=[str(x or '').strip().strip('<>') for x in tokens if str(x or '').strip()][:10]
    if not toks:
        return []
    clauses=[]; args=[]
    for tok in toks:
        like='%'+tok+'%'
        clauses.append('(queue_id=%s OR release_queue_id=%s OR mail_id=%s OR message_id=%s OR raw_log LIKE %s)')
        args.extend([tok,tok,tok,tok,like])
    sql='SELECT * FROM amavis_log_events WHERE '+ ' OR '.join(clauses) +' ORDER BY id DESC LIMIT %s'
    args.append(int(limit))
    with conn() as connection:
        with connection.cursor() as cursor:
            cursor.execute(sql,args)
            seed=cursor.fetchall() or []
            sessions=[]
            for r in seed:
                sid=str(r.get('session_id') or '')
                if sid and sid not in sessions:
                    sessions.append(sid)
            if sessions:
                placeholders=','.join(['%s']*len(sessions))
                cursor.execute('SELECT * FROM amavis_log_events WHERE session_id IN ('+placeholders+') ORDER BY id DESC LIMIT %s', sessions+[int(limit)])
                expanded=cursor.fetchall() or []
            else:
                expanded=[]
    merged=[]; seen=set()
    for row in list(seed)+list(expanded):
        rid=row.get('id')
        if rid in seen: continue
        seen.add(rid); merged.append(row)
    merged.sort(key=lambda r:int(r.get('id') or 0), reverse=True)
    return merged[:int(limit)]
