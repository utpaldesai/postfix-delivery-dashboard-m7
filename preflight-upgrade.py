#!/usr/bin/env python3
"""Non-destructive deployment preflight for R6.5 Fix 1."""
from __future__ import annotations
from pathlib import Path
import sys

from scripts.env_value import parse_env

ROOT = Path(__file__).resolve().parent
ENV = ROOT / ".env"
DBDIR = ROOT / "data" / "mariadb"

errors: list[str] = []
if not ENV.exists():
    errors.append(".env is missing")
    env = {}
else:
    env = parse_env(ENV)


def first(*keys: str) -> str:
    for key in keys:
        value = env.get(key, "").strip()
        if value:
            return value
    return ""


def populated(path: Path) -> bool:
    if not path.exists():
        return False
    return any(p.name != "lost+found" for p in path.iterdir())

existing_db = populated(DBDIR)
db_name = first("DB_NAME", "MYSQL_DATABASE")
db_user = first("DB_USER", "MYSQL_USER")
db_password = first("DB_PASSWORD", "MYSQL_PASSWORD")
db_root_password = first("DB_ROOT_PASSWORD", "MYSQL_ROOT_PASSWORD")
home_domains = first("HOME_DOMAINS")

if not db_name:
    errors.append("DB_NAME is missing (legacy MYSQL_DATABASE is also accepted)")
if not db_user:
    errors.append("DB_USER is missing (legacy MYSQL_USER is also accepted)")
if not db_password:
    errors.append("DB_PASSWORD is missing (legacy MYSQL_PASSWORD is also accepted)")
if not db_root_password:
    errors.append("DB_ROOT_PASSWORD is missing (legacy MYSQL_ROOT_PASSWORD is also accepted)")
if not home_domains:
    errors.append("HOME_DOMAINS is missing; no production fallback is permitted")

placeholder_values = {
    "change-db-password",
    "change-root-password",
    "change-web-password",
    "change-spam-pref-db-password",
    "example.com",
    "change-home-domain.example",
}
for label, value in (
    ("DB_PASSWORD", db_password),
    ("DB_ROOT_PASSWORD", db_root_password),
    ("WEB_PASSWORD", first("WEB_PASSWORD")),
    ("SPAM_PREF_DB_PASSWORD", first("SPAM_PREF_DB_PASSWORD")),
    ("HOME_DOMAINS", home_domains),
):
    if value in placeholder_values:
        errors.append(f"{label} still contains an example/default value")

if not first("WEB_PASSWORD"):
    errors.append("WEB_PASSWORD is missing")

if existing_db and not db_name:
    errors.append("Existing MariaDB data detected but database identity cannot be resolved")

if errors:
    print("DEPLOYMENT PREFLIGHT FAILED - NOTHING HAS BEEN CHANGED")
    for error in errors:
        print(f" - {error}")
    if existing_db:
        print(f"Protected existing MariaDB directory: {DBDIR}")
    sys.exit(1)

print("DEPLOYMENT PREFLIGHT PASSED")
if existing_db:
    print(f"Existing populated MariaDB data detected and protected: {DBDIR}")
    print("Database preservation mode: no reinitialization, no volume deletion, no forced DB recreation")
else:
    print("No existing populated MariaDB directory detected (fresh-install mode)")
print(f"Resolved database name: {db_name}")
print(f"Configured HOME_DOMAINS entries: {len([d for d in home_domains.split(',') if d.strip()])}")
