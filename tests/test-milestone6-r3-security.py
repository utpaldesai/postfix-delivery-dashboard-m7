from pathlib import Path

compose = Path("docker-compose.yaml").read_text(encoding="utf-8")
session = Path("app/session_auth.py").read_text(encoding="utf-8")
db = Path("app/db.py").read_text(encoding="utf-8")
wrapper = Path("amavisd-release-wrapper.py").read_text(encoding="utf-8")
env_example = Path(".env.example").read_text(encoding="utf-8")


def require(text, haystack):
    assert text in haystack, text


# Controlled HTTP deployment: Secure cookie must remain configurable and default false.
require("SESSION_COOKIE_SECURE: ${SESSION_COOKIE_SECURE:-false}", compose)
require('os.getenv("SESSION_COOKIE_SECURE", "false")', session)
require("SESSION_COOKIE_SECURE=false", env_example)

# Preserve the existing password-hash contract. Raising this in place would invalidate
# hashes because the current schema does not store per-user PBKDF2 iteration counts.
require('hashlib.pbkdf2_hmac(', db)
require('"sha256"', db)
require('260000', db)

# Container hardening and bounded resources.
require("read_only: true", compose)
require("no-new-privileges:true", compose)
require("cap_drop:", compose)
require("- ALL", compose)
require("pids_limit: ${APP_PIDS_LIMIT:-256}", compose)
require("/tmp:rw,noexec,nosuid,size=256m,mode=1777", compose)
require('group_add:', compose)
require('${AMAVIS_GID:-130}', compose)
require(':/host-amavis/virusmails:ro', compose)

# Repeated release fix: no fixed stale 0400 runtime path; unique temp file and cleanup.
require('tempfile.mkstemp(prefix="amavisd-release-runtime-", dir="/tmp")', wrapper)
require('["perl", "-T", str(TARGET)', wrapper)
require('finally:', wrapper)
require('TARGET.unlink(missing_ok=True)', wrapper)

print("Milestone 6 R3 security compatibility test passed")
