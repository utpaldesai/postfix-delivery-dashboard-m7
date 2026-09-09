from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")
quarantine=Path("app/quarantine.py").read_text(encoding="utf-8")
compose=Path("docker-compose.yaml").read_text(encoding="utf-8")
env=Path(".env.example").read_text(encoding="utf-8")
helper=Path("host-tools/mail-size-api.php").read_text(encoding="utf-8")

# Dashboard/quarantine user access is session + ACL, not source-IP allowlisting.
assert "quarantine_ip_allowed" not in main
assert "Client IP not allowed for quarantine management" not in main
assert "def ip_allowed(" not in quarantine
assert "QUARANTINE_ALLOWED_IPS" not in quarantine
assert "QUARANTINE_ALLOWED_IPS" not in compose
assert "QUARANTINE_ALLOWED_IPS" not in env
assert 'return request.client.host if request.client else ""' in main

# Quarantine endpoints still require RBAC.
assert 'Depends(require_permission("quarantine", "view"))' in main
assert 'Depends(require_permission("quarantine", "admin"))' in main
assert 'Depends(require_permission("audit", "view"))' in main

# Backend-only Mail Size helper remains loopback-restricted.
assert "Loopback access required" in helper
assert "127.0.0.1" in helper

print("Milestone 5 dashboard IP allowlist removal regression test passed")
