from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")
sess=Path("app/session_auth.py").read_text(encoding="utf-8")
compose=Path("docker-compose.yaml").read_text(encoding="utf-8")
env=Path(".env.example").read_text(encoding="utf-8")

assert "LOGIN_RATE_LIMIT_ATTEMPTS" in main
assert "LOGIN_RATE_LIMIT_LOCKOUT_SECONDS" in main
assert 'status_code=429' in main
assert '"Retry-After"' in main

assert "ABSOLUTE_TIMEOUT_HOURS" in sess
assert "ABSOLUTE_TIMEOUT_SECONDS" in sess
assert "now - session.created_at > ABSOLUTE_TIMEOUT_SECONDS" in sess
assert "max_age=SESSION_ABSOLUTE_TIMEOUT_SECONDS" in main

assert '@app.middleware("http")' in main
assert "csrf_origin_guard" in main
assert '"x-postfix-dashboard"' in main
assert '"Invalid request origin"' in main

assert '@app.get("/health/ready")' in main
assert '@app.get("/api/system/ready")' in main
public=main.split('@app.get("/health/ready")',1)[1].split('@app.get("/api/system/ready")',1)[0]
assert '"checks"' not in public
assert "active_sessions" not in public
assert 'apiFetch("/api/system/ready")' in main

refresh=main.split('@app.post("/api/quarantine/refresh")',1)[1].split('@app.post("/api/quarantine/learn")',1)[0]
assert "detail=str(exc)" not in refresh
assert "Quarantine refresh failed; see server logs for details" in refresh

assert "image: postfix-delivery-dashboard:m7" in compose
assert "SESSION_ABSOLUTE_TIMEOUT_HOURS" in compose
assert "LOGIN_RATE_LIMIT_ATTEMPTS" in compose
assert "SESSION_COOKIE_SECURE=" in env

# Quarantine layout and Amavis action structure must remain unchanged.
assert "Milestone 6 baseline: exact five-column quarantine alignment" in main
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main
assert 'class="qrow-select"' in main
assert 'class="qactionbox"' in main

print("Milestone 5 Security Pack 1 regression test passed")
