from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")
db=Path("app/db.py").read_text(encoding="utf-8")

assert "CREATE TABLE IF NOT EXISTS dashboard_users" in db
assert "hashlib.pbkdf2_hmac" in db
assert "hmac.compare_digest" in db
assert "260000" in db
assert "ensure_bootstrap_user" in main
assert "authenticate_dashboard_user" in main

for area in ("delivery","summary","quarantine","system","audit","mail_flow"):
    assert area in db

assert 'data-tab="aclTab"' in main
assert 'data-tab="helpTab"' in main
assert '<div id="aclTab" class="tabpane">' in main
assert '<div id="helpTab" class="tabpane">' in main
assert "/api/admin/users" in main
assert "/api/me" in main
assert 'Depends(require_permission("quarantine", "admin"))' in main
assert 'Depends(require_permission("quarantine", "view"))' in main
assert 'Depends(require_permission("mail_flow", "view"))' in main
assert "Administrator access required" in main
assert "You cannot delete your own account" in main
assert "You cannot disable or remove your own administrator role" in main

# Quarantine layout remains unchanged.
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main
assert "Spam Score rule hover" in main

print("Milestone 5 User ACL + Help regression test passed")
