from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")
db=Path("app/db.py").read_text(encoding="utf-8")
compose=Path("docker-compose.yaml").read_text(encoding="utf-8")
env=Path(".env.example").read_text(encoding="utf-8")
helper=Path("host-tools/mail-size-api.php").read_text(encoding="utf-8")

assert '"mail_size",' in db
assert 'data-tab="mailSizeTab"' in main
assert '<div id="mailSizeTab" class="tabpane">' in main
assert 'id="mailSizeServices"' not in main
assert 'id="mailSizeOutlook"' in main
assert 'id="mailSizeWebmail"' in main
assert 'id="mailSizeBackups"' in main
assert 'id="mailSizeAudit"' in main

assert '@app.get("/api/mail-size/status")' in main
assert '@app.post("/api/mail-size/limit")' in main
assert '@app.post("/api/mail-size/revert")' in main
assert 'Depends(require_permission("mail_size", "admin"))' in main

assert 'MAIL_SIZE_API_URL:' in compose
assert 'MAIL_SIZE_API_KEY:' in compose
assert 'MAIL_SIZE_API_URL=' in env
assert 'MAIL_SIZE_API_KEY=' in env

# Native page: no external page iframe.
assert 'id="mailSizeFrame"' not in main
assert 'MAIL_SIZE_MANAGER_URL' not in main
assert 'openMailSizeExternal' not in main

# Host helper retains restricted deploy architecture.
assert "127.0.0.1" in helper
assert "HTTP_X_MAIL_SIZE_KEY" in helper
assert "sudo /usr/local/bin/deploy_postfix.sh" in helper
assert "/etc/postfix/master.cf" in helper
assert "/var/lib/postfix-web/backups/" in helper

# Mail Size remains before System Status.
assert main.index('data-tab="mailSizeTab"') < main.index('data-tab="systemTab"')
assert main.index('<div id="mailSizeTab"') < main.index('<div id="systemTab"')

# Privileged tab only.
assert 'else if(area==="mail_size") allowed=canAccess("mail_size","admin");' in main

print("Milestone 5 native Mail Size tab regression test passed")
