from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/"app/main.py").read_text(); compose=(root/"docker-compose.yaml").read_text(); db=(root/"app/db.py").read_text(); env=(root/".env.example").read_text()
assert 'data-tab="monitorTab"' in main
assert '/api/monitor/pop3-logins' in main and '/api/monitor/roundcube-logins' in main
assert 'require_permission("monitor", "view")' in main
assert 'DOVECOT_MAIL_LOG_FILE:-/var/log/mail.log' in compose
assert 'ROUNDCUBE_LOGIN_LOG_FILE:-/var/lib/roundcube/logs/userlogins.log' in compose
assert '/host-dovecot/mail.log:ro' in compose and '/host-roundcube/userlogins.log:ro' in compose

# group_add defaults must remain unique after Compose variable expansion.
assert 'MONITOR_MAIL_LOG_GID' not in compose
assert compose.count('${AMAVIS_LOG_GID:-4}') == 1
assert compose.count('${ROUNDCUBE_LOG_GID:-33}') == 1
assert '"monitor"' in db
assert 'Monitor</h3>' in main
assert 'Amavis Global W/B' not in main
assert not (root/'app/amavis_wb.py').exists()
print("R1.1.16 Monitor login regression passed.")
