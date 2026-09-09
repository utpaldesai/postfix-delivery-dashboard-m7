from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text(encoding='utf-8')
db=(root/'app/db.py').read_text(encoding='utf-8')
mon=(root/'app/monitor.py').read_text(encoding='utf-8')
compose=(root/'docker-compose.yaml').read_text(encoding='utf-8')
assert 'CREATE TABLE IF NOT EXISTS mail_login_events' in db
assert 'UNIQUE KEY uq_mail_login_event_hash' in db
assert '/api/monitor/summary' in main and '/api/monitor/user-history' in main
assert 'POP3 Login Summary' in main and 'data-monitor-protocol="IMAP"' not in main and 'Webmail' in main
assert 'parse_dovecot_events' in mon and 'imap-login' not in mon and 'intentionally ignored' in mon and 'enrich_ip' in mon
assert 'offline-mmdb' in (root/'app/geoip_intelligence.py').read_text(encoding='utf-8')
assert '.side-nav{flex:1 1 auto!important;min-height:0!important;overflow-y:auto!important' in main
assert '.sidebar{overflow:hidden!important}' in main
assert 'from .amavis_wb import' not in main and not (root/'app/amavis_wb.py').exists()
assert 'image: postfix-delivery-dashboard:m7' in compose
print('R1.1.17 Monitor DB/GEO/sidebar regression passed.')
