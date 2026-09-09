from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MAIN=(ROOT/'app/main.py').read_text()
DB=(ROOT/'app/db.py').read_text()
SPAM=(ROOT/'app/spam_lists.py').read_text()
COMPOSE=(ROOT/'docker-compose.yaml').read_text()
assert 'R18.5 Operational Safety & Administration Pack' in MAIN
assert 'dashboard_config_snapshots' in DB
assert 'create_config_snapshot' in DB and 'list_config_snapshots' in DB
assert '@app.get("/api/system/operations")' in MAIN
assert '@app.post("/api/system/config-snapshots")' in MAIN
assert 'password_configured' in MAIN and 'key_configured' in MAIN
assert 'SPAM_PREF_DB_PASSWORD' not in MAIN[MAIN.index('def _safe_dashboard_config'):MAIN.index('def _config_diff')].replace('os.getenv("SPAM_PREF_DB_PASSWORD", "")','')
assert 'conflict_summary' in SPAM
assert '@app.get("/api/spam-lists/conflicts")' in MAIN
assert MAIN.index('@app.get("/api/spam-lists/conflicts")') < MAIN.index('@app.post("/api/spam-lists/{prefid}")')
assert 'SPAMLIST_CONFLICT_CHECK' in MAIN
assert 'CONFIG_SNAPSHOT_CREATE' in MAIN
assert 'Operational Safety' in MAIN
assert 'Review Conflicts' in MAIN
assert 'MAIL_SIZE_API_URL' in COMPOSE
assert (ROOT/'host-tools/mail-size-api.php').exists()
print('R18.5 Operational Safety pack PASS')
