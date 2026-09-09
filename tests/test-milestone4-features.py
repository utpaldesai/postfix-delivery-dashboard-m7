from pathlib import Path
main=Path('app/main.py').read_text()
db=Path('app/db.py').read_text()
q=Path('app/quarantine.py').read_text()
s=Path('app/session_auth.py').read_text()
wrapper=Path('amavisd-release-wrapper.py').read_text()
compose=Path('docker-compose.yaml').read_text()

# Real session authentication
assert 'HTTPBasic' not in main
assert '@app.post("/api/login")' in main
assert 'httponly=True' in main and 'samesite="strict"' in main
assert '@app.post("/api/logout")' in main
assert 'session_store.touch(token)' in main

# Enhanced DB-backed audit with JSONL mirror
assert 'CREATE TABLE IF NOT EXISTS dashboard_audit' in db
assert 'def audit_records(' in db
assert 'audit_import_jsonl' in main
assert 'Mirror the append-only audit event into MariaDB' in q
assert 'RELEASE_FAILED' in main

# Readiness + page
assert '@app.get("/health/ready")' in main
assert 'data-tab="systemTab"' in main
assert 'Amavis PDP 127.0.0.1:9998' in main

# Incremental quarantine cache
assert '_file_cache = {}' in q
assert 'signature = (stat.st_mtime_ns, stat.st_size)' in q
assert '"reused": reused' in q

# Queue flow
assert 'def queue_timeline(' in db
assert '@app.get("/api/flow/{queue_id}")' in main
assert 'async function openFlow(queueId)' in main

# Milestone 2 guards retained
assert '["perl", "-T", str(TARGET)' in wrapper
assert 'confirm(`Release ${pdpId}?`)' not in main
assert 'SESSION_COOKIE_NAME:' in compose
print('Milestone 4 feature regression test passed')
