from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/'app/main.py').read_text()
db=(ROOT/'app/db.py').read_text()
compose=(ROOT/'docker-compose.yaml').read_text()
env=(ROOT/'.env.example').read_text()

assert 'CREATE TABLE IF NOT EXISTS amavis_log_events' in db
assert 'CREATE TABLE IF NOT EXISTS amavis_log_ingest_state' in db
assert 'UNIQUE KEY uq_amavis_log_coordinate' in db
assert 'def store_amavis_events_batch' in db
assert 'def find_continuous_amavis_evidence' in db
assert 'def amavis_evidence_follow' in main
assert "threading.Thread(target=amavis_evidence_follow, daemon=True).start()" in main
assert ("find_continuous_amavis_evidence(tokens,80)" in main or "find_current_amavis_trace(" in main)
assert "initial_full_import" in main
assert "Do not advance the MariaDB checkpoint after a failed batch" in main
assert 'MariaDB continuous evidence' in main
assert 'Database storage' in main and 'Ingest status' in main
assert '${AMAVIS_LOG_DIR:-/var/lib/amavis/logs}:/host-amavis/logs:ro' in compose
assert 'AMAVIS_LOG_DIR=/var/lib/amavis/logs' in env
assert 'AMAVIS_LOG_FILE' not in compose
# Production log remains read-only and the stable app image name remains unchanged.
assert 'postfix-delivery-dashboard:m7' in compose
assert ':/host-amavis/logs:ro' in compose
# No destructive database lifecycle commands in the implementation.
for forbidden in ('DROP TABLE amavis_log','TRUNCATE TABLE amavis_log','DELETE FROM amavis_log_events'):
    assert forbidden not in db
print('R1.1.27 continuous Amavis MariaDB evidence regression passed')
