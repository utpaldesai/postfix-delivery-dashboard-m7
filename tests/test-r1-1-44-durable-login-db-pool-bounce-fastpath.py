from pathlib import Path
import tempfile
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
db = (root / 'app/db.py').read_text(encoding='utf-8')
mon = (root / 'app/monitor.py').read_text(encoding='utf-8')
main = (root / 'app/main.py').read_text(encoding='utf-8')
compose = (root / 'docker-compose.yaml').read_text(encoding='utf-8')

# Additive forward-only schemas.
assert 'CREATE TABLE IF NOT EXISTS mail_login_ingest_state' in db
assert 'CREATE TABLE IF NOT EXISTS postfix_bounce_projection' in db
assert 'CREATE TABLE IF NOT EXISTS postfix_bounce_projection_state' in db
assert 'DROP TABLE' not in '\n'.join(x for x in db.splitlines() if 'r1.1.44' in x.lower())

# Durable login ingestion: no repeated tail scanner in active path.
assert 'def _read_incremental(' in mon
assert 'source_device' in db and 'source_inode' in db and 'source_offset' in db
assert 'adopt_existing_eof' in mon
assert 'bootstrap_tail' in mon
assert 'rotated' in mon and 'file_shrunk' in mon
assert 'def _read_tail(' not in mon
assert '_existing_hashes' in mon
assert '_enrich_new_events' in mon
assert 'sync_login_events()\n    summary' not in mon

# Parser must not perform GEO enrichment before deduplication.
from app import monitor
orig_geo = monitor._geo
monitor._geo = lambda ip: (_ for _ in ()).throw(AssertionError('parser must not GEO-enrich'))
try:
    events = monitor.parse_dovecot_events([
        'Sep  7 10:00:01 host dovecot: pop3-login: Login: user=<a@example.test>, method=PLAIN, rip=8.8.8.8, lip=10.0.0.1'
    ])
    assert len(events) == 1 and events[0]['country'] == ''
finally:
    monitor._geo = orig_geo

# Incremental reader reads only appended bytes when a durable state exists.
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / 'mail.log'
    p.write_bytes(b'old-line\nnew-line\n')
    old_load = monitor._load_ingest_state
    old_hist = monitor._source_has_history
    try:
        monitor._load_ingest_state = lambda key: {
            'source_device': p.stat().st_dev,
            'source_inode': p.stat().st_ino,
            'source_offset': len(b'old-line\n'),
        }
        monitor._source_has_history = lambda source: True
        lines, info, next_offset = monitor._read_incremental('dovecot-pop3', 'dovecot', p)
        assert lines == ['new-line']
        assert info['mode'] == 'append'
        assert next_offset == p.stat().st_size
    finally:
        monitor._load_ingest_state = old_load
        monitor._source_has_history = old_hist

# Central dashboard DB uses bounded reusable connections rather than connect/close per query.
assert 'class _ConnectionPool' in db
assert 'DB_POOL_SIZE' in db
assert '_DB_POOL.acquire()' in db and '_DB_POOL.release(connection)' in db
assert 'connection = pymysql.connect(**CFG)\n    try:\n        yield connection\n    finally:\n        connection.close()' not in db
assert 'DB_POOL_SIZE: ${DB_POOL_SIZE:-8}' in compose

# Bounced summary and detail use the indexed bounce projection.
assert 'def _daily_bounce_projection_summary' in db
assert "FROM postfix_bounce_projection" in db
assert 'idx_bounce_sender_day_domain' in db
assert 'idx_bounce_recipient_day_domain' in db
assert 'if str(status_filter or "").upper() == "BOUNCED"' in db
assert 'R1.1.44 serves bounce summary and drill-down' in main
assert 'durable MariaDB device/inode/byte-offset checkpoints' in main

print('R1.1.44 durable login ingestion / DB pool / bounce fast-path regression passed.')
