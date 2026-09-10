from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
db=(ROOT/'app/db.py').read_text()
main=(ROOT/'app/main.py').read_text()
compose=(ROOT/'docker-compose.yaml').read_text()

assert 'CREATE TABLE IF NOT EXISTS amavis_attachment_history' in db
assert 'UNIQUE KEY uq_amavis_attachment_event_hash' in db
for idx in ('idx_amavis_attach_mail_id','idx_amavis_attach_queue_id','idx_amavis_attach_release_id','idx_amavis_attach_message_id','idx_amavis_attach_session_id','idx_amavis_attach_time_id'):
    assert idx in db
assert 'store_amavis_attachment_history_batch(events)' in db
assert 'backfill_amavis_attachment_history' in db
assert 'find_current_amavis_attachment_history' in db
assert "No attachment file is opened and no archive is extracted" in db
assert "threading.Thread(target=lambda: backfill_amavis_attachment_history(5000), daemon=True).start()" in main
assert "'attachment_history': attachment_view" in main
assert 'Amavis attachment content · MariaDB history' in main
assert 'does not open attachments, execute content, or extract archives' in main
assert "scope': 'CURRENT_MESSAGE_ONLY'" in main
assert 'postfix-delivery-dashboard:m7' in compose
for forbidden in ('DROP TABLE amavis_attachment_history','TRUNCATE TABLE amavis_attachment_history','DELETE FROM amavis_attachment_history'):
    assert forbidden not in db
print('R1.1.31 Amavis attachment history regression passed')
