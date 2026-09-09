from pathlib import Path
root=Path(__file__).resolve().parents[1]
db=(root/'app/db.py').read_text()
main=(root/'app/main.py').read_text()
assert 'CREATE TABLE IF NOT EXISTS amavis_log_evidence' in db
assert 'UNIQUE KEY uq_amavis_evidence_hash' in db
assert 'find_amavis_evidence' in main and 'store_amavis_evidence' in main
assert 'MariaDB continuous evidence' in main or 'MariaDB legacy retained evidence' in main
assert '_tail_matching_lines(AMAVIS_LOG' in main
print('Fix7 Amavis evidence DB regression passed')
