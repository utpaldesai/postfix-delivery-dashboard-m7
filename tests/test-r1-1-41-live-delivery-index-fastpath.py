from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DB=(ROOT/'app/db.py').read_text(encoding='utf-8')
MAIN=(ROOT/'app/main.py').read_text(encoding='utf-8')
README=(ROOT/'README.md').read_text(encoding='utf-8')

# Live page must select newest Queue-IDs first and only then aggregate details.
assert 'def _latest_queue_ids_fast(' in DB
assert 'FORCE INDEX ({index_name})' in DB
assert 'idx_delivery_updated_queue' in DB
assert 'ADD KEY idx_delivery_updated_queue (last_updated, queue_id)' in DB
assert 'def _group_selected_queue_ids(' in DB
assert 'WHERE queue_id IN ({placeholders})' in DB
assert 'use_live_fast_path = (not search and not date_from and not date_to and not include_total' in DB
assert 'selected = _latest_queue_ids_fast' in DB
assert 'rows = _group_selected_queue_ids' in DB

# First in-place continuous-feed migration must not replay an already-populated DB.
assert 'def postfix_delivery_projection_has_rows()' in DB
assert 'SELECT 1 AS present FROM postfix_delivery_final LIMIT 1' in DB
assert 'if postfix_delivery_projection_has_rows():' in MAIN
assert 'db_adopt_existing_projection' in MAIN

# Fresh bootstrap must use a bounded reverse tail reader, not all_lines[].
assert 'def _tail_postfix_lines(' in MAIN
assert "path.open('rb')" in MAIN
assert "raw.seek(pos)" in MAIN
assert 'all_lines=[]' not in MAIN
assert 'db_bootstrap_tail_bounded' in MAIN

# Preserve non-destructive database policy.
for forbidden in ('DROP TABLE postfix_', 'TRUNCATE TABLE postfix_', 'DROP DATABASE', 'CREATE DATABASE'):
    assert forbidden not in DB
assert 'R1.1.41 — Live Delivery Index Fast Path' in README
print('R1.1.41 live Delivery index fast-path regression passed')
