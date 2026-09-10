from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
DB=(ROOT/'app/db.py').read_text(encoding='utf-8')
MAIN=(ROOT/'app/main.py').read_text(encoding='utf-8')
COMPOSE=(ROOT/'docker-compose.yaml').read_text(encoding='utf-8')
README=(ROOT/'README.md').read_text(encoding='utf-8')
repo=ROOT/'local-email-intelligence-repo'
seed=json.loads((repo/'local-email-intelligence-2026.09.03-v1.json').read_text())

# No bundled third-party active repository or source registry.
assert not (ROOT/'harmful-email-repo').exists()
assert not (ROOT/'fraud-repo').exists()
assert repo.is_dir()
assert not (repo/'sources').exists()
assert seed['source_policy']=='LOCAL_ONLY_NO_THIRD_PARTY_NO_NETWORK_DEPENDENCY'
assert seed['external_sources']==[]
assert seed['training_authority'] is False
for forbidden in ('PhishTank','URLhaus','Sting9','rf_peixoto_phishing_pot','apache_spamassassin_public_corpus','rspamd_test_corpus'):
    assert forbidden not in (repo/'local-email-intelligence-2026.09.03-v1.json').read_text()

# Forward-only MariaDB continuous Postfix event store/checkpoint.
for table in ('postfix_log_events','postfix_log_ingest_state'):
    assert f'CREATE TABLE IF NOT EXISTS {table}' in DB
for fn in ('get_postfix_ingest_state','set_postfix_ingest_state','store_postfix_raw_events_batch'):
    assert f'def {fn}(' in DB
assert 'UNIQUE KEY uq_postfix_source_position' in DB
assert 'Never advance the MariaDB checkpoint from the exception path.' in MAIN
assert 'store_postfix_raw_events_batch' in MAIN
assert 'POSTFIX_INGEST_SOURCE_KEY' in MAIN and 'POSTFIX_INGEST_SOURCE_KEY' in COMPOSE
assert 'POSTFIX_INGEST_BATCH_LINES' in COMPOSE
assert 'POSTFIX_INGEST_POLL_SECONDS' in COMPOSE

# No destructive migration and existing projection remains the UI source.
for forbidden in ('DROP TABLE postfix_','TRUNCATE TABLE postfix_','DROP DATABASE','CREATE DATABASE'):
    assert forbidden not in DB
assert 'postfix_delivery_final' in DB
assert 'R1.1.39 — Self-contained Local Intelligence + Continuous Postfix Feed' in README
assert 'No runtime network lookup is introduced.' in README
print('R1.1.39 self-contained local intelligence + continuous Postfix feed regression passed')
