from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AI = (ROOT / 'app' / 'ai_trainer.py').read_text(encoding='utf-8')
DB = (ROOT / 'app' / 'db.py').read_text(encoding='utf-8')
MAIN = (ROOT / 'app' / 'main.py').read_text(encoding='utf-8')


def _func_body(source: str, name: str) -> str:
    start = source.index(f'def {name}(')
    tail = source[start:]
    nxt = tail.find('\ndef ', 5)
    return tail if nxt < 0 else tail[:nxt]


def test_live_status_uses_compact_db_snapshot_not_dataset_scan():
    body = _func_body(AI, 'status')
    assert '_status_snapshot()' in body
    assert '_dataset_rows()' not in body
    assert 'ai_trainer_status_snapshot' in DB
    assert 'get_ai_trainer_status_snapshot' in DB
    assert 'replace_ai_trainer_status_snapshot' in DB


def test_snapshot_is_forward_only_and_preserves_jsonl_evidence():
    assert 'CREATE TABLE IF NOT EXISTS ai_trainer_status_snapshot' in DB
    assert 'DROP TABLE' not in DB[DB.index('AI_TRAINER_STATUS_SCHEMA'):DB.index('FRAUD_REPO_SCHEMA')]
    assert '_append_jsonl(DATASET, row)' in AI
    assert 'replace_ai_trainer_status_snapshot' in AI


def test_ai_architecture_polling_only_runs_when_visualization_is_visible():
    assert 'function aiArchitectureVisible()' in MAIN
    assert 'if(!aiArchitectureVisible()){stopAIArchitectureLive();return;}' in MAIN
    side_clock = MAIN[MAIN.index('updateSideClock();'):MAIN.index('function openFlowTabTarget')]
    assert 'ensureAIArchitectureLive();' not in side_clock


def test_delivery_statistics_are_throttled_and_health_logging_filtered():
    assert 'const DELIVERY_STATS_TTL_MS=60000;' in MAIN
    assert 'loadDeliveryStatistics(signal)' in MAIN
    assert '},15000);' in MAIN
    assert 'class _SuppressHealthLiveAccess(logging.Filter):' in MAIN
    assert '"/health/live" not in record.getMessage()' in MAIN
    live = _func_body(MAIN, 'live')
    assert 'stats()' not in live
    assert 'db_ready' not in live
