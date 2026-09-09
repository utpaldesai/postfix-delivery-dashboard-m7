from pathlib import Path
import os
import tempfile

ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/'app/main.py').read_text(encoding='utf-8')
qsrc=(ROOT/'app/quarantine.py').read_text(encoding='utf-8')
qintel=(ROOT/'app/quarantine_intelligence.py').read_text(encoding='utf-8')
ai=(ROOT/'app/ai_trainer.py').read_text(encoding='utf-8')
compose=(ROOT/'docker-compose.yaml').read_text(encoding='utf-8')

assert 'image: postfix-delivery-dashboard:m7' in compose
assert '@app.post("/api/quarantine/correct-learning")' in main
assert 'CORRECT TO ${item.learning==="spam"?"HAM":"SPAM"}' in main
assert 'sa-learn --forget' in main or '"--forget"' in qsrc
assert 'CORRECT_TO_HAM' in qsrc and 'CORRECT_TO_SPAM' in qsrc
assert 'Latest approved label wins' in ai
assert 'RELEASE_STATUS_DB = STATE_DIR / "release_status.jsonl"' in qsrc
assert 'queued\\s+as' in qsrc
assert 'Queue ID:' in main and 'Release Status' in main
assert 'queue_timeline(queue_id)' in main
assert 'SELECT id, username FROM bayes_vars WHERE username=%s LIMIT 1' not in qintel
assert 'def _bayes_stats' not in qintel
assert '"bayes_seen": _bayes_seen' not in qintel
assert '<h4>Bayes Learning</h4>' not in main
assert '<h4>Host maildb Tables</h4>' not in main
assert 'SpamAssassin Learning & Human Correction' in main
assert 'Release Verification' in main
print('R1.1.7 correction/release verification regression passed')
