from pathlib import Path
root=Path(__file__).resolve().parents[1]
db=(root/'app/db.py').read_text(encoding='utf-8')
main=(root/'app/main.py').read_text(encoding='utf-8')
ai=(root/'app/ai_trainer.py').read_text(encoding='utf-8')

# Forward-only DB additions and tuned hot-path indexes.
assert 'CREATE TABLE IF NOT EXISTS ai_ground_truth_history' in db
assert 'CREATE TABLE IF NOT EXISTS ai_conflict_investigations' in db
assert 'def ensure_r1129_indexes()' in db
for idx in ('idx_amavis_mail_id_id','idx_amavis_queue_id_id','idx_amavis_release_queue_id_id','idx_amavis_message_id_id','idx_amavis_session_id_id','idx_amavis_quarantine_id','idx_delivery_status_updated'):
    assert idx in db
assert "INFORMATION_SCHEMA.STATISTICS" in db
assert 'DROP TABLE' not in db

# Current-item correlation is exact/indexed and avoids sender-only/raw-log broad matching.
trace=db[db.index('def find_current_amavis_trace'):db.index('def find_continuous_amavis_evidence')]
assert "Correlation priority is mail_id -> Queue-ID/release Queue-ID -> Message-ID" in trace
assert "sender=%s" not in trace and "sender LIKE" not in trace
assert "raw_log LIKE" not in trace
assert "quarantine_file" in trace
assert "session_id IN" in trace
assert "'scope': 'CURRENT_MESSAGE_ONLY'" in main
assert 'Current message Amavis trace' in main

# Intelligence status uses a bounded server-side snapshot rather than reparsing on every 10s poll.
assert 'AI_TRAINER_STATUS_CACHE_SECONDS' in ai
assert 'def _status_signature()' in ai
assert 'status_cache_seconds' in ai

# Conflict/reversal/calibration foundations.
assert 'HAM_CLASSIFICATIONS' in ai and 'SPAM_CLASSIFICATIONS' in ai
assert 'AI_HUMAN_CONFLICT_REVERSE_ENGINEERED' in ai
assert 'def _forensic_conflict_review' in ai
assert 'validation_errors' in ai
assert 'hard_ham_recall' in ai
assert '@app.post("/api/ai-trainer/ground-truth")' in main
assert 'UCE_AUTHENTICATED' in main
assert 'Save Changed Ground Truth' in main
assert 'does not call sa-learn' in main
print('R1.1.29 intelligence performance/current Amavis/index tuning regression passed')
