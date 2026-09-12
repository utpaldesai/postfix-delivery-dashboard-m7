from pathlib import Path

root=Path(__file__).resolve().parents[1]
trainer=(root/"app/ai_trainer.py").read_text()
main=(root/"app/main.py").read_text()
quarantine=(root/"app/quarantine.py").read_text()
ti=(root/"app/ai_threat_intelligence.py").read_text()

assert 'AUTHORITATIVE_LABEL_SOURCES' in trainer
assert 'def _row_is_training_eligible' in trainer
assert 'if _row_is_training_eligible(row)' in trainer
assert 'source="sa-learn"' not in quarantine
assert 'source="human-correction"' not in quarantine
assert 'AI_LABEL_BACKFILL_BLOCKED' in main
assert 'ADMIN GROUND TRUTH ONLY' in main
assert 'def _transport_provider' in ti
assert 'provider_transitions' in ti
assert 'MX/provider verification is contextual only' in ti
print('R1.1.52 training provenance + provider-aware transport regression: PASS')
