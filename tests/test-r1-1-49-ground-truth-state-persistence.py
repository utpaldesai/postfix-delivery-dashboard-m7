from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/'app/main.py').read_text()
db=(ROOT/'app/db.py').read_text()
trainer=(ROOT/'app/ai_trainer.py').read_text()

assert 'ai_ground_truth_current(source_sha256, pdp_id=pdp_id)' in main
assert "if not row and pid:" in db
assert "admin_notes TEXT NOT NULL" in db
assert "ALTER TABLE ai_ground_truth_history ADD COLUMN admin_notes" in db
assert "review_reason=review_reason, admin_notes=admin_notes" in trainer
assert 'if(reason) reason.value=String(currentAiGtSaved.review_reason||"")' in main
assert 'if(notes) notes.value=String(currentAiGtSaved.admin_notes||"")' in main
assert ('currentAiGtSaved={label,classification,review_reason,admin_notes' in main or 'currentAiGtSaved=data.admin_ground_truth||' in main)
assert 'Reset unsaved edits to the persisted administrator state' in main
print('R1.1.49 ground-truth state persistence regression: PASS')
