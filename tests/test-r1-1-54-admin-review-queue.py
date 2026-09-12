from pathlib import Path

root = Path(__file__).resolve().parents[1]
main = (root / 'app' / 'main.py').read_text(encoding='utf-8')
quarantine = (root / 'app' / 'quarantine.py').read_text(encoding='utf-8')
db = (root / 'app' / 'db.py').read_text(encoding='utf-8')
help_text = main

assert 'admin_decision: str = "all"' in main
assert 'ai_ground_truth_current_pdp_ids()' in main
assert 'admin_decision=admin_decision' in main
assert 'id="qAdminDecision"' in main
assert 'Review Pending Messages' in main
assert 'Admin Decision Required</b> · <button' not in main
assert 'reviewPendingQuarantineItem' not in main
assert 'openRequiredReviewQueue()' in main
assert 'admin_decision="all"' in quarantine
assert 'admin_decision == "required"' in quarantine
assert 'admin_decision == "completed"' in quarantine
assert '"review_queue"' in quarantine
assert 'def ai_ground_truth_current_pdp_ids()' in db
assert "status='CURRENT'" in db
assert 'R1.1.55 Admin Review Queue De-duplication' in help_text
print('R1.1.55 Admin Review Queue de-duplication regression: PASS')
