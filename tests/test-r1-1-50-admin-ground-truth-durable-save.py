from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/'app/main.py').read_text()
db=(ROOT/'app/db.py').read_text()
trainer=(ROOT/'app/ai_trainer.py').read_text()

# R1.1.49 root cause: ai_ground_truth_history has 13 columns and must have
# 12 bound parameters plus literal CURRENT. The old build had only 11 bound
# placeholders and silently failed every DB-history INSERT.
m=re.search(r'''INSERT INTO ai_ground_truth_history\s*\n\s*\(source_sha256,pdp_id,label,classification,review_reason,admin_notes,reviewer,label_source,status,previous_label,reversal_count,generation_id,feature_schema\)\s*\n\s*VALUES \(([^\n]+)\)''', db)
assert m, 'ground truth INSERT not found'
values=m.group(1)
assert values.count('%s') == 12, values
assert "'CURRENT'" in values
assert "%s,%s,'CURRENT',%s" in values, values  # reviewer,label_source,status,previous_label ordering

# DB persistence errors must no longer be swallowed as successful calibration.
history_block=trainer[trainer.index('# MariaDB is authoritative for the Admin Decision state.'):trainer.index('conflict_id=None')]
assert '_persist_admin_ground_truth_db(' in history_block
assert 'except Exception' not in history_block
assert 'GROUND_TRUTH_DB_HISTORY_FAILED' not in history_block
assert 'except ModuleNotFoundError as exc:' in trainer
assert 'getattr(exc, "name", "") == "pymysql"' in trainer

# Re-saving a label already present in the immutable dataset must still repair/
# refresh MariaDB CURRENT state, including notes/reason.
dup=trainer[trainer.index('if previous_label == label and str(row.get("classification") or "") == classification:'):trainer.index('            break', trainer.index('if previous_label == label and str(row.get("classification") or "") == classification:'))]
assert '_persist_admin_ground_truth_db(' in dup
assert 'admin_notes=admin_notes' in dup
assert 'review_reason=review_reason' in dup
assert '"source_sha256": sha' in dup

# Reopen path must restore ground truth even when another shadow AI component fails.
assert 'result["admin_ground_truth"] = {}' in main
assert 'gt_source_path = quarantine_source_path(pdp_id)' in main
restore_pos=main.index('gt_source_path = quarantine_source_path(pdp_id)')
ai_except_pos=main.rfind('except Exception as exc:', 0, restore_pos)
assert ai_except_pos != -1 and ai_except_pos < restore_pos

# POST save must verify exact DB read-back before reporting success to browser.
assert 'persisted=ai_ground_truth_current(result.get("source_sha256", ""), pdp_id=pdp_id) or {}' in main
assert 'Admin Ground Truth persistence verification failed' in main
assert '"admin_ground_truth":persisted' in main
assert 'currentAiGtSaved=data.admin_ground_truth||' in main
assert 'persisted in MariaDB' in main

print('R1.1.50 durable Admin Ground Truth save/reopen regression: PASS')
