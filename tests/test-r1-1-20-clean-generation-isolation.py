from pathlib import Path
import json
import tempfile
from app import ai_trainer as ai

assert ai.CURRENT_GENERATION == "independent-g1"

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    ai.STATE_DIR = td
    ai.DATASET = td / "training_samples.jsonl"
    ai.CANDIDATE_MODEL = td / "candidate_model.json"
    ai.ACTIVE_MODEL = td / "active_model.json"
    ai.EVENT_LOG = td / "events.jsonl"
    ai.MODEL_META = td / "model_meta.json"

    # Three reset-era schema-v4 labels are current-compatible.
    rows = [
        {"sample_id":"n1","label":"HAM","feature_schema":4,"features":{"x":1},"hard_ham":True},
        {"sample_id":"n2","label":"HAM","feature_schema":4,"features":{"x":1},"hard_ham":True},
        {"sample_id":"n3","label":"SPAM","feature_schema":4,"features":{"y":1},"hard_ham":False},
    ]
    ai.DATASET.write_text("".join(json.dumps(r)+"\n" for r in rows), encoding="utf-8")

    # Persisted pre-clean model files must be audit-only, never current UI state.
    legacy = {
        "version":"ai-20260901-045215",
        "feature_schema":4,
        "dataset_samples":1207,
        "algorithm":"balanced-logistic-regression-hashed-v4-authneutral-independent",
        "metrics":{"accuracy":92.74,"balanced_accuracy":92.78},
    }
    ai.CANDIDATE_MODEL.write_text(json.dumps(legacy), encoding="utf-8")
    ai.ACTIVE_MODEL.write_text(json.dumps({**legacy, "version":"ai-20260826-101713"}), encoding="utf-8")

    st = ai.status()
    assert st["generation_id"] == "independent-g1"
    assert st["dataset_samples"] == 3
    assert st["ham_labels"] == 2 and st["spam_labels"] == 1
    assert st["candidate"] is None
    assert st["active"] is None
    assert st["legacy_candidate_archived"] is True
    assert st["legacy_active_archived"] is True
    assert st["next_auto_train_in"] == 247

    prediction = ai.predict_file(td / "does-not-need-to-exist.eml")
    assert prediction["available"] is False
    assert "No active independent model" in prediction["reason"]

print("R1.1.20 clean-generation isolation regression passed")
