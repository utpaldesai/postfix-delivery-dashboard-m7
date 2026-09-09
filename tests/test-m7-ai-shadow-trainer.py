from pathlib import Path
import tempfile

from app import ai_trainer as ai

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    ai.STATE_DIR = root / "ai-trainer"
    ai.DATASET = ai.STATE_DIR / "training_samples.jsonl"
    ai.CANDIDATE_MODEL = ai.STATE_DIR / "candidate_model.json"
    ai.ACTIVE_MODEL = ai.STATE_DIR / "active_model.json"
    ai.EVENT_LOG = ai.STATE_DIR / "events.jsonl"
    ai.MODEL_META = ai.STATE_DIR / "model_meta.json"
    ai.MIN_PER_CLASS = 2
    ai.AI_ENABLED = True

    samples = [
        ("h1.eml", "HAM", "Project meeting agenda and invoice approval", "pass", "pass", "-1.2"),
        ("h2.eml", "HAM", "Quarterly report attached for review", "pass", "pass", "0.1"),
        ("s1.eml", "SPAM", "Urgent account suspended click verify password", "fail", "fail", "12.8"),
        ("s2.eml", "SPAM", "Winner prize claim cryptocurrency wallet now", "fail", "none", "15.2"),
    ]
    for name, label, body, spf, dkim, score in samples:
        path = root / name
        path.write_text(f"From: sender@example.test\nTo: user@example.test\nSubject: {body}\nX-Spam-Status: Yes, score={score} tests=BAYES_99,SPF_FAIL\n\n{body}\n", encoding="utf-8")
        result = ai.record_human_label(name, label, path, {"spf": spf, "dkim": dkim, "score": score}, "tester")
        assert result["ok"]

    status = ai.status()
    assert status["shadow_only"] is True
    assert status["ham_labels"] == 2
    assert status["spam_labels"] == 2

    candidate = ai.train_candidate("tester")
    assert candidate["shadow_only"] is True
    assert candidate["algorithm"] in {"multinomial-naive-bayes-hashed-v2-independent", "balanced-logistic-regression-hashed-v4-authneutral-independent"}
    assert ai.ACTIVE_MODEL.exists() is False, "training must not auto-promote"

    promoted = ai.promote_candidate("tester")
    assert promoted["shadow_only"] is True
    assert ai.ACTIVE_MODEL.exists()

    probe = root / "probe.eml"
    probe.write_text("From: fraud@example.test\nTo: user@example.test\nSubject: urgent verify password\n\nclick verify password prize wallet\n", encoding="utf-8")
    prediction = ai.predict_file(probe, {"spf": "fail", "dkim": "fail", "score": "11.0"})
    assert prediction["available"] is True
    assert prediction["shadow_only"] is True
    assert prediction["verdict"] in {"HAM", "SPAM"}
    assert 0 <= prediction["confidence"] <= 100

    text = ai.DATASET.read_text(encoding="utf-8")
    assert "Project meeting agenda" not in text
    assert "Urgent account suspended" not in text
    assert '"features"' in text

print("M7 AI shadow trainer regression passed")
