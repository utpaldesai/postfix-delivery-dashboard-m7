#!/usr/bin/env python3
import importlib
import os
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    qdir = root / "virusmails"
    sdir = root / "state"
    qdir.mkdir()
    sdir.mkdir()
    fake = root / "sa-learn"
    fake.write_text("#!/bin/sh\necho learned:$*\nexit 0\n")
    fake.chmod(0o755)

    os.environ["QUARANTINE_DIR"] = str(qdir)
    os.environ["QUARANTINE_STATE_DIR"] = str(sdir)
    os.environ["SA_LEARN_CMD"] = str(fake)
    os.environ["SA_LEARN_ENABLED"] = "true"
    os.environ["SA_LEARN_ON_MARK_SPAM"] = "true"
    os.environ["SA_LEARN_USER"] = "amavis"

    import app.quarantine as q
    q = importlib.reload(q)

    ham_id = "spam-ham-test"
    ham_file = qdir / ham_id
    ham_file.write_text(
        "From: sender@example.net\n"
        "To: user@example.org\n"
        "Subject: ham learning test\n"
        "X-Spam-Score: 6.5\n"
        "X-Spam-Status: Yes, score=6.5 tests=[BAYES_80=2.0,HTML_MESSAGE=0.1]\n\nbody\n"
    )
    result = q.learn_ham(ham_id, "127.0.0.1", "tester")
    assert result["ok"] and result["learning"] == "ham"
    assert ham_id in q.LEARN_HAM_DB.read_text()
    assert ham_file.exists(), "Learning must not delete quarantine mail"
    try:
        q.learn_spam(ham_id, "127.0.0.1", "tester")
        raise AssertionError("opposite learning should have been blocked")
    except RuntimeError as exc:
        assert "already learned as ham" in str(exc)

    spam_id = "spam-spam-test"
    spam_file = qdir / spam_id
    spam_file.write_text(
        "From: bad@example.net\nTo: user@example.org\nSubject: spam\n"
        "X-Spam-Score: 12.0\nX-Spam-Status: Yes, score=12.0 tests=[BAYES_99=3.5,SPF_FAIL=1.0]\n\nbody\n"
    )
    result = q.mark_spam(spam_id, "127.0.0.1", "tester")
    assert result["ok"]
    assert spam_id in q.SPAM_DB.read_text()
    assert spam_id in q.LEARN_SPAM_DB.read_text()
    assert spam_file.exists(), "Mark Spam must preserve quarantine mail"

    parsed = q._parse_file(spam_file, spam_id, spam_file.name, spam_file.stat().st_mtime, set(), set())
    assert parsed["triggered_rules"][0]["name"] == "BAYES_99"
    assert parsed["triggered_rules"][0]["score"] == 3.5
    assert parsed["learning"] == "spam"

    audit = q.AUDIT_JSONL.read_text()
    assert '"action":"LEARN_HAM"' in audit
    assert '"action":"LEARN_SPAM"' in audit
    assert '"action":"SPAM_FLG"' in audit

print("Milestone 6 SpamAssassin learning regression passed")
