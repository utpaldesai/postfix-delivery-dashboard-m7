from pathlib import Path

q=Path("app/quarantine.py").read_text(encoding="utf-8")
main=Path("app/main.py").read_text(encoding="utf-8")

assert "AUDIT_JSONL" in q
assert "def audit_records(" in q
assert '"ip": remote_addr' in q
assert '"from": snapshot["from"]' in q
assert '"to": snapshot["to"]' in q
assert '"subject": snapshot["subject"]' in q
assert 'data-tab="auditTab"' in main
assert 'id="auditRows"' in main
assert '@app.get("/api/quarantine/audit/records")' in main
assert "RELEASED" in main
assert "MARKED SPAM" in main

print("Quarantine audit tab test passed")
