from pathlib import Path

q = Path("app/quarantine.py").read_text(encoding="utf-8")
main = Path("app/main.py").read_text(encoding="utf-8")
compose = Path("docker-compose.yaml").read_text(encoding="utf-8")

assert "def _decision_for(" in q
assert "def _assert_undecided(" in q
assert q.count("_assert_undecided(pdp_id)") >= 2
assert "SAFETY / RETENTION RULE:" in q

# No destructive quarantine-file operations should exist.
for forbidden in (
    "os.remove(",
    "os.unlink(",
    ".unlink(",
    "shutil.move(",
    "os.rename(",
    ".rename(",
):
    assert forbidden not in q, forbidden

assert "const finalized=Boolean(item.is_released||item.is_manual_spam);" in main
assert "const actionDisabled=finalized||!canManageQuarantine;" in main
assert main.count('${actionDisabled?"disabled":""}') >= 2
assert ":/host-amavis/virusmails:ro" in compose

print("Quarantine retention/final-action test passed")
