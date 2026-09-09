from pathlib import Path
v=Path("verify-source.sh").read_text(encoding="utf-8")
assert "Dashboard Milestone 4" not in v
assert "Milestone 7 Enterprise source verification passed." in v
assert "Milestone 6 source verification passed." not in v
print("Milestone 5 verifier regression test passed")
