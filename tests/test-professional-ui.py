from pathlib import Path
main=Path("app/main.py").read_text()
for x in ("--panel:#fff",".tabbtn.active",".qmail{",".audit-table",".delivery-compact","function statusBadge("):
    assert x in main
print("Professional UI test passed")
