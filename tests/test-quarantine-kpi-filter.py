from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")

assert 'data-qfilter="all"' in main
assert 'data-qfilter="Spam"' in main
assert 'data-qfilter="Virus"' in main
assert 'data-qfilter="Banned"' in main
assert 'id="qCategory"' not in main
assert 'let quarantineCategory="all";' in main
assert 'category:quarantineCategory' in main
assert 'document.querySelectorAll(".qmetric-filter")' in main

print("Quarantine KPI filter test passed")
