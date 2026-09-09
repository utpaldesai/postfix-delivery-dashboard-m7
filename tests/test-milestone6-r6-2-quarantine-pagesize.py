from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")

assert 'page_size: int = Query(20, ge=10, le=200)' in main
assert '/api/quarantine?page=1&page_size=10' in main
assert 'apiFetch("/api/quarantine?page=1&page_size=1")' not in main
assert '/api/quarantine/list?page=1&page_size=1' not in main

print("Milestone 6 R6.2 quarantine page-size compatibility regression passed")
