from pathlib import Path
main=Path('app/main.py').read_text(encoding='utf-8')
refresh=main.split('@app.post("/api/quarantine/refresh")',1)[1].split('@app.post("/api/quarantine/learn")',1)[0]
assert 'detail=str(exc)' not in refresh
assert 'detail="Invalid AI ground-truth request"' in refresh
assert 'logger.warning("AI ground-truth request rejected due to invalid input")' in refresh
assert 'detail="Quarantine refresh failed; see server logs for details"' in refresh
print('R1.1.30 security regression correction passed')
