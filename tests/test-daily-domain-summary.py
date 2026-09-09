from pathlib import Path

db = Path("app/db.py").read_text(encoding="utf-8")
main = Path("app/main.py").read_text(encoding="utf-8")

assert "def daily_domain_summary(" in db
assert '"BOUNCED"' in main
assert '@app.get("/api/summary/domains")' in main
assert 'id="dailyDomainRows"' not in main
assert 'id="dailyBounceRows"' in main
assert "renderDailyDomainTable" in main

print("Bounced daily domain summary source test passed")
