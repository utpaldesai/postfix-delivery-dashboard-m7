from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")
db=Path("app/db.py").read_text(encoding="utf-8")

assert "def bounced_domain_details(" in db
assert "final_status = 'BOUNCED'" in db
assert "status_detail AS bounce_reason" in db
assert "LIMIT 2000" in db

assert '@app.get("/api/summary/bounces/detail")' in main
assert 'Depends(require_permission("summary", "view"))' in main
assert "function bounceCountButton(row,direction)" in main
assert "function openBounceDetail(dateIso,domain,direction)" in main
assert 'id="bounceDetailModal"' in main
assert '<th>DATE</th>' in main
assert '<th>FROM</th>' in main
assert '<th>TO</th>' in main
assert '<th>SUBJECT</th>' in main
assert '<th>REASON FOR BOUNCE</th>' in main
assert 'bounceCountButton(row,"sent")' in main
assert 'bounceCountButton(row,"received")' in main
assert 'row.subject||"Not captured"' in main
assert "Subject is not present in standard Postfix final-delivery logs." in main

# Existing key features preserved.
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main
assert 'data-tab="aclTab"' in main
assert 'data-tab="helpTab"' in main
assert "z-index:10000 !important" in main

print("Milestone 5 bounce-detail drill-down regression test passed")
