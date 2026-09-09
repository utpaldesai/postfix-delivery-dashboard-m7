from pathlib import Path

main = Path("app/main.py").read_text()
db = Path("app/db.py").read_text()

assert "WHEN final_status='QUARANTINED' THEN queue_id" in db
assert "WHEN final_status='SPAM' THEN queue_id" not in db[db.index("def stats():"):db.index("def cleanup(")]

assert '<div class="card" data-filter="QUARANTINED">Quarantined<b id="spam">0</b></div>' in main
assert '<option value="QUARANTINED">Quarantined (0)</option>' in main
assert 'QUARANTINED:"Quarantined"' in main
assert 'QUARANTINED:stat.spam||0' in main

print("Milestone 1 quarantined counter/filter regression test passed")
