from pathlib import Path
parser=Path("app/parser.py").read_text()
db=Path("app/db.py").read_text()
main=Path("app/main.py").read_text()
assert '"QUARANTINED"' in parser
assert 'state = "QUARANTINED"' in parser
assert 'Message quarantined as spam' in parser
assert "SPAM_TO_QUARANTINED_MIGRATION" in db
assert "SET final_status = 'QUARANTINED'" in db
assert 'data-filter="QUARANTINED">Quarantined' in main
print("Quarantined delivery status test passed")
