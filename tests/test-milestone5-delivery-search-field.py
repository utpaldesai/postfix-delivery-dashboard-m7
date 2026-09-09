from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
main = (ROOT / "app" / "main.py").read_text()
db = (ROOT / "app" / "db.py").read_text()

assert 'id="searchField"' in main
assert '<option value="all" selected>All fields</option>' in main
assert '<option value="from">From</option>' in main
assert '<option value="to">To</option>' in main
assert 'search_field: str = "all"' in main
assert 'search_field:searchField' in main
assert 'field_map = {' in db
assert '"from": ("sender",)' in db
assert '"to": ("recipient",)' in db
print("PASS: Delivery All fields / From / To search selector")
