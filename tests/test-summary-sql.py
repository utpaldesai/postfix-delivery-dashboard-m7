from pathlib import Path

db = Path("app/db.py").read_text(encoding="utf-8")

# PyMySQL uses %-formatting, so literal SQL percent signs must be escaped.
assert "sender LIKE '%%@%%'" in db
assert "recipient LIKE '%%@%%'" in db
assert "STR_TO_DATE(log_timestamp, '%%Y %%b %%d %%H:%%i:%%s')" in db

print("Summary SQL percent escaping test passed")
