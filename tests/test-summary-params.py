from pathlib import Path
import re

text = Path("app/db.py").read_text(encoding="utf-8")
assert "params = domains * 8" in text

# Direction summary SQL has eight domain placeholder groups:
# sender/recipient pair repeated across four direction CASEs.
section = text.split("def direction_summary(", 1)[1]
sql_part = section.split('with conn() as connection:', 1)[0]
assert sql_part.count("({ph})") == 8, sql_part.count("({ph})")

print("Summary parameter-count test passed")
