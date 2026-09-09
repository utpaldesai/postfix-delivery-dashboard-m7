from pathlib import Path
import os
import sys
import tempfile
import time

os.environ["HOME_DOMAINS"] = "corp.example"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.quarantine as quarantine

raw = b"""From: Sender <sender@outside.example>\r\nTo: One <one@corp.example>, ext@outside.example\r\nCc: Two <two@corp.example>\r\nBcc: Three <three@corp.example>\r\nX-Envelope-To: Four <four@corp.example>, ext2@outside.example\r\nSubject: Test\r\nX-Spam-Score: 7.0\r\n\r\nSECRET BODY MUST NOT APPEAR IN HEADER\r\n"""

with tempfile.TemporaryDirectory() as td:
    path = Path(td) / "spam-test"
    path.write_bytes(raw)
    item = quarantine._parse_file(path, "spam-test", "spam-test", time.time(), set(), set())

assert item["display_to"] == (
    "One <one@corp.example>, Two <two@corp.example>, "
    "Three <three@corp.example>, Four <four@corp.example>"
)
assert "outside.example" not in item["display_to"]
assert "SECRET BODY" not in item["header"]
assert "X-Envelope-To:" in item["header"]

main = Path("app/main.py").read_text(encoding="utf-8")
for token in [
    'class="qheader-btn"',
    'View Full Header',
    'id="qHeaderModal"',
    'openQuarantineHeader(',
    'copyQuarantineHeader()',
    'item.display_to',
]:
    assert token in main, token

print("Milestone 6 home-domain recipient/header regression passed")
