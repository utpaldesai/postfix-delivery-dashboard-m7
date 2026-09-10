from pathlib import Path as _Path
import sys as _sys
_ROOT=str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path: _sys.path.insert(0,_ROOT)
from app.parser import parse_line

line = (
    "Aug 05 18:10:00 ms postfix/smtpd/smtpd[1234]: "
    "NOQUEUE: reject: RCPT from sender.example[192.0.2.10]: "
    "554 5.7.1 content rejected as spam; "
    "from=<spam@example.com> to=<user@nirma.co.in>"
)

event = parse_line(line)
assert event is not None
assert event["final_status"] == "QUARANTINED", event
assert event["sender"] == "spam@example.com", event
assert event["recipient"] == "user@nirma.co.in", event
print("Spam parser test passed")
