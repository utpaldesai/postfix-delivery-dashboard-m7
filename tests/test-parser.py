from pathlib import Path as _Path
import sys as _sys
_ROOT=str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path: _sys.path.insert(0,_ROOT)
from app.parser import parse_line

line = (
    "Aug 05 17:06:20 ms postfix/smtpd/smtpd[3224702]: "
    "NOQUEUE: reject: RCPT from paper.nuvaxium.com[45.74.252.223]: "
    "450 4.7.1 Service unavailable; Client host [45.74.252.223] "
    "blocked using zen.spamhaus.org; Listed by CSS; "
    "from=<ayla@nuvaxium.com> to=<info@nirma.co.in> "
    "proto=ESMTP helo=<paper.nuvaxium.com>"
)

event = parse_line(line)
assert event is not None, "event was discarded"
assert event["final_status"] == "BLOCKED", event
assert event["sender"] == "ayla@nuvaxium.com", event
assert event["recipient"] == "info@nirma.co.in", event
assert event["delivery_target"] == "45.74.252.223", event
assert event["queue_id"].startswith("NOQUEUE-"), event
assert event["service"] == "smtpd/smtpd", event
print("Parser test passed")
print(event)
