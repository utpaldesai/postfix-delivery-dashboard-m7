from pathlib import Path as _Path
import sys as _sys
_ROOT=str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path: _sys.path.insert(0,_ROOT)
from app.parser import parse_line

rank_line = (
    "Aug 06 13:50:22 ms postfix/postscreen-primary/postscreen[3833429]: "
    "DNSBL rank 3 for [185.253.116.188]:50183"
)

reject_line = (
    "Aug 06 13:50:23 ms postfix/postscreen-primary/postscreen[3833429]: "
    "NOQUEUE: reject: RCPT from [185.253.116.188]:50183: "
    "550 5.7.1 Service unavailable; client [185.253.116.188] "
    "blocked using zen.spamhaus.org; "
    "from=<purchase@santi-egom.space>, "
    "to=<hemalshah@nirma.co.in>, "
    "proto=ESMTP, helo=<mail0.santi-egom.space>"
)

assert parse_line(rank_line) is None

event = parse_line(reject_line)
assert event is not None
assert event["final_status"] == "BLOCKED", event
assert event["sender"] == "purchase@santi-egom.space", event
assert event["recipient"] == "hemalshah@nirma.co.in", event
assert event["delivery_target"] == "185.253.116.188", event
assert event["service"] == "postscreen-primary/postscreen", event
assert event["queue_id"].startswith("NOQUEUE-"), event
print("Postscreen RBL rejection test passed")
