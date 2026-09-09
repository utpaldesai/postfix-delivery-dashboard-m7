from pathlib import Path as _Path
import sys as _sys
_ROOT=str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path: _sys.path.insert(0,_ROOT)
from app.parser import parse_line

samples = [
    (
        "Aug 05 18:30:00 ms postfix/amavis/smtp[12345]: "
        "4hTEST12345: to=<user@nirma.co.in>, "
        "relay=127.0.0.1[127.0.0.1]:10024, delay=1.2, "
        "dsn=2.7.0, status=sent "
        "(250 2.7.0 Ok, discarded, id=1121887-14 - spam)"
    ),
    (
        "Aug 05 18:31:00 ms postfix/amavis/smtp[12346]: "
        "4hTEST12346: to=<user2@nirma.co.in>, "
        "relay=127.0.0.1[127.0.0.1]:10026, delay=1.2, "
        "dsn=2.7.0, status=sent "
        "(250 2.7.0 Ok, quarantined, id=1121887-15 - spam)"
    ),
]

for line in samples:
    event = parse_line(line)
    assert event is not None, line
    assert event["final_status"] == "QUARANTINED", event
    assert event["delivery_target"] == "Amavis content filter", event
    assert event["status_detail"] == "Message quarantined as spam", event

print("Amavis spam decision tests passed")
