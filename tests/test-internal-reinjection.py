from pathlib import Path as _Path
import sys as _sys
_ROOT=str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path: _sys.path.insert(0,_ROOT)
from app.parser import parse_line

samples = [
    (
        "Aug 05 17:54:01 ms postfix/amavis/smtp[3120488]: "
        "4hFV2R1g7yzWjL: to=<parthiv@nirma.co.in>, "
        "relay=127.0.0.1[127.0.0.1]:10026, delay=2.1, "
        "delays=0.03/0/0/2.1, dsn=2.0.0, status=sent "
        "(250 2.0.0 from MTA(smtp:[127.0.0.1]:10025): "
        "250 2.0.0 Ok: queued as 4hFVCd51CGzWjM)"
    ),
    (
        "Aug 05 17:54:02 ms postfix/amavis/smtp[3120488]: "
        "4hFV2R1g7yzWjK: to=<user@nirma.co.in>, "
        "relay=127.0.0.1[127.0.0.1]:10024, delay=2.1, "
        "dsn=2.0.0, status=sent "
        "(250 2.0.0 from MTA(smtp:[127.0.0.1]:10025): "
        "250 2.0.0 Ok: queued as 4hFVH71hPDzVBt)"
    ),
]

for line in samples:
    assert parse_line(line) is None, line

print("Internal reinjection filters passed")
