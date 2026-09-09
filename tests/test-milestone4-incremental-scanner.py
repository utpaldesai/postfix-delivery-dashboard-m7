from pathlib import Path as _Path
import sys as _sys, tempfile, gzip
_ROOT=str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path: _sys.path.insert(0,_ROOT)
import app.quarantine as q

with tempfile.TemporaryDirectory() as td:
    base=_Path(td)
    quarantine=base/'virusmails'; quarantine.mkdir()
    state=base/'state'; state.mkdir()
    msg=(b'From: sender@example.com\nTo: user@example.com\nSubject: Test\n'
         b'X-Spam-Score: 7.0\nX-Spam-Status: Yes, tests=[TEST_RULE]\n\nBody')
    f=quarantine/'spam-test.gz'
    with gzip.open(f,'wb') as h: h.write(msg)
    q.QUARANTINE_DIR=quarantine
    q.STATE_DIR=state
    q.RELEASED_DB=state/'released_ids.db'
    q.SPAM_DB=state/'spam_ids.db'
    q.AUDIT_LOG=state/'audit.log'
    q.AUDIT_JSONL=state/'audit.jsonl'
    q._file_cache={}
    q.cache={"data":[],"last_updated":"Never","error":"","scan_stats":{"parsed":0,"reused":0}}
    q.refresh_cache()
    assert q.cache['scan_stats']['parsed']==1
    assert q.cache['scan_stats']['reused']==0
    q.refresh_cache()
    assert q.cache['scan_stats']['parsed']==0
    assert q.cache['scan_stats']['reused']==1
print('Milestone 4 incremental quarantine scanner test passed')
