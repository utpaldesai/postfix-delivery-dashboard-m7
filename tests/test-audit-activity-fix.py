from pathlib import Path as _Path
import sys as _sys
_ROOT=str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path: _sys.path.insert(0,_ROOT)
from pathlib import Path
import tempfile
import app.quarantine as q

with tempfile.TemporaryDirectory() as td:
    state = Path(td)
    q.STATE_DIR = state
    q.AUDIT_LOG = state / 'quarantine_audit.log'
    q.AUDIT_JSONL = state / 'quarantine_audit.jsonl'
    q.RELEASED_DB = state / 'released_ids.db'
    q.SPAM_DB = state / 'spam_ids.db'

    q._item_snapshot = lambda pdp_id: {
        'from': 'sender@example.com',
        'to': 'user@nirma.co.in',
        'subject': 'Audit test',
        'category': 'Spam',
        'score': '10.5',
    }

    q.write_audit('LOGIN', '', '192.168.20.177', 'admin')
    q.write_audit('RELEASE', '4/spam-test.gz', '192.168.20.177', 'admin')
    q.write_audit('SPAM_FLG', '4/spam-test2.gz', '192.168.20.177', 'admin')

    data = q.audit_records(page=1, page_size=50)
    assert data['total'] == 3, data
    actions = {row['action'] for row in data['rows']}
    assert actions == {'LOGIN', 'RELEASE', 'SPAM_FLG'}, actions
    for row in data['rows']:
        assert row['user'] == 'admin'
        assert row['ip'] == '192.168.20.177'

    login = q.audit_records(action='LOGIN', page=1, page_size=50)
    assert login['total'] == 1
    assert login['rows'][0]['pdp_id'] == ''

print('Audit activity regression test passed')
