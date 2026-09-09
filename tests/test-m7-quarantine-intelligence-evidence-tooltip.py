#!/usr/bin/env python3
from pathlib import Path
import importlib, os, tempfile, sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
main=(ROOT/'app/main.py').read_text(encoding='utf-8')
qsrc=(ROOT/'app/quarantine.py').read_text(encoding='utf-8')

for token in (
    'SpamAssassin Intelligence','Final Score','Required Score','Verdict',
    'Top contributing rules','Negative / trust rules','All tests',
    'function spamEvidenceSummary(item)','Score: ${esc(item.score)}',
):
    assert token in main, token
for token in ('"required_score": required_score','"spam_verdict": spam_verdict','"dmarc": dmarc'):
    assert token in qsrc, token

with tempfile.TemporaryDirectory() as td:
    root=Path(td); qdir=root/'virusmails'; sdir=root/'state'; qdir.mkdir(); sdir.mkdir()
    os.environ['QUARANTINE_DIR']=str(qdir); os.environ['QUARANTINE_STATE_DIR']=str(sdir)
    import app.quarantine as q
    q=importlib.reload(q)
    p=qdir/'spam-intel-test.gz'
    import gzip
    with gzip.open(p,'wb') as f:
        f.write(b'From: sender@example.net\nTo: user@example.org\nSubject: test\nAuthentication-Results: mx.example; spf=pass; dkim=fail; dmarc=pass\nX-Spam-Score: 8.7\nX-Spam-Status: Yes, score=8.7 required=5.0 tests=[BAYES_99=3.5,SPF_FAIL=1.5,HTML_MESSAGE=0.1,DKIM_VALID=-0.1,RCVD_IN_DNSWL=-0.5]\n\nbody\n')
    item=q._parse_file(p,p.name,p.name,p.stat().st_mtime,set(),set())
    assert item['score']=='8.7'
    assert item['required_score']=='5.0'
    assert item['spam_verdict']=='SPAM'
    assert item['dmarc']=='pass'
    assert item['triggered_rules'][0]['name']=='BAYES_99'
print('M7 Quarantine Intelligence evidence tooltip regression passed')
