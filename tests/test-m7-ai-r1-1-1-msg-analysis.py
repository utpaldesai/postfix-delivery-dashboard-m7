from pathlib import Path
import sys, tempfile, types

root=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
main=(root/'app/main.py').read_text()
req=(root/'requirements.txt').read_text().lower()
assert 'accept=".eml,.msg' in main
assert 'data_b64' in main
assert 'fileToBase64' in main
assert 'extract-msg' in req

# Exercise the MSG normalization path without requiring the third-party package
# in the source-audit environment.
class FakeMsg:
    def __init__(self, path):
        self.header='Received: from mx.example [198.51.100.10]\r\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\nX-Spam-Score: 7.2\r\nX-Spam-Status: Yes, score=7.2 required=5.0 tests=[BAYES_99=3.5,HTML_MESSAGE=0.1,RCVD_IN_DNSWL=-0.5]'
        self.sender='sender@example.test'; self.to='user@example.test'; self.cc=''; self.subject='MSG test'; self.date='Mon, 24 Aug 2026 17:00:00 +0530'; self.body='test body'; self.htmlBody=None
    def close(self): pass
sys.modules['extract_msg']=types.SimpleNamespace(Message=FakeMsg)
from app.email_analysis import analyze_upload
r=analyze_upload('sample.msg', bytes.fromhex('D0CF11E0A1B11AE1') + b'fake compound payload')
assert r['source_format']=='MSG'
assert r['subject']=='MSG test'
assert r['spamassassin']['verdict']=='SPAM'
assert r['authentication']=={'spf':'pass','dkim':'pass','dmarc':'pass'}
print('AI R1.1.1 MSG analysis regression passed')
