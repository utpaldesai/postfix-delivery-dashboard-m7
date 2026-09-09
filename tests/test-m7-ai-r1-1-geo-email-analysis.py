from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.email_analysis import analyze_raw
from app.geoip_intelligence import received_public_ips

root = Path(__file__).resolve().parents[1]
main = (root / "app/main.py").read_text(encoding="utf-8")
compose = (root / "docker-compose.yaml").read_text(encoding="utf-8")
req = (root / "requirements.txt").read_text(encoding="utf-8")

assert 'data-tab="emailAnalysisTab"' in main
assert '<h2>Email Analysis</h2>' in main
assert '/api/email-analysis' in main
assert 'GEO-IP Intelligence' in main
assert 'network_lookup' in (root / "app/geoip_intelligence.py").read_text(encoding="utf-8")
assert 'geoip2>=' in req
assert './data/geoip:/data/geoip:ro' in compose
assert 'image: postfix-delivery-dashboard:m7' in compose
assert 'Submission — Port 587' in main
assert '<div class="ms-card-title">Webmail</div>' in main
assert '.ms-profile-pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))' in main

header = """Received: from internal ([10.0.0.3]) by mx.local\nReceived: from relay.example ([8.8.8.8]) by mx.local\n"""
assert received_public_ips(header) == ['8.8.8.8']
raw = b"""Received: from relay.example ([8.8.8.8]) by mx.local\nAuthentication-Results: mx.local; spf=fail; dkim=fail; dmarc=fail\nFrom: bad@example.net\nTo: user@example.org\nSubject: Example\nMessage-ID: <x@example.net>\nX-Spam-Score: 8.7\nX-Spam-Status: Yes, score=8.7 required=5.0 tests=[BAYES_99=3.5,SPF_FAIL=1.5,DKIM_VALID=-0.1]\n\nhello\n"""
result = analyze_raw(raw)
assert result['spamassassin']['score'] == '8.7'
assert result['spamassassin']['verdict'] == 'SPAM'
assert result['authentication'] == {'spf':'fail','dkim':'fail','dmarc':'fail'}
assert result['geoip']['source_ip'] == '8.8.8.8'
assert result['persisted'] is False
assert result['network_lookup'] is False
print('AI R1.1 GEO-IP / Email Analysis regression passed')
