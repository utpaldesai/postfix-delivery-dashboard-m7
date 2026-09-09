from pathlib import Path
import tempfile

root = Path(__file__).resolve().parents[1]
main = (root / 'app/main.py').read_text(encoding='utf-8')
trainer = (root / 'app/ai_trainer.py').read_text(encoding='utf-8')
monitor = (root / 'app/monitor.py').read_text(encoding='utf-8')
env = (root / '.env.example').read_text(encoding='utf-8')

# Monitor: IMAP removed from UI/API/new ingestion, historical DB data untouched by code.
assert 'data-monitor-protocol="IMAP"' not in main
assert 'pattern="^(POP3|WEBMAIL)$"' in main
assert 'IMAP login events are intentionally not collected' in main
assert 'IMAP login events are intentionally ignored' in monitor
assert 'DELETE FROM mail_login_events' not in monitor
assert 'TRUNCATE' not in monitor.upper()

# AI feature families; sandbox/network lookups intentionally absent.
for token in ('authentication_alignment','sender_header_anomaly','url_domain','mime_attachment','independent_authentication','nlp_text'):
    assert token in trainer
assert 'HARD_HAM_WEIGHT' in trainer
assert 'balanced-logistic-regression-hashed-v4-authneutral-independent' in trainer
assert 'feature_schema": CURRENT_FEATURE_SCHEMA' in trainer
assert 'no sandboxing' in trainer.lower()
assert 'requests' not in trainer and 'httpx' not in trainer
assert 'AI_TRAINER_HARD_HAM_WEIGHT=1.75' in env

from app.ai_trainer import _extract_features_and_meta
raw = b"""From: Finance Team <billing@vendor.example>\nReply-To: accounts@payments.example\nReturn-Path: <bounce@mailer.example>\nSubject: URGENT: invoice attached - action required\nMessage-ID: <123@mailer.example>\nAuthentication-Results: mx.example; spf=pass smtp.mailfrom=mailer.example; dkim=pass header.d=vendor.example; dmarc=pass header.from=vendor.example\nDKIM-Signature: v=1; d=vendor.example; s=mail; b=abc\nReceived: from relay.vendor.example (relay.vendor.example [8.8.8.8]) by mx.example with ESMTPS;\nContent-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\nPayment overdue. Please review https://billing.vendor.example/invoice and verify your account.\n--x\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=invoice.pdf\n\nPDFDATA\n--x--\n"""
with tempfile.TemporaryDirectory() as td:
    msg = Path(td) / 'sample.eml'
    msg.write_bytes(raw)
    features, meta = _extract_features_and_meta(msg, {'score': '7.2', 'category': 'Spam'})
    assert features
    assert {'nlp_text','authentication_alignment','sender_header_anomaly','url_domain','mime_attachment','independent_authentication'} <= set(meta['feature_families'])
    assert meta['hard_ham_score'] >= 2

print('R1.1.18 Fix4 AI hard-HAM + no-IMAP Monitor regression passed.')
