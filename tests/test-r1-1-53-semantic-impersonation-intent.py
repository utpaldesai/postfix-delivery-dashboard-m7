from email import policy
from email.parser import BytesParser
from pathlib import Path
import tempfile

from app import ai_trainer

PHISH = b"""From: admin@finwoodinternational.com <admin@finwoodinternational.com>\nTo: info@nirma.co.in\nSubject: Fwd: Confirm delivery to release pending emails\nMessage-ID: <x@finwoodinternational.com>\nAuthentication-Results: mx.example; dmarc=pass header.from=finwoodinternational.com\nReceived-SPF: pass client-ip=92.119.158.149; envelope-from=admin@finwoodinternational.com\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<html><body>\n<h1>Pending Email Delivery</h1>\n<p>Hello nirma.co.in,</p>\n<p>You have pending emails stuck on our mail server that require delivery confirmation.</p>\n<p><b>Action Required:</b> Confirm delivery to release emails</p>\n<a href=\"https://9fr54o5g57.execute-api.us-east-1.amazonaws.com/prod?key=abc\">Release Pending Emails</a>\n<p>Mail Server Team - nirma.co.in Mail Services</p>\n</body></html>\n"""

LEGIT = b"""From: alerts@vendor.example\nTo: info@nirma.co.in\nSubject: Monthly service report\nMessage-ID: <x@vendor.example>\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<html><body><p>Hello info@nirma.co.in, your monthly service report is ready.</p>\n<a href=\"https://portal.vendor.example/report\">View report</a></body></html>\n"""


def evidence(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    text = ai_trainer.html.unescape((str(msg.get('Subject','')) + '\n' + ai_trainer._body_text(msg)).lower())
    from_domain = ai_trainer._domain_from_address(str(msg.get('From','')))
    urls=[]
    for raw_url in ai_trainer._URL_RE.findall(text):
        candidate = raw_url if '://' in raw_url else 'http://' + raw_url
        try:
            host=(ai_trainer.urlsplit(candidate.rstrip('.,);]>\'\"')).hostname or '').lower().strip('.')
        except Exception:
            host=''
        if host:
            urls.append(host)
    return ai_trainer._semantic_intent_evidence(msg, text, from_domain, urls)


def main():
    ev=evidence(PHISH)
    assert ev['high_confidence'] is True, ev
    assert ev['suggested_label']=='SPAM', ev
    assert ev['suggested_classification']=='CREDENTIAL_PHISHING', ev
    assert 'EXTERNAL_SENDER_CLAIMS_RECIPIENT_MAIL_SERVICE' in ev['signals'], ev
    assert 'RECIPIENT_MAIL_SERVICE_EXTERNAL_ACTION' in ev['signals'], ev
    assert any(x.endswith('execute-api.us-east-1.amazonaws.com') for x in ev['external_action_domains']), ev

    benign=evidence(LEGIT)
    assert benign['high_confidence'] is False, benign
    assert benign['suggested_label']=='', benign

    base={'verdict':'HAM','confidence':91.2,'probabilities':{'HAM':91.2,'SPAM':8.8}}
    over=ai_trainer._apply_semantic_shadow_overlay(base, ev)
    assert over['verdict']=='SPAM', over
    assert over['decision_source']=='SEMANTIC_INTENT_OVERLAY', over
    assert over['semantic_override'] is True, over
    assert over['model_verdict']=='HAM', over
    assert over['model_confidence']==91.2, over
    assert over['model_probabilities']['HAM']==91.2, over

    with tempfile.NamedTemporaryFile(suffix='.eml') as f:
        f.write(PHISH); f.flush()
        features, meta=ai_trainer._extract_features_and_meta(Path(f.name), None)
    assert ai_trainer.CURRENT_FEATURE_SCHEMA == 4
    assert len(meta['feature_families']) == 7, meta['feature_families']
    assert meta['semantic_intent']['high_confidence'] is True
    assert len(features) > 0

    print('R1.1.53 semantic impersonation + action-intent regression: PASS')


if __name__ == '__main__':
    main()
