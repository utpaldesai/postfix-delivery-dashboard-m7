import importlib.util
import os
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
ai_path = root / 'app' / 'ai_trainer.py'
text = ai_path.read_text(encoding='utf-8')
assert 'CURRENT_AUTH_POLICY = "identity-neutral-v1"' in text
assert 'balanced-logistic-regression-hashed-v4-authneutral-independent' in text
assert 'if value != "pass"' in text
assert '_sanitize_authentication_policy_features' in text

with tempfile.TemporaryDirectory() as td:
    os.environ['QUARANTINE_STATE_DIR'] = td
    spec = importlib.util.spec_from_file_location('ai_r1128', ai_path)
    ai = importlib.util.module_from_spec(spec); spec.loader.exec_module(ai)
    eml = Path(td) / 'authpass.eml'
    eml.write_text('''From: sales@bulk.example\nTo: user@example.test\nSubject: Special offer buy now\nAuthentication-Results: mx.example; spf=pass smtp.mailfrom=bulk.example; dkim=pass header.d=bulk.example; dmarc=pass header.from=bulk.example\nReceived-SPF: pass\n\nUnsolicited special offer. Buy now and click https://bulk.example/deal\n''', encoding='utf-8')
    features, meta = ai._extract_features_and_meta(eml, {})
    for mech in ('spf','dkim','dmarc'):
        assert ai._hash_token('auth:'+mech+':pass') not in features
        assert ai._hash_token('auth:observed:'+mech) in features
    assert ai._hash_token('authhdr:authentication-results:pass') not in features
    assert ai._hash_token('authhdr:received-spf:pass') not in features

    legacy = {
      ai._hash_token('auth:spf:pass'): 2,
      ai._hash_token('auth:dkim:pass'): 1,
      ai._hash_token('nlp:uce_language'): 3,
    }
    clean = ai._sanitize_authentication_policy_features(legacy)
    assert ai._hash_token('auth:spf:pass') not in clean
    assert ai._hash_token('auth:dkim:pass') not in clean
    assert ai._hash_token('nlp:uce_language') in clean

main=(root/'app/main.py').read_text(encoding='utf-8')
assert 'Identity auth passes' in main
assert 'identity-neutral-v1' in main
assert 'contributes no positive HAM trust weight' in main
print('R1.1.28 authentication-neutral UCE calibration regression passed')
