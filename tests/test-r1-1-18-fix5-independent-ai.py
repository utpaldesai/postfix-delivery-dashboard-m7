from pathlib import Path

root=Path(__file__).resolve().parents[1]
trainer=(root/'app/ai_trainer.py').read_text(encoding='utf-8')
main=(root/'app/main.py').read_text(encoding='utf-8')

# AI decision must be independent of SpamAssassin/Amavis verdict/score/rules.
assert 'balanced-logistic-regression-hashed-v4-authneutral-independent' in trainer
assert 'CURRENT_FEATURE_SCHEMA = 4' in trainer
assert 'X-Spam-Status' not in trainer
assert 'X-Spam-Flag' not in trainer
assert 'X-Spam-Level' not in trainer
assert 'amavis:category:' not in trainer
assert 'sa:score:' not in trainer
assert 'sarule:' not in trainer
assert 'reputation:sa_rule:' not in trainer
assert 'independent_authentication' in trainer
assert 'migrate_legacy_feature_rows' in trainer
assert 'Independent generation started. No active independent model has been promoted yet.' in trainer
assert 'SpamAssassin score, rule hits, X-Spam headers, Amavis verdict/category and quarantine state are excluded' in main

# Existing legacy rows are preserved for audit but are not migrated into clean-generation training.
assert 'disabled_for_clean_generation' in trainer
assert '_model_is_current_generation' in trainer

# IMAP operational Monitor view remains removed from the prior fix.
assert 'value="IMAP"' not in main
print('R1.1.18 Fix5 independent AI regression passed')


# Changing only SA/Amavis evidence must not change the independent feature vector.
import tempfile
from app import ai_trainer as ai
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    common_headers="""From: sender@example.test
To: user@example.test
Subject: Online Training
Authentication-Results: mx.example; spf=pass smtp.mailfrom=example.test; dkim=pass header.d=example.test; dmarc=pass header.from=example.test
Received-SPF: pass
Content-Type: text/plain; charset=utf-8
"""
    body="\nPlease join the online training meeting tomorrow.\n"
    a=td/'a.eml'; b=td/'b.eml'
    a.write_text(common_headers+'X-Spam-Status: Yes, score=12.0 tests=RCVD_IN_UCEPROTECT3\n'+body,encoding='utf-8')
    b.write_text(common_headers+'X-Spam-Status: No, score=-1.0 tests=ALL_TRUSTED\n'+body,encoding='utf-8')
    fa,_=ai._extract_features_and_meta(a, {'category':'spam','score':12.0,'spf':'fail'})
    fb,_=ai._extract_features_and_meta(b, {'category':'clean','score':-1.0,'spf':'pass'})
    assert fa == fb, 'SA/Amavis-only differences changed independent AI features'
print('SA/Amavis independence vector regression passed')
