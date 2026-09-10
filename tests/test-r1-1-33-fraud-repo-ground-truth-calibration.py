from pathlib import Path
import json

root=Path(__file__).resolve().parents[1]
db=(root/'app/db.py').read_text(encoding='utf-8')
main=(root/'app/main.py').read_text(encoding='utf-8')
ai=(root/'app/ai_trainer.py').read_text(encoding='utf-8')
repo=json.loads((root/'local-email-intelligence-repo/local-email-intelligence-2026.09.03-v1.json').read_text(encoding='utf-8'))

# Historical repository tables remain additive for populated-DB compatibility.
for table in ('fraud_repo_versions','fraud_taxonomy','fraud_intent_patterns','fraud_mechanisms','fraud_counter_evidence','fraud_sample_provenance','fraud_regression_cases','fraud_repo_import_audit','ai_ground_truth_calibration'):
    assert f'CREATE TABLE IF NOT EXISTS {table}' in db
for forbidden in ('DROP TABLE fraud_','TRUNCATE TABLE fraud_','DELETE FROM fraud_','DROP DATABASE','CREATE DATABASE'):
    assert forbidden not in db

# R1.1.39 active repository is local-only evidence and never Set-2 authority.
assert repo['version']=='local-email-intel-2026.09.03-v1'
assert repo['source_policy']=='LOCAL_ONLY_NO_THIRD_PARTY_NO_NETWORK_DEPENDENCY'
assert repo['external_sources']==[]
assert repo['training_authority'] is False
assert len(repo['patterns']) >= 15
assert 'LOCAL_RULE_BASE' in db
assert 'training_authority BOOLEAN NOT NULL DEFAULT FALSE' in db

for cls in ('CREDENTIAL_PHISHING','BEC','INVOICE_FRAUD','ADVANCE_FEE_INVESTMENT','INHERITANCE_419','LOTTERY_PRIZE','FAKE_JOB','CHARITY_FRAUD','TECH_SUPPORT','CALLBACK_PHISHING','FAKE_ECOMMERCE','SEO_DIRECTORY'):
    assert cls in ai and cls in main
assert 'Acknowledge AI Proposal' in main
assert 'Save Changed Ground Truth' in main
assert 'Only explicit administrator action creates Set-2 Ground Truth' in main
assert 'Local Email Intelligence Repository' in main
print('R1.1.33 compatibility + R1.1.39 local repository regression passed')
