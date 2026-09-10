from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
# R1.1.37 external repository experiment is superseded in R1.1.39.
assert not (ROOT/'fraud-repo').exists()
assert not (ROOT/'harmful-email-repo').exists()
assert (ROOT/'local-email-intelligence-repo').is_dir()
s=(ROOT/'app/main.py').read_text()
for token in ['Time (IST)','Final Status','Prediction source','Prediction status','Acknowledge AI Proposal','Save Changed Ground Truth','Reset','Review / reversal reason','Notes (optional)','Local intelligence repository']:
    assert token in s, token
assert 'qintel-identity-grid{grid-template-columns:repeat(8' in s
assert 'overflow-x:hidden' in s
assert 'admin_notes' in s
print('R1.1.37 layout compatibility retained; external repo superseded by R1.1.39 local repository')
