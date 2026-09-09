from pathlib import Path
import importlib.util
ROOT=Path(__file__).resolve().parents[1]
MAIN=(ROOT/'app/main.py').read_text()
EMAIL=(ROOT/'app/email_analysis.py').read_text()
assert 'Amavis Global W/B' not in MAIN
assert '/api/amavis-global-wb' not in MAIN
assert 'amavisWbTab' not in MAIN
assert 'z-index:30000' in MAIN and 'max-height:90vh' in MAIN
assert 'approved-mail-flow-image{display:block!important;width:100%' in MAIN
assert 'data-tooltip' in MAIN and 'z-index:31000' in MAIN
assert 'BEC / Impersonation Intelligence' in MAIN
assert 'Why am I suspicious?' in MAIN
assert '_bec_intelligence' in EMAIL
assert 'Email address used in display name' in EMAIL
assert 'From / Reply-To mismatch' in EMAIL
assert 'Shared mail infrastructure' in EMAIL
assert 'Financial / payment lure language' in EMAIL
print('R1.1.8 BEC/UI regression passed')
