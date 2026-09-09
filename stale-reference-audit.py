#!/usr/bin/env python3
from pathlib import Path
import sys
errors=[]
active_files=[
    Path('app/main.py'),Path('app/quarantine.py'),Path('Dockerfile'),Path('docker-compose.yaml'),
    Path('.env.example'),Path('verify-source.sh'),Path('verify-running.sh'),Path('audit-build.py'),
    Path('full-rebuild.sh'),Path('preflight-upgrade.py'),Path('README.md'),Path('SECURITY-PACK1.md'),
]
forbidden={
    'Dashboard Milestone 5':'old visible dashboard label',
    'Postfix Delivery Dashboard — Milestone 5':'old current-page label',
    'postfix-delivery-dashboard:milestone5-security-pack1':'old active image tag',
    'postfix-delivery-dashboard:milestone6-r3-release-fix2':'old active image tag',
    'postfix-delivery-dashboard:milestone6-r6.5-fix1':'old active image tag',
    'dashboard-complete-flowchart-r18.4.png':'old help asset',
    'm7-enterprise-ai-r1.1.3-help-update':'previous active image tag',
    'Complete System Flowchart':'removed Help feature',
    '/api/help/flowchart':'removed Help feature',
}
for path in active_files:
    if not path.exists():
        errors.append(f'missing active file: {path}')
        continue
    text=path.read_text(encoding='utf-8',errors='replace')
    for token,desc in forbidden.items():
        if token in text: errors.append(f'{path}: {desc}: {token}')
for path in Path('tests').glob('test*.py'):
    text=path.read_text(encoding='utf-8',errors='replace')
    for token in (
        'postfix-delivery-dashboard:milestone5-security-pack1',
        'postfix-delivery-dashboard:milestone6-r3-release-fix2',
        'R6.5 Fix 1 source verification passed.',
    ):
        if token in text: errors.append(f'{path}: stale compatibility assertion: {token}')
if Path('fraud-repo').exists(): errors.append('obsolete bundled fraud-repo directory present')
for oldname in ('external-email-corpus-registry-2026.09.03.json','fraud-intelligence-2026.09.03-v2.json','fraud-intelligence-2026.09.03-v3.json'):
    if any(Path('.').rglob(oldname)): errors.append(f'obsolete bundled repository file present: {oldname}')
if Path('docker-compose.yml').exists(): errors.append('duplicate docker-compose.yml present')
if not Path('docker-compose.yaml').exists(): errors.append('docker-compose.yaml missing')
root_md={p.name for p in Path('.').glob('*.md')}
allowed_md={'README.md','SECURITY-PACK1.md'}
if root_md != allowed_md: errors.append(f'root markdown set must be {sorted(allowed_md)}, got {sorted(root_md)}')
if errors:
    print('STALE REFERENCE AUDIT FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print('STALE REFERENCE AUDIT PASSED - Milestone 7 Enterprise')
