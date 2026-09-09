import re
from pathlib import Path
lines=Path('docker-compose.yaml').read_text().splitlines()
start=next(i for i,l in enumerate(lines) if l.strip()=='group_add:')
body=[]
for line in lines[start+1:]:
    if line.startswith('    ') and not line.startswith('      '):
        break
    body.append(line)
text='\n'.join(body)
defaults=[x.strip() for x in re.findall(r'\$\{[^}:]+:-([^}]+)\}', text)]
assert len(defaults)==len(set(defaults)), f'duplicate default GIDs in group_add: {defaults}'
assert 'MONITOR_MAIL_LOG_GID' not in text
print('R1.1.16 compose group_add uniqueness regression passed.')
