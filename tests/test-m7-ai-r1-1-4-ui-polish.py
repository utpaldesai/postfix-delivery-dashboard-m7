from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MAIN=(ROOT/'app'/'main.py').read_text()
COMPOSE=(ROOT/'docker-compose.yaml').read_text()
assert 'image: postfix-delivery-dashboard:m7' in COMPOSE
for label in ['Overview','Mail Operations','Security &amp; Intelligence','Administration','Support']:
    assert label in MAIN
assert 'class="nav-group-label"' in MAIN
assert 'New Limit' in MAIN
assert 'width:6ch' in MAIN
assert 'max="99"' in MAIN  # policy unchanged; compact control is visual only
assert 'Complete System Flowchart' not in MAIN
assert 'View System Flowchart' not in MAIN
assert '/api/help/flowchart' not in MAIN
assert '<h3>Navigation</h3>' in MAIN
assert 'compact four-digit-width numeric New Limit field' in MAIN
print('AI R1.1.4 UI polish regression passed.')
