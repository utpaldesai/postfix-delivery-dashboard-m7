from pathlib import Path
main=Path('app/main.py').read_text(encoding='utf-8')
assert '<svg id="mailFlowSvg"' in main
assert 'viewBox="0 0 1600 900"' in main
assert 'INBOUND MAIL FLOW' in main and 'OUTBOUND MAIL FLOW' in main
assert 'AMAVIS QUARANTINE' in main and 'MAIL OPERATIONS' in main
assert '/api/quarantine?page=1&page_size=10' in main
assert '/api/quarantine/list' not in main
print('Mail Flow compatibility regression passed')
