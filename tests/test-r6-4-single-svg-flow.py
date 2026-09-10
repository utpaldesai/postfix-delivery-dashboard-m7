from pathlib import Path
main=Path('app/main.py').read_text(encoding='utf-8')
assert '<svg id="mailFlowSvg"' in main
assert 'viewBox="0 0 1600 900"' in main
assert 'preserveAspectRatio="xMidYMid meet"' in main
for text in ('INBOUND MAIL FLOW','OUTBOUND MAIL FLOW','SHARED QUARANTINE','AMAVIS QUARANTINE','MAIL OPERATIONS','POSTFIX DELIVERY DASHBOARD','LEGEND'):
    assert text in main, text
assert '/api/quarantine?page=1&page_size=10' in main
assert '/api/quarantine/list' not in main
assert 'dynamicFlowRows' not in main
assert 'flow-poster-canvas' not in main
assert 'visual-process' not in main
assert 'SCADA' not in main
print('R6.4 single-SVG Mail Flow regression passed')
