from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MAIN=(ROOT/'app'/'main.py').read_text()
ASSET=ROOT/'app'/'assets'/'dashboard-complete-flowchart-milestone6.png'
assert 'Complete System Flowchart' not in MAIN
assert 'View System Flowchart' not in MAIN
assert '/api/help/flowchart' not in MAIN
assert 'helpFlowchartModal' not in MAIN
assert 'openHelpFlowchart' not in MAIN
assert not ASSET.exists(), 'obsolete Help flowchart asset must not be packaged'
print('Help flowchart removal regression passed.')
