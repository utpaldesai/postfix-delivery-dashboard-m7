from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
compose=(root/'docker-compose.yaml').read_text()
assert 'graphical live trainer state' in main
assert 'ai-graph-shell' in main and 'tfTrainingNode' in main and '7-Day Calibration' in main
assert 'Infrastructure AI' in main and 'Campaign AI' in main and 'Independent Evidence Fusion' in main
assert 'SHADOW VERDICT' in main and 'NO MAIL ACTION' in main
assert 'apiFetch("/api/ai-trainer/status")' in main
assert 'apiFetch("/api/ai/trainer/status")' not in main
assert 'daily-bounce-compact' in main and 'summary-count-link' in main
assert '<h3>Home-Domain Email ID MIS</h3>' not in main
assert 'image: postfix-delivery-dashboard:m7' in compose
print('R1.1.24 graphical AI compatibility regression passed')
