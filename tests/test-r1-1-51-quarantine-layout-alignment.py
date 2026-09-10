from pathlib import Path

main = (Path(__file__).resolve().parents[1] / "app" / "main.py").read_text()
assert '.qintel-ai-metrics.qintel-ai-metrics-single{grid-template-columns:minmax(0,1fr)}' in main
assert 'qintel-ai-metrics qintel-ai-metrics-single' in main
assert 'Independent Attachment Intelligence' in main
assert 'Infrastructure AI · LOCAL' in main
assert 'Campaign AI · LOCAL' in main
assert 'R1.1.51 keeps Quarantine Intelligence' in main
print('R1.1.51 Quarantine Intelligence layout alignment regression: PASS')
