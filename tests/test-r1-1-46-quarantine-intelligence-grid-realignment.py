from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
main = (ROOT / "app/main.py").read_text(encoding="utf-8")
readme = (ROOT / "README.md").read_text(encoding="utf-8")

for token in [
    "R1.1.46 — Quarantine Intelligence grid realignment",
    "qintel-review-row",
    "qintel-support-row",
    "qintel-review-solo",
    ".qintel-ai-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))",
    ".qintel-ai-grid{display:grid;grid-template-columns:145px minmax(0,1fr)",
    '<section class="qintel-card qintel-support-pair"><h4>Sender Policy</h4>',
    '<section class="qintel-card qintel-wide"><h4>Dashboard Learning History</h4>',
    "Quarantine Intelligence Grid Layout",
]:
    assert token in main, token

assert "# R1.1.46 — Quarantine Intelligence Grid Realignment" in readme
assert main.count('<section class="qintel-card qintel-support-pair"><h4>Sender Policy</h4>') == 1
assert "DROP TABLE" not in main
assert "TRUNCATE TABLE" not in main
print("R1.1.46 Quarantine Intelligence grid realignment regression passed")
