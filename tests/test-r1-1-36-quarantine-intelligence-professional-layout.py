from pathlib import Path

main = Path("app/main.py").read_text()
for token in [
    "qintel-identity-grid",
    "qintel-ai-primary",
    "qintel-ground-truth",
    "qintel-wide",
    "Current Message Identity",
    "Prediction source",
    "SHADOW ONLY ·",
    "Amavis Current Message Trace",
]:
    assert token in main, token
assert "width:min(1480px,98vw)" in main
assert "overflow-x:hidden" in main
assert "grid-template-columns:minmax(0,3fr) minmax(360px,2fr)" in main
assert "result[\"message_identity\"]" in main
assert "DROP TABLE" not in main
assert "TRUNCATE TABLE" not in main
print("R1.1.36 Quarantine Intelligence professional layout regression passed")
