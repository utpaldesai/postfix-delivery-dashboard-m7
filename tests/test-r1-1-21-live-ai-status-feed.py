from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app" / "main.py").read_text()

assert '@app.get("/api/ai-trainer/status")' in MAIN
assert 'Depends(require_permission("quarantine", "view"))' in MAIN
assert 'AI_TRAINER_LIVE_INTERVAL_MS=10000' in MAIN
assert 'startAiTrainerLiveFeed()' in MAIN
assert 'stopAiTrainerLiveFeed()' in MAIN
assert 'refreshAiTrainerLiveStatus()' in MAIN
assert 'id="aiLiveLabels"' in MAIN
assert 'id="aiLiveAccuracy"' in MAIN
assert 'id="aiLiveBalanced"' in MAIN
assert 'id="aiLiveFp"' in MAIN
assert 'id="aiLiveFn"' in MAIN
assert 'LIVE · 10s' in MAIN
assert 'LIVE FEED DEGRADED' in MAIN
assert 'await refreshAiTrainerLiveStatus();' in MAIN
print("R1.1.21 live AI status feed regression passed")
