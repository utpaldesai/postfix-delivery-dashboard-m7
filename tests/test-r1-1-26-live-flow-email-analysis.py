from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
TRAINER = (ROOT / "app" / "ai_trainer.py").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")

def test_live_multitier_trainer_flow():
    for text in (
        "Multi-Tier Threat Intelligence Framework", "Message AI", "Infrastructure AI",
        "Campaign AI", "Correlation Engine", "Dataset Preflight", "7-Day Calibration",
        "BUILDING DATASET", "SHADOW EXPERIMENTAL",
    ):
        assert text in MAIN
    assert '/api/ai-trainer/status' in MAIN
    assert 'setInterval(refreshAIArchitectureLive,10000)' in MAIN

def test_email_analysis_uses_current_candidate_shadow_only():
    assert 'predict_shadow_candidate_file' in TRAINER
    assert 'ai_predict_shadow_candidate_file(Path(ai_path), result)' in MAIN
    assert 'result["ai_trainer"] = ai_trainer_status()' in MAIN
    assert 'Production Security Evidence · Observation Only' in MAIN
    assert 'No fabricated infrastructure score' in MAIN
    assert 'No fabricated campaign score' in MAIN

def test_safety_and_stable_image_preserved():
    assert 'AI_SHADOW_MODE = True' in TRAINER
    assert 'image: postfix-delivery-dashboard:m7' in COMPOSE
    destructive = ('DROP DATABASE', 'TRUNCATE TABLE', 'rm -rf /var/lib/mysql')
    combined = MAIN + TRAINER
    assert not any(x in combined for x in destructive)
