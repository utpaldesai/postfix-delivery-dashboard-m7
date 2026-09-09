from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_future_amavis_hook_is_reserved_but_hard_disabled():
    trainer = (ROOT / "app" / "ai_trainer.py").read_text()
    env = (ROOT / ".env.example").read_text()
    compose = (ROOT / "docker-compose.yaml").read_text()
    assert 'AI_AMAVIS_HOOK_MODE = os.getenv("AI_AMAVIS_HOOK_MODE", "disabled")' in trainer
    assert '"decision_capable_in_this_release": False' in trainer
    assert '"feeds_ai_features": False' in trainer
    assert 'AI_AMAVIS_HOOK_MODE=disabled' in env
    assert 'AI_AMAVIS_HOOK_MODE: ${AI_AMAVIS_HOOK_MODE:-disabled}' in compose
