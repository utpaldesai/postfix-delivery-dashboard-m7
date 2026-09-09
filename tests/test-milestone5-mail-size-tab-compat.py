from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")
compose=Path("docker-compose.yaml").read_text(encoding="utf-8")
env=Path(".env.example").read_text(encoding="utf-8")

assert 'data-tab="mailSizeTab"' in main
assert 'MAIL_SIZE_API_URL = os.getenv(' in main
assert 'MAIL_SIZE_API_KEY = os.getenv("MAIL_SIZE_API_KEY", "").strip()' in main
assert 'MAIL_SIZE_API_URL:' in compose
assert 'MAIL_SIZE_API_KEY:' in compose
assert 'MAIL_SIZE_API_URL=' in env
assert 'MAIL_SIZE_API_KEY=' in env
assert 'MAIL_SIZE_MANAGER_URL' not in main
assert 'id="mailSizeFrame"' not in main

print("Milestone 5 native Mail Size compatibility test passed")
