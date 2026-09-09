from pathlib import Path
main = Path('app/main.py').read_text()
session = Path('app/session_auth.py').read_text()
env = Path('.env.example').read_text()
assert 'IDLE_TIMEOUT_MINUTES = max(1, int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "15")))' in session
assert 'session_store.touch(token)' in main
assert 'AUTO_LOGOUT_INACTIVITY' in main
assert 'window.location="/login"' in main
assert 'SESSION_IDLE_TIMEOUT_MINUTES=15' in env
print('Milestone 1 inactivity timeout compatibility test passed')
