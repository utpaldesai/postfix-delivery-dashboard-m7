from pathlib import Path

db = Path("app/db.py").read_text(encoding="utf-8")
assert 'hashlib.pbkdf2_hmac(' in db
assert '"sha256"' in db
assert '260000' in db
assert 'PASSWORD_PBKDF2_ROUNDS = 600000' not in db
assert 'PASSWORD_PBKDF2_LEGACY_ROUNDS' not in db
print("Milestone 6 R3 password compatibility regression passed")
