from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")
helper=Path("host-tools/mail-size-api.php").read_text(encoding="utf-8")
installer=Path("host-tools/install-mail-size-api.sh").read_text(encoding="utf-8")

assert "def _mail_size_api_request(" in main
assert 'UrlRequest(' in main
assert '"X-Mail-Size-Key": MAIL_SIZE_API_KEY' in main
assert 'MAIL_SIZE_API_TIMEOUT' in main

assert "Loopback access required" in helper
assert "Invalid API key" in helper
assert "cooldown_remaining" in helper
assert "profile_state" in helper
assert "sudo /usr/local/bin/deploy_postfix.sh" in helper
assert "restore " in helper
assert "basename(" in helper
assert "realpath(" in helper

assert 'KEY_DIR="/etc/postfix-web"' in installer
assert 'KEY_FILE="$KEY_DIR/mail-size-api.key"' in installer
assert "MAIL_SIZE_API_URL" in installer
assert "MAIL_SIZE_API_KEY" in installer

print("Milestone 5 native Mail Size helper regression test passed")
