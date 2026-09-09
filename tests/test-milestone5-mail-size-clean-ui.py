from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")

assert "This tab embeds the existing hardened Postfix Master Manager." not in main
assert "Embedded manager:" not in main
assert 'id="mailSizeFrame"' not in main
assert "Open in New Window" not in main

assert "Manage Email Size" in main
assert "Service Health" not in main
assert "Base64 Size Calculator" in main
assert "Submission — Port 587" in main
assert '<div class="ms-card-title">Webmail</div>' in main
assert "Recent Backups" in main
assert "Audit Trail" in main
assert "Operational Controls" in main

print("Milestone 5 native Mail Size clean UI regression test passed")

assert ".ms-profile-pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))" in main
