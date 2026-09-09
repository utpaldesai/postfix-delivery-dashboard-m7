from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")
db=Path("app/db.py").read_text(encoding="utf-8")
compose=Path("docker-compose.yaml").read_text(encoding="utf-8")
env=Path(".env.example").read_text(encoding="utf-8")
module=Path("app/spam_lists.py").read_text(encoding="utf-8")

assert '"spam_lists",' in db
assert 'data-tab="spamListsTab"' in main
assert 'data-tooltip="Whitelist / Blacklist"' in main
assert '<div id="spamListsTab" class="tabpane">' in main

for pref in ("whitelist_auth","whitelist_from","blacklist_from"):
    assert pref in main
    assert pref in module

assert 'if scope == "global":' in module
assert 'return "@GLOBAL"' in module
assert 'return "%" + principal' in module
assert 'return principal' in module

assert '@app.get("/api/spam-lists")' in main
assert '@app.post("/api/spam-lists")' in main
assert '@app.post("/api/spam-lists/{prefid}")' in main
assert '@app.delete("/api/spam-lists/{prefid}")' in main
assert 'Depends(require_permission("spam_lists", "view"))' in main
assert 'Depends(require_permission("spam_lists", "admin"))' in main

assert "INSERT INTO userpref" in module
assert "UPDATE userpref" in module
assert "DELETE FROM userpref" in module
assert "prefid" in module

for key in (
    "SPAM_PREF_DB_HOST",
    "SPAM_PREF_DB_PORT",
    "SPAM_PREF_DB_NAME",
    "SPAM_PREF_DB_USER",
    "SPAM_PREF_DB_PASSWORD",
):
    assert key in compose
    assert key in env

# Existing critical features retained.
assert 'data-tab="mailSizeTab"' in main
assert "./data/reader:/data/reader" in compose
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main


# Live table examples use @GLOBAL as the global username marker.
assert 'username == "@GLOBAL"' in module
assert 'return "@GLOBAL"' in module
assert "@GLOBAL" in main
assert "*@aculife.co.in" not in main  # no site-specific example hardcoded into product UI

print("Milestone 5 SpamAssassin whitelist/blacklist manager regression test passed")
