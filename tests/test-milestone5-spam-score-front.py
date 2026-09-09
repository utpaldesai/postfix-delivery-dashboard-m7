from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")

assert "Milestone 5 R5 - keep Spam Score hover above quarantine rows" in main
assert "#quarantineTab .qmail-list{" in main
assert "overflow:visible !important" in main
assert "#quarantineTab .qmail:hover" in main
assert "#quarantineTab .qmail:focus-within" in main
assert "z-index:500" in main
assert "#quarantineTab .qscore-tooltip{" in main
assert "z-index:10000 !important" in main

# No approved grid-width change.
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main

print("Milestone 5 Spam Score front-layer regression test passed")
