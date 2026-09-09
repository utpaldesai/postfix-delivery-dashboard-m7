from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")
for token in (
    "#quarantineTab .qmail{",
    "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px",
    'class="qrow-select"',
    'class="qside ${cardClass}"',
    'class="qmail-main"',
    'class="qauthbox"',
    'class="qscorebox"',
    'class="qactionbox"',
    'class="qlist-head"',
):
    assert token in main, token
print("Quarantine professional UI test passed")
