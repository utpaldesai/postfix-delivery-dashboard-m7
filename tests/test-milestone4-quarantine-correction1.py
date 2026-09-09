from pathlib import Path

main = Path("app/main.py").read_text(encoding="utf-8")

# Historical test filename retained so upgrades over an existing Milestone 4
# directory overwrite the stale test instead of leaving an obsolete assertion.
assert "Milestone 6 baseline: exact five-column quarantine alignment" in main
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main
assert '<div class="qh-select"></div>' not in main
assert 'class="qselect-cell"' not in main
assert 'class="qrow-select"' in main

header = main.split(
    '<div class="qlist-head" aria-hidden="true">', 1
)[1].split('</div>\n\n<div id="qRows"', 1)[0]

for label in (
    "Category / Time",
    "Message Details",
    "SPF / DKIM",
    "Spam Score",
    "Actions",
):
    assert label in header

row = main.split(
    'return `\n      <div class="qmail">', 1
)[1].split('</div>`;', 1)[0]

order = [
    'class="qside ${cardClass}"',
    'class="qmail-main"',
    'class="qauthbox"',
    'class="qscorebox"',
    'class="qactionbox"',
]
positions = [row.index(token) for token in order]
assert positions == sorted(positions)

print("Milestone 5 quarantine correction compatibility test passed")
