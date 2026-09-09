from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")

assert ("Milestone 4 quarantine correction 1: exact five-column alignment" in main or "Milestone 6 baseline: exact five-column quarantine alignment" in main)
assert 'grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px' in main
assert '<div class="qh-select"></div>' not in main
assert 'class="qselect-cell"' not in main
assert 'class="qrow-select"' in main

# Header is exactly five logical columns.
header=main.split('<div class="qlist-head" aria-hidden="true">',1)[1].split('</div>\n\n<div id="qRows"',1)[0]
for label in ("Category / Time","Message Details","SPF / DKIM","Spam Score","Actions"):
    assert label in header

# Body order must align with those columns.
row=main.split('return `\n      <div class="qmail">',1)[1].split('</div>`;',1)[0]
order=[
    'class="qside ${cardClass}"',
    'class="qmail-main"',
    'class="qauthbox"',
    'class="qscorebox"',
    'class="qactionbox"',
]
positions=[row.index(x) for x in order]
assert positions == sorted(positions)

# Message fields preserve hover titles; recipient hover uses home-domain-only display.
assert 'title="${esc(item.from)}"' in row
assert 'title="${esc(item.display_to||\"No home-domain recipient found\")}"' in row
assert 'title="${esc(item.subject)}"' in row
assert 'title="${esc(item.pdp_id)}"' in row

# R5 single-row actions are intentionally the two primary decisions.
action=row.split('class="qactionbox"',1)[1]
assert 'quarantineReleaseLearnHam(' in action
assert 'quarantineAction("spam"' in action
assert '>RELEASE + HAM<' in action
assert '>MARK SPAM<' in action

print("Quarantine correction 1 regression test passed")
