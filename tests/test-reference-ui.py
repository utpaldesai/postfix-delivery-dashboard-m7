from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")
checks=[
  'class="sidebar"',
  'class="content-shell"',
  'Amavis Quarantine Management',
  'class="qhero"',
  'id="qLastUpdated"',
  'class="qtoolbar"',
  'class="qfooterbar"',
  'class="info-note"',
  '#quarantineTab .qmail{',
  'grid-template-columns:122px',
  'MARK SPAM',
]
for token in checks:
    assert token in main, token
print("Reference-inspired UI test passed")
