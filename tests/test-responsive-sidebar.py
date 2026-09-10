from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")

checks=[
    'id="sidebarPin"',
    'id="mobileMenuBtn"',
    'id="sidebarBackdrop"',
    'SIDEBAR_PIN_KEY',
    'localStorage.setItem',
    'body.sidebar-collapsed .sidebar',
    'body.sidebar-mobile-open .sidebar',
    '@media(max-width:820px)',
    'grid-template-columns:repeat(auto-fit',
]
for token in checks:
    assert token in main, token

print("Responsive sidebar test passed")
