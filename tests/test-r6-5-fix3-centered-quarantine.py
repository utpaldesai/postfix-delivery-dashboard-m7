from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")
assert '<g id="outboundFlowGroup" transform="translate(0 70)">' in main
assert '<g id="sharedQuarantineGroup">' in main
assert 'x="475" y="310" width="390" height="104"' in main
assert "SHARED QUARANTINE" in main
assert 'M648 292V312H620' in main
assert 'M648 510V414H720' in main
assert 'x="910" y="322" width="190" height="80"' in main
assert '<g id="bottomDashboardGroup" transform="translate(0 -22)">' in main
print("R6.5 Fix 3 centered shared quarantine regression passed")
