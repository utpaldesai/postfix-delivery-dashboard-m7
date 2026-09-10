from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")
assert 'function bindMailFlowSvgNavigation()' in main
assert 'svg.querySelectorAll(".svg-click[data-flow-target]")' in main
assert 'data-flow-target="quarantineTab"' in main
assert 'data-flow-status="BLOCKED"' in main
assert 'data-flow-status="DEFERRED"' in main
assert 'data-flow-status="DELIVERED"' in main
assert 'class="opcard svg-click"' in main
assert 'class="modulebox svg-click"' in main
assert 'class="flow-red"' in main
assert 'M648 292V312H620' in main
assert 'M648 510V414H720' in main
assert '/api/quarantine?page=1&page_size=10' in main
print("R6.5 interactive SVG Mail Flow regression passed")
