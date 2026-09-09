from pathlib import Path
m=Path('app/main.py').read_text()
decl=m.index('const sidebarTooltipPortal=document.getElementById("sidebarTooltipPortal")')
listener=m.index('document.querySelectorAll(".side-nav .tabbtn")', decl)
init=m.index('\napplySidebarState();', listener)
assert decl < listener < init
# no top-level apply between resize handler close and portal declaration
segment=m[m.index('window.addEventListener("resize"'):decl]
assert '\napplySidebarState();' not in segment
route=m[m.index('@app.get("/api/mail-flow/approved-image")'):m.index('@app.get("/api/mail-flow/approved-image")')+260]
assert 'Depends(require_permission' not in route
flow=m[m.index('@app.get("/api/flow/{queue_id}")'):m.index('@app.get("/api/flow/{queue_id}")')+300]
assert 'Depends(require_permission("mail_flow", "view"))' in flow
assert 'from .amavis_wb import' not in m
assert 'data-tab="amavisWbTab"' not in m
assert not Path('app/amavis_wb.py').exists()
assert '/host-amavis/logs/amavis.log' in m
assert 'live_log' in m
print('R1.1.11 stability regression passed.')
