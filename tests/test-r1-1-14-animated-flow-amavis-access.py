from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
compose=(root/'docker-compose.yaml').read_text()
env=(root/'.env.example').read_text()
assert 'image: postfix-delivery-dashboard:m7' in compose
assert '${AMAVIS_GID:-130}' in compose
assert '${AMAVIS_LOG_GID:-4}' in compose
assert 'AMAVIS_LOG_DIR:-/var/lib/amavis/logs' in compose
assert ': /host-amavis/logs:ro' not in compose  # avoid malformed mount spacing
assert '/host-amavis/logs:ro' in compose
assert 'AMAVIS_LOG_GID=4' in env
assert 'approved-mail-flow-overlay' in main
assert 'animation:approvedFlowTravel' in main
assert '@keyframes approvedFlowTravel' in main
assert 'one shared Bayes DB' in main
assert 'prefers-reduced-motion' in main
assert 'id="approvedMailFlowFrame" class="approved-mail-flow-frame"' in main
assert '.legacy-mail-flow-runtime{display:none!important}' in main
assert 'Permission denied: container needs read access to the host adm group/GID' in main
assert '#quarantineTab .qmail:has(.qside.banned-card)' in main
assert '#quarantineTab .qmail:has(.qside.virus-card)' in main
assert 'from .amavis_wb import' not in main
assert '/api/amavis-global-wb' not in main
assert not (root/'app/amavis_wb.py').exists()
print('R1.1.14 animated flow / Amavis access regression passed')
