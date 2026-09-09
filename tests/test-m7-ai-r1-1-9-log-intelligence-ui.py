from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
compose=(root/'docker-compose.yaml').read_text()
assert 'queue_timeline_with_log_fallback' in main
assert 'amavis_log_intelligence' in main
assert '/host-amavis/logs/amavis.log' in main
assert 'AMAVIS_LOG_DIR:-/var/lib/amavis/logs' in compose
assert 'HOST_MAIL_LOG:-/var/log/postfix.log' in compose
assert 'sidebarTooltipPortal' in main and 'showSidebarTooltip' in main
assert 'flow-dialog-open' in main
assert 'HAM→SPAM' in main and 'SPAM→HAM' in main
assert 'Amavis Log Intelligence' in main
assert not (root/'app/amavis_wb.py').exists()
assert 'amavisWbTab' not in main
assert 'Amavis Global W/B' not in main
assert (root/'obsolete-files.manifest').exists()
