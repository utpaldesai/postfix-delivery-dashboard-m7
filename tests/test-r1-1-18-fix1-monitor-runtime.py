from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
main = (root / 'app/main.py').read_text()
monitor = (root / 'app/monitor.py').read_text()

# Runtime regression: formatter must exist before Monitor can render any rows.
def_pos = main.find('function fmtDateTime(value)')
load_pos = main.find('async function loadMonitor()')
assert def_pos >= 0, 'fmtDateTime helper is missing'
assert load_pos >= 0, 'loadMonitor is missing'
assert def_pos < load_pos, 'fmtDateTime must be defined before loadMonitor'
assert 'fmtDateTime(x.last_login' in main
assert 'fmtDateTime(x.last_seen' in main
assert 'fmtDateTime(x.event_time' in main

# Summary counters must use the same filter WHERE clause as the displayed rows.
assert "stats_sql = f\"\"\"" in monitor
assert "WHERE {where}" in monitor
assert '"stats": stats' in monitor

# API must not overwrite filtered stats with global DB totals.
summary_api = main[main.find('@app.get("/api/monitor/summary")'):main.find('@app.get("/api/monitor/user-history")')]
assert 'monitor_db_stats()' not in summary_api

# Removed feature remains removed.
assert 'from .amavis_wb import' not in main
assert not (root/'app/amavis_wb.py').exists()
print('R1.1.18 Fix1 Monitor runtime/filter regression passed.')
