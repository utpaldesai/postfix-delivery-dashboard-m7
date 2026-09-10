from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/'app/main.py').read_text(encoding='utf-8')
monitor=(ROOT/'app/monitor.py').read_text(encoding='utf-8')
db=(ROOT/'app/db.py').read_text(encoding='utf-8')
readme=(ROOT/'README.md').read_text(encoding='utf-8')

assert 'CREATE TABLE IF NOT EXISTS mail_login_user_summary' in db
assert 'CREATE TABLE IF NOT EXISTS mail_login_summary_state' in db
assert 'def ensure_monitor_summary_projection()' in db
assert 'idx_mail_login_summary_protocol_time' in db
assert 'idx_mail_login_protocol_time_id' in db
assert 'query_mode": "summary_projection_fastpath"' in monitor
assert 'FROM mail_login_user_summary' in monitor
assert 'if not str(search or "").strip() and not date_from and not date_to' in monitor
assert 'FROM mail_login_events' in monitor
section=main[main.index('@app.get("/api/monitor/summary")'):main.index('@app.get("/api/monitor/pop3-logins")')]
assert 'sync_login_events()' not in section
assert 'monitorRequestController.abort()' in main
assert 'setTimeout(()=>loadMonitor().catch(()=>{}),350)' in main

assert '<button class="tabbtn active" data-tab="deliveryTab"' in main
assert '<button class="tabbtn active" data-tab="flowTab"' not in main
assert 'class="help-visual-tile" type="button" data-tab="flowTab"' in main
assert 'class="help-visual-tile" type="button" data-tab="aiTrainerFlowTab"' in main
assert 'class="help-visual-tile" type="button" data-tab="aiIntelligenceTab"' in main
assert 'function openHelpVisualization(tabId)' in main
assert 'function returnToHelp()' in main
assert main.count('← Back to Help') >= 3
assert '"deliveryTab","summaryTab","monitorTab"' in main
assert 'R1.1.42 — Login Summary Fast Paths + Help Visualization Tiles' in readme
print('R1.1.42 login fast-path + Help visualization tiles regression passed')
