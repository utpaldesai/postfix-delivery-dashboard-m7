from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
qi=(root/'app/quarantine_intelligence.py').read_text()
readme=(root/'README.md').read_text()

assert '<h4>Bayes Learning</h4>' not in main
assert '<h4>Host maildb Tables</h4>' not in main
assert 'Loading host maildb intelligence' not in main
assert 'const bayes=data.bayes||{}' not in main
assert 'const tables=data.tables||[]' not in main
assert 'KNOWN_TABLES' not in qi
assert 'def _table_overview' not in qi
assert 'def _bayes_user' not in qi
assert 'def _bayes_stats' not in qi
assert '"bayes_user"' not in qi
assert '"bayes":' not in qi
assert '"tables": overview' not in qi
assert 'sender_policy' in qi and 'history' in qi
assert 'R1.1.40 — Quarantine Intelligence Cleanup' in readme
print('R1.1.40 Quarantine Intelligence Bayes/maildb-table cleanup regression passed')
