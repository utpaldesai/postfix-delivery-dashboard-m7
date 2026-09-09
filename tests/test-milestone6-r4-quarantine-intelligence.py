from pathlib import Path

main = Path('app/main.py').read_text(encoding='utf-8')
q = Path('app/quarantine.py').read_text(encoding='utf-8')
intel = Path('app/quarantine_intelligence.py').read_text(encoding='utf-8')
sql = Path('sql/maildb-dashboard-learning-history.sql').read_text(encoding='utf-8')
dockerfile = Path('Dockerfile').read_text(encoding='utf-8')

# Additive intelligence and Release+HAM workflow.
assert '@app.get("/api/quarantine/intelligence")' in main
assert '@app.post("/api/quarantine/release-learn-ham")' in main
assert 'quarantine_release(pdp_id, remote_addr, username)' in main
assert 'quarantine_learn_ham(pdp_id, remote_addr, username)' in main
assert 'Intelligence' in main
assert 'RELEASE + HAM' in main

# Existing backend actions remain available; R5 intentionally exposes only
# Release+HAM and Mark Spam as the two primary row decisions.
assert 'quarantine_release(pdp_id, remote_addr, username)' in main
assert 'onclick=\'quarantineAction("spam"' in main
assert 'def release(pdp_id: str, remote_addr: str, username: str = ""):' in q
assert 'def mark_spam(pdp_id: str, remote_addr: str, username: str = ""):' in q
assert 'LEARN_SPAM_DB = STATE_DIR / "learn_spam_ids.db"' in q
assert 'LEARN_HAM_DB = STATE_DIR / "learn_ham_ids.db"' in q

# Current Quarantine Intelligence keeps only message-relevant maildb evidence.
# Generic host table inventory and Bayes statistics were intentionally removed in R1.1.40.
assert '_sender_policy' in intel
assert '_history' in intel
assert 'def _table_overview' not in intel
assert 'def _bayes_stats' not in intel
assert '<h4>Bayes Learning</h4>' not in main
assert '<h4>Host maildb Tables</h4>' not in main
for forbidden in ('INSERT INTO bayes_', 'UPDATE bayes_', 'DELETE FROM bayes_', 'INSERT INTO txrep', 'UPDATE txrep'):
    assert forbidden not in intel

# Dashboard owns only its new history table.
assert 'dashboard_learning_history' in sql
assert 'GRANT SELECT, INSERT ON maildb.dashboard_learning_history' in sql
assert '_record_learning_history_best_effort' in q

# Logout remains reachable at 100% browser scale by scrolling only navigation.
assert '.sidebar{height:100dvh;max-height:100dvh;overflow:hidden}' in main
assert '.side-nav{flex:1 1 auto;min-height:0;overflow-y:auto' in main

# Previously requested low-risk fixes remain in this pack.
assert 'stats.spam??stats.quarantined??0' in main
assert '--no-server-header' in dockerfile

print('Milestone 6 R4 Quarantine Intelligence regression test passed')
