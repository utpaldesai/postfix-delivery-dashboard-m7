from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
db=(root/'app/db.py').read_text()
docker=(root/'Dockerfile').read_text()
assert 'data-tab="aiTrainerFlowTab"' in main
assert 'data-tab="aiIntelligenceTab"' in main
assert 'id="qReleased"' in main and '/api/quarantine/released-count' in main
assert 'def released_quarantine_count' in db
assert 'TRUSTED_PROXY_IPS' in main and 'x-forwarded-for' in main and 'x-real-ip' in main
assert 'client_ip=_client_ip(request)' in main
assert 'FROM node:24.20.0-slim AS node_runtime' in docker
assert 'COPY --from=node_runtime /usr/local/bin/node' in docker
# R1.1.25 retires log-derived Home-Domain Email ID MIS.
assert '<h3>Home-Domain Email ID MIS</h3>' not in main
assert '/api/summary/addresses' not in main
print('R1.1.22 consolidated changes compatibility regression passed')
