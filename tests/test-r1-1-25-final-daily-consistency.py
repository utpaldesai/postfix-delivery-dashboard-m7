from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
db=(root/'app/db.py').read_text()
compose=(root/'docker-compose.yaml').read_text()
docker=(root/'Dockerfile').read_text()
help_text=main
# Removed non-authoritative log-derived mailbox MIS, including backend/API/UI remnants.
for stale in ('<h3>Home-Domain Email ID MIS</h3>','/api/summary/addresses','home_address_summary','home_address_details','homeAddressRows','openAddressDetail','addressDetailModal','home-address-mis'):
    assert stale not in (main+db)
# Daily bounce report uses a bounded compact layout and retains meaningful drill-down.
assert 'daily-bounce-compact' in main and 'max-width:760px' in main
assert 'width:78px' in main
assert '<th class="num">Recv</th><th class="num">Total</th>' in main
assert 'bounceCountButton' in main and 'openBounceDetail' in main
assert '/api/summary/bounces/detail' in main
# Released is count-only and cannot be mistaken for a filter/drill-down control.
assert 'qmetric released qmetric-static' in main
assert '<small>Count only</small>' in main
assert 'data-qfilter="Released"' not in main
# Live graphical AI and endpoint remain consistent.
assert 'ai-graph-shell' in main and 'SHADOW VERDICT' in main and 'NO MAIL ACTION' in main
assert 'apiFetch("/api/ai-trainer/status")' in main
# Stable deployment/runtime conventions.
assert 'image: postfix-delivery-dashboard:m7' in compose
assert 'FROM node:24.20.0-slim AS node_runtime' in docker
# Help explains intentional MIS retirement.
assert 'retired Home-Domain Email ID MIS' in help_text
print('R1.1.25 final daily consistency regression passed')
