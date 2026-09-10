from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
db=(root/'app/db.py').read_text()
compose=(root/'docker-compose.yaml').read_text()
# R1.1.25 intentionally removes the log-derived per-address MIS and its drill-down.
for stale in ('/api/summary/addresses/detail','openAddressDetail','homeAddressRows','home_address_details','_normal_home_mailbox'):
    assert stale not in (main+db)
# Daily bounced-domain counts retain the approved compact drill-down pattern.
assert 'daily-bounce-compact' in main
assert 'bounceCountButton' in main and 'openBounceDetail' in main
assert 'image: postfix-delivery-dashboard:m7' in compose
print('R1.1.23 superseded MIS regression passed')
