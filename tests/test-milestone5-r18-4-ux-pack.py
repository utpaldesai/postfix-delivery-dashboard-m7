from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MAIN=(ROOT/'app/main.py').read_text()
Q=(ROOT/'app/quarantine.py').read_text()
assert 'User Experience Pack' in MAIN
assert 'clearDeliveryFilters()' in MAIN
assert 'clearQuarantineFilters()' in MAIN
assert 'clearAuditFilters()' in MAIN
assert 'deliveryPageSize' in MAIN and 'qPageSize' in MAIN and 'slPageSize' in MAIN and 'auditPageSize' in MAIN
assert 'UX_FILTER_KEY' in MAIN and 'localStorage.setItem(UX_FILTER_KEY' in MAIN
assert 'ux-filter-badge' in MAIN and 'ux-last-refresh' in MAIN
assert 'position:sticky' in MAIN
assert 'Download PNG' not in MAIN
assert 'page_size: int = Query(20, ge=10, le=200)' in MAIN
assert 'effective_page_size' in Q
print('R18.4 UX pack PASS')
