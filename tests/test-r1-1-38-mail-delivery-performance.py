from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MAIN=(ROOT/"app/main.py").read_text(encoding="utf-8")
DB=(ROOT/"app/db.py").read_text(encoding="utf-8")
README=(ROOT/"README.md").read_text(encoding="utf-8")

def test_interactive_delivery_skips_blocking_exact_count():
    assert 'include_total:"false"' in MAIN
    assert 'include_total: bool = Query(True)' in MAIN
    assert 'fetch_size = size if include_total else size + 1' in DB
    assert 'if include_total:' in DB
    assert '"has_more": has_more' in DB

def test_visible_rows_are_loaded_before_global_statistics():
    load=MAIN[MAIN.index('async function load(){'):MAIN.index('async function openFlow') ]
    assert load.index('await apiFetch("/api/deliveries?"+query') < load.index('apiFetch("/api/statistics"')
    assert 'Loading Mail Delivery…' in load
    assert 'deliveryHasMore=Boolean(data.has_more)' in load

def test_stale_requests_and_search_storms_are_bounded():
    assert 'deliveryLoadController.abort()' in MAIN
    assert 'signal=deliveryLoadController.signal' in MAIN
    assert 'deliverySearchTimer=setTimeout(()=>load(),350)' in MAIN

def test_help_and_release_document_performance_behavior():
    assert 'global counters refresh afterward so they do not block the table' in MAIN
    assert 'R1.1.38 — Mail Delivery performance optimization' in README

def test_existing_delivery_semantics_still_present():
    assert 'GROUP_CONCAT(' in DB
    assert "WHEN SUM(final_status='BLOCKED') > 0 THEN 'BLOCKED'" in DB
    assert 'openFlow(' in MAIN
