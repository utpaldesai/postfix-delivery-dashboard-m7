from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")
db=Path("app/db.py").read_text(encoding="utf-8")
q=Path("app/quarantine.py").read_text(encoding="utf-8")

for token in (
    'value="equals">Equals',
    'value="not_equal">Not equal',
    'value="begins_with">Begins with',
    'value="ends_with">Ends with',
    'value="contains" selected>Contains',
    'value="does_not_contain">Does not contain',
):
    assert token in main, token

for element_id in ("searchOperator","qSearchOperator","auditSearchOperator"):
    assert f'id="{element_id}"' in main

assert 'search_operator: str = "contains"' in main
assert 'q_operator: str = "contains"' in main
assert "TEXT_FILTER_OPERATORS" in db
assert "def _text_filter_clause(" in db
assert "def _text_filter_match(" in q
assert 'search_operator:searchOperator' in main
assert 'q_operator:document.getElementById("qSearchOperator").value' in main
assert 'q_operator:document.getElementById("auditSearchOperator").value' in main

# Negative operators must use all-field exclusion semantics.
assert 'joiner = " AND "' in db
assert 'return all(value != needle for value in haystacks)' in q
assert 'return all(needle not in value for value in haystacks)' in q

# Delivery dashboard top spacing.
assert "#deliveryTab{" in main
assert "padding-top:18px" in main

# Existing protected features.
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main
assert 'data-tab="aclTab"' in main
assert 'data-tab="helpTab"' in main
assert '@app.get("/api/summary/bounces/detail")' in main
assert "z-index:10000 !important" in main

print("Milestone 5 Excel-style text filters regression test passed")
