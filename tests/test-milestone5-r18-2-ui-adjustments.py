from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/"app"/"main.py").read_text(encoding="utf-8")
quarantine=(ROOT/"app"/"quarantine.py").read_text(encoding="utf-8")

# 1. Mail Size no longer shows Service Health.
assert "Service Health" not in main
assert 'id="mailSizeServices"' not in main

# 2. Help flowchart remains viewable but has no dashboard download action.
assert "Download PNG" not in main
assert "download=1" not in main

# 3. Spam list table checkboxes align to compact table font size.
assert '.sl-row-check,.sl-select-visible{width:11px;height:11px;margin:0;vertical-align:middle;' in main

# 4. Quarantine adds field selector before the existing text operator.
field_pos=main.index('id="qSearchField"')
operator_pos=main.index('id="qSearchOperator"')
assert field_pos < operator_pos
assert '<option value="from">From</option>' in main
assert '<option value="to">To</option>' in main
assert 'q_field:document.getElementById("qSearchField").value' in main
assert 'q_field: str = "all"' in main
assert 'q_field="all"' in quarantine
assert 'q_field == "from"' in quarantine
assert 'q_field == "to"' in quarantine

print("Milestone 5 R18.2 requested UI adjustments regression passed")
