from pathlib import Path
import re

main=Path("app/main.py").read_text(encoding="utf-8")
q=Path("app/quarantine.py").read_text(encoding="utf-8")

# Historical filename retained intentionally so an in-place upgrade overwrites
# the old Milestone 4 assertion with current Milestone 5 ACL-aware behavior.

for label in ("From:", "To:", "Subject:", "ID:"):
    assert re.search(
        rf'class=["\']qdetails-label["\']\s*>\s*{re.escape(label)}',
        main,
    ), label

# A row is disabled if already finalized OR the user lacks Quarantine Admin.
assert "const finalized=Boolean(item.is_released||item.is_manual_spam);" in main
assert "const actionDisabled=finalized||!canManageQuarantine;" in main
assert '${actionDisabled?"disabled":""}' in main

# Bulk controls and server endpoint remain present.
for token in (
    'id="qSelectAllVisible"',
    'id="qBulkRelease"',
    'id="qBulkSpam"',
    '@app.post("/api/quarantine/bulk-action")',
    'async function quarantineBulkAction(mode)',
):
    assert token in main, token

# Current approved five-column layout.
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main

# Spam Score popup and front-layer fix remain present.
assert 'class="qscore-hover"' in main
assert 'class="qscore-tooltip"' in main
assert "z-index:10000 !important" in main

# Address normalization and release safety remain present.
assert "from email.utils import getaddresses" in q
assert "def _clean_mailbox_values(" in q

wrapper=Path("amavisd-release-wrapper.py").read_text(encoding="utf-8")
assert '["perl", "-T", str(TARGET)' in wrapper

print("Milestone 5 compatibility test for quarantine enhancements1 passed")
