from pathlib import Path
import re

main=Path("app/main.py").read_text()
q=Path("app/quarantine.py").read_text()
verify=Path("verify-source.sh").read_text()

# Layout: message metadata in main column, adjacent auth/score/actions retained.
for label in ("From:", "To:", "Subject:", "ID:"):
    pattern = rf'class=["\']qdetails-label["\']\s*>\s*{re.escape(label)}'
    assert re.search(pattern, main), label

for css_class in ("qauthbox", "qscorebox", "qactionbox"):
    pattern = rf'class=["\'][^"\']*\b{css_class}\b[^"\']*["\']'
    assert re.search(pattern, main), css_class

# Optional bulk selection + endpoints.
for token in [
    'id="qSelectAllVisible"',
    'id="qBulkRelease"',
    'id="qBulkSpam"',
    '@app.post("/api/quarantine/bulk-action")',
    'async function quarantineBulkAction(mode)',
]:
    assert token in main, token

# Finalized rows and read-only ACL users cannot be bulk-selected.
assert "const actionDisabled=finalized||!canManageQuarantine;" in main
assert '${actionDisabled?"disabled":""}' in main

# Mailbox normalization is parser-side.
assert "from email.utils import getaddresses" in q
assert "def _clean_mailbox_values(" in q
assert "seen = set()" in q
assert 'from_value = _clean_mailbox_values' in q

# Packaging hygiene.
assert Path("docker-compose.yaml").exists()
assert not Path("docker-compose.yml").exists()
assert "python3 -m py_compile" in verify
assert "python3 audit-build.py" in verify
assert "xargs -0 -n1 -P4" in verify and "PYTHONPATH=. python3" in verify

# Critical Amavis release behavior retained.
wrapper=Path("amavisd-release-wrapper.py").read_text()
assert '["perl", "-T", str(TARGET)' in wrapper

assert "#quarantineTab .qselect-item{" in main
qselect_css=main.split("#quarantineTab .qselect-item{",1)[1].split("}",1)[0]
for token in ("min-width:16px", "min-height:16px", "flex:none", "padding:0"):
    assert token in qselect_css, token

qbulk_css=main.split("#quarantineTab .qbulkselect input{",1)[1].split("}",1)[0]
for token in ("min-width:16px", "min-height:16px", "flex:none", "padding:0"):
    assert token in qbulk_css, token


# Spam score must remain a dedicated adjacent column between auth and actions.
auth_pos=main.find('<div class="qauthbox">')
score_pos=main.find('<div class="qscorebox">')
action_pos=main.find('<div class="qactionbox">')
assert -1 not in (auth_pos, score_pos, action_pos)
assert auth_pos < score_pos < action_pos
assert '<div class="qscorelabel">Spam score</div>' in main
assert '<span class="qscore ${scoreClass}"' in main
assert 'grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px' in main


assert 'class="qlist-head"' in main
assert 'Category / Time' in main
assert 'Message Details' in main
assert 'SPF / DKIM' in main
assert 'Spam Score' in main
assert 'Actions' in main
assert 'class="qrow-select"' in main

print("Milestone 4 quarantine enhancements pack regression test passed")
