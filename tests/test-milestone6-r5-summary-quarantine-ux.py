from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")
db=Path("app/db.py").read_text(encoding="utf-8")

# Summary wording/count semantics.
assert "Emails Sent" in main
assert "Emails Received" in main
assert "Unique Senders" not in main
assert "Unique Recipients" not in main
assert '"emails_sent": emails_sent' in db
assert '"emails_received": emails_received' in db
assert "emails_sent = home_to_external + home_to_home" in db
assert "emails_received = external_to_home + home_to_home" in db

# Bounced summary alignment.
assert 'class="summary-table daily-bounce-table"' in main
assert 'class="bounce-date-col"' in main
assert "daily-bounce-table th.num" in main

# Primary row actions retained; corrective learning may add a contextual third action.
row=main.split('return `\n      <div class="qmail">',1)[1].split('</div>`;',1)[0]
action=row.split('class="qactionbox"',1)[1]
assert action.count("<button") >= 2
assert "RELEASE + HAM" in action
assert "MARK SPAM" in action
assert "LEARN HAM" not in action
assert ">RELEASE<" not in action

# Intelligence remains additive outside the action column.
details=row.split('class="qmail-main"',1)[1].split('class="qauthbox"',1)[0]
assert "Intelligence" in details
assert "openQuarantineIntelligence" in details

# Synchronized top/bottom pager.
for element in ("qTopPrev","qTopNext","qBottomPrev","qBottomNext","qPgTop","qPg"):
    assert f'id="{element}"' in main
assert 'button.disabled=qp<=1' in main
assert 'button.disabled=qp>=qtp' in main

print("Milestone 6 R5 Summary + Quarantine UX regression passed")
