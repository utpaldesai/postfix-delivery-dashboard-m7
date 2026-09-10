from pathlib import Path

db = Path("app/db.py").read_text(encoding="utf-8")
main = Path("app/main.py").read_text(encoding="utf-8")

# Summary UI reports message/delivery counts, not distinct-address counts.
assert '"emails_sent": emails_sent' in db
assert '"emails_received": emails_received' in db
assert 'id="emailsSent"' in main
assert 'id="emailsReceived"' in main
assert "Unique Senders" not in main
assert "Unique Recipients" not in main

# Old API keys stay available only for backward compatibility.
assert '"unique_senders"' in db
assert '"unique_recipients"' in db

assert "<h3>Daily Domain Summary</h3>" not in main
assert "<h3>Daily Bounced Domain Summary</h3>" in main

print("Mail Direction message-count summary test passed")
