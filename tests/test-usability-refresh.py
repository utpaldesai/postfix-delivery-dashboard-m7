from pathlib import Path
main=Path("app/main.py").read_text()
assert "Postfix Final Delivery Dashboard" not in main
assert "Postfix Delivery Dashboard" in main
assert "function conciseDetail(" in main
assert "Mailbox over quota" in main
assert "Invalid recipient address" in main
assert "Blocked by RBL" in main
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main
assert ">MARK SPAM</button>" in main
print("Usability refresh test passed")
