from pathlib import Path
main = Path("app/main.py").read_text(encoding="utf-8")

# Inspect the login-page area only; internal milestone references elsewhere are allowed.
idx = main.find('id="login')
if idx < 0:
    idx = main.find("Login")
assert idx >= 0
window = main[max(0, idx-5000):idx+15000]
assert "Milestone 6" not in window
assert "Postfix Delivery Dashboard" in window

print("Login milestone branding removal regression passed")
