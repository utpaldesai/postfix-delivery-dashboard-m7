from pathlib import Path
main = Path("app/main.py").read_text(encoding="utf-8")

html_i = main.index('HTML = r"""<!doctype html>')
login_i = main.index('LOGIN_HTML = r"""<!doctype html>')
dashboard = main[html_i:login_i]
login = main[login_i:]

assert "R6.5 Fix 2 — Mail Flow SVG stylesheet belongs to MAIN dashboard" in dashboard
assert ".mail-flow-svg .svg-node>rect" in dashboard
assert "fill:#ffffff!important" in dashboard
assert ".mail-flow-svg .opcard>rect" in dashboard
assert ".mail-flow-svg .modulebox>rect" in dashboard
assert "R6.5 Fix 2 — Mail Flow SVG stylesheet belongs to MAIN dashboard" not in login

# Connector routing no longer crosses the outbound Amavis box.
assert 'M648 292V312H620' in dashboard
assert 'M648 510V414H720' in dashboard

print("R6.5 Fix 2 landing-page CSS placement regression passed")
