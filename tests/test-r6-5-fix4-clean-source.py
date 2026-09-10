from pathlib import Path

root = Path(".")
main = Path("app/main.py").read_text(encoding="utf-8")

assert "SHARED QUARANTINE" in main
assert 'class="flow-red"' in main
assert 'M648 292V312H620' in main
assert 'M648 510V414H720' in main

allowed = {"README.md", "SECURITY-PACK1.md"}
root_md = {p.name for p in root.glob("*.md")}
assert root_md == allowed, root_md
assert Path("licenses/README.md").exists()

print("R6.5 Fix 4 clean-source regression passed")
