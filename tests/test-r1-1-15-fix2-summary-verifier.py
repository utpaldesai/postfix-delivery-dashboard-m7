from pathlib import Path
main=Path("app/main.py").read_text()
verify=Path("verify-source.sh").read_text()
assert "repeat(3,minmax(180px,260px))" in main
assert "max-width:800px" in main
assert 'SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)' in verify
assert 'export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"' in verify
print("R1.1.15 Fix2 summary/verifier regression passed.")
