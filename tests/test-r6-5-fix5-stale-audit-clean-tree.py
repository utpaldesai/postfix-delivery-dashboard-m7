from pathlib import Path
import subprocess, sys

assert not Path("MILESTONE6.md").exists()
assert Path("README.md").exists()

proc = subprocess.run(
    [sys.executable, "stale-reference-audit.py"],
    capture_output=True,
    text=True,
    timeout=30,
)
assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
assert "FileNotFoundError" not in (proc.stdout + proc.stderr)

print("R6.5 Fix 5 stale-reference audit clean-tree regression passed")
