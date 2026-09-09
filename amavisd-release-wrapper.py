#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path(os.getenv("AMAVIS_RELEASE_SOURCE", "/opt/host-amavis/amavisd-release"))
PDP_SERVER = os.getenv("AMAVIS_PDP_SERVER", "127.0.0.1:9998").strip()

if not re.fullmatch(r"(?:127\.0\.0\.1|localhost):[0-9]{1,5}", PDP_SERVER):
    print(f"ERROR: unsupported AMAVIS_PDP_SERVER={PDP_SERVER!r}", file=sys.stderr)
    sys.exit(64)
if not SOURCE.is_file():
    print(f"ERROR: host amavisd-release not mounted at {SOURCE}", file=sys.stderr)
    sys.exit(66)

text = SOURCE.read_text(encoding="utf-8", errors="strict")
pattern = re.compile(r"(?m)^(\s*)\$socketname\s*=\s*(['\"])(.*?)\2\s*;\s*$")

def repl(match):
    return f"{match.group(1)}$socketname = '{PDP_SERVER}';"

patched, count = pattern.subn(repl, text, count=1)
if count != 1:
    print("ERROR: active $socketname assignment not found", file=sys.stderr)
    sys.exit(65)

# Use a unique runtime copy for every release.  The previous fixed filename
# became mode 0400 and could not be overwritten on a second release while
# the container intentionally runs with cap_drop: ALL.
fd, runtime_path = tempfile.mkstemp(prefix="amavisd-release-runtime-", dir="/tmp")
TARGET = Path(runtime_path)

try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(patched)
        handle.flush()
        os.fsync(handle.fileno())

    TARGET.chmod(0o400)
    result = subprocess.run(["perl", "-T", str(TARGET), *sys.argv[1:]], check=False)
    sys.exit(result.returncode)
finally:
    TARGET.unlink(missing_ok=True)
