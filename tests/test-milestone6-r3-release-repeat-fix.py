from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
wrapper = (ROOT / "amavisd-release-wrapper.py").read_text(encoding="utf-8")
compose = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")

assert 'tempfile.mkstemp(prefix="amavisd-release-runtime-", dir="/tmp")' in wrapper
assert 'TARGET.unlink(missing_ok=True)' in wrapper
assert 'subprocess.run(["perl", "-T", str(TARGET)' in wrapper
assert 'TARGET = Path("/tmp/amavisd-release-runtime")' not in wrapper
assert 'group_add:' in compose and '${AMAVIS_GID:-130}' in compose
assert '/tmp:rw,noexec,nosuid,size=256m,mode=1777' in compose
assert 'cap_drop:' in compose and '- ALL' in compose

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    source = td / "amavisd-release"
    source.write_text("#!/usr/bin/perl\n$socketname = '/var/run/amavis/amavisd.sock';\n", encoding="utf-8")
    bindir = td / "bin"
    bindir.mkdir()
    fake_perl = bindir / "perl"
    fake_perl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_perl.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["AMAVIS_RELEASE_SOURCE"] = str(source)
    env["AMAVIS_PDP_SERVER"] = "127.0.0.1:9998"
    before = set(Path('/tmp').glob('amavisd-release-runtime-*'))
    for _ in range(2):
        proc = subprocess.run([str(ROOT / 'amavisd-release-wrapper.py'), 'dummy-id'], env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
    after = set(Path('/tmp').glob('amavisd-release-runtime-*'))
    assert after == before, (before, after)

print('Milestone 6 R3 repeat-release wrapper regression passed')
