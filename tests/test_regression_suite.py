from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def test_packaged_regression_suite():
    completed = subprocess.run(
        [str(ROOT / 'verify-source.sh')],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout
    assert 'Milestone 7 Enterprise source verification passed.' in completed.stdout
