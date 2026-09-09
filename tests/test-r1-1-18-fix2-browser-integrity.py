from pathlib import Path
import subprocess, sys
root=Path(__file__).resolve().parents[1]
cp=subprocess.run([sys.executable,str(root/'scripts/verify_inline_js.py')],cwd=root)
assert cp.returncode==0
main=(root/'app/main.py').read_text()
print('R1.1.18 Fix2 browser integrity regression passed.')
assert 'backupRestoreTab' not in main
assert 'securityBlocksTab' not in main
