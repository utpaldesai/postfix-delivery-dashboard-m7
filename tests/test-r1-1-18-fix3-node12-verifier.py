#!/usr/bin/env python3
from pathlib import Path
p = Path('scripts/verify_inline_js.py')
s = p.read_text(encoding='utf-8')
assert 'node_major < 14' in s
assert 'too old for dashboard browser-JS syntax' in s
assert 'node --check skipped' in s
assert 'static DOM/handler/string integrity checks remain active' in s
print('R1.1.18 Fix3 Node 12 verifier compatibility regression passed.')
