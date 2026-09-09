from pathlib import Path

src = Path('app/main.py').read_text()
required = [
    'M7 Quarantine Intelligence: opaque evidence card separated from table background',
    'background:#ffffff !important',
    'color:#111827 !important',
    'border:1px solid #94a3b8 !important',
    'box-shadow:0 18px 48px rgba(15,23,42,.28),0 5px 14px rgba(15,23,42,.16) !important',
    'opacity:1 !important',
    'backdrop-filter:none !important',
    'isolation:isolate',
    '#quarantineTab .qscore-tip-rule{color:#0f172a}',
    '#quarantineTab .qscore-tip-value{color:#92400e;font-weight:800}',
]
for marker in required:
    assert marker in src, marker
assert 'z-index:10000 !important' in src
assert 'pointer-events:auto' in src
assert '#quarantineTab .qscore-hover:focus .qscore-tooltip' in src
print('M7 Quarantine Intelligence tooltip contrast regression passed')
