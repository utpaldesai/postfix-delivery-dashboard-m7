from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")

assert 'class="delivery-compact"' in main
assert "<th>SIZE (MB)</th>" not in main
assert "<th>DELIVERY TARGET / STATUS DETAIL</th>" not in main
assert "<th>DETAIL</th>" in main
assert "delivery-meta" in main
assert "Size: ${mb} MB" in main
assert 'colspan="7"' in main

print("Compact delivery tab test passed")
