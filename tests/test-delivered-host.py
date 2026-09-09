from pathlib import Path
main=Path("app/main.py").read_text()
assert "<th>DELIVERED TO HOST</th>" in main
assert "const deliveredHost=list[0]?.delivery_target||\"-\";" in main
assert 'class="delivery-host"' in main
print("Delivered To Host test passed")
