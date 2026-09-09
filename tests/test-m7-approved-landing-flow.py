from pathlib import Path

root = Path(__file__).resolve().parents[1]
main = (root / "app" / "main.py").read_text()
asset = root / "app" / "assets" / "mail-flow-approved-m7.png"

assert asset.is_file(), "approved Mail Flow image is missing"
assert asset.stat().st_size > 100_000, "approved Mail Flow image looks truncated"
assert '@app.get("/api/mail-flow/approved-image")' in main
assert 'id="approvedMailFlowFrame"' in main
assert 'id="approvedMailFlowImage"' in main
assert 'src="/api/mail-flow/approved-image"' in main
assert 'legacy-mail-flow-runtime' in main
assert 'document.getElementById("approvedMailFlowFrame")||document.getElementById("mailFlowSvg")' in main
assert 'class="help-visual-tile" type="button" data-tab="flowTab"' in main
assert '<button class="tabbtn active" data-tab="flowTab"' not in main
print("Milestone 7 approved Mail Flow asset / Help launch regression passed")
