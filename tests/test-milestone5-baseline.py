from pathlib import Path
main=Path("app/main.py").read_text(encoding="utf-8")
compose=Path("docker-compose.yaml").read_text(encoding="utf-8")
wrapper=Path("amavisd-release-wrapper.py").read_text(encoding="utf-8")

assert "Postfix Delivery Dashboard" in main
assert "Milestone 6 baseline: exact five-column quarantine alignment" in main
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main
assert 'class="qrow-select"' in main
assert 'class="qmail-main"' in main
assert 'class="qauthbox"' in main
assert 'class="qscorebox"' in main
assert 'class="qactionbox"' in main
assert 'quarantineReleaseLearnHam(' in main
assert 'quarantineAction("spam"' in main
assert not Path("docker-compose.yml").exists()
assert Path("docker-compose.yaml").exists()
assert '["perl", "-T", str(TARGET)' in wrapper

print("Milestone 5 baseline regression test passed")
