#!/usr/bin/env python3
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
compose = (ROOT / "docker-compose.yaml").read_text()
dockerfile = (ROOT / "Dockerfile").read_text()
main = (ROOT / "app/main.py").read_text()
env = (ROOT / ".env.example").read_text()

assert "image: postfix-delivery-dashboard:m7" in compose
assert "docker-compose.yml" not in {p.name for p in ROOT.iterdir()}
assert "spamassassin" in dockerfile
assert "libdbd-mysql-perl" in dockerfile
assert "libbsd-resource-perl" in dockerfile
assert "libarchive-zip-perl" in dockerfile
assert "libio-string-perl" in dockerfile
assert "SPAMASSASSIN_CONFIG_DIR" in compose
assert ":/etc/spamassassin:ro" in compose
assert "SA_LEARN_ON_MARK_SPAM" in compose
assert "Postfix Delivery Dashboard" in main
assert 'async function quarantineLearn(mode,pdpId)' in main
assert '/api/quarantine/learn' in main
assert "SPAMASSASSIN_CONFIG_DIR=/etc/spamassassin" in env
assert not (ROOT / "MILESTONE6.md").exists()
assert (ROOT / "README.md").is_file()
assert (ROOT / "SECURITY-PACK1.md").is_file()
assert (ROOT / "licenses" / "README.md").is_file()
assert not (ROOT / "UPGRADE-MILESTONE6.txt").exists()
print("Milestone 6 packaging regression passed")
