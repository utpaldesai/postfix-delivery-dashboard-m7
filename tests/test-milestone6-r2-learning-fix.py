from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
main=(ROOT/"app/main.py").read_text(encoding="utf-8")
quarantine=(ROOT/"app/quarantine.py").read_text(encoding="utf-8")
compose=(ROOT/"docker-compose.yaml").read_text(encoding="utf-8")
dockerfile=(ROOT/"Dockerfile").read_text(encoding="utf-8")

for package in ("libbsd-resource-perl","libarchive-zip-perl","libio-string-perl"):
    assert package in dockerfile
assert 'SA_LEARN_MAX_SIZE = os.getenv("SA_LEARN_MAX_SIZE", "0")' in quarantine
assert '"--max-size", SA_LEARN_MAX_SIZE' in quarantine
assert 'SA_LEARN_MAX_SIZE: ${SA_LEARN_MAX_SIZE:-0}' in compose
assert 'data-tab="flowTab"' in main
assert '<div id="flowTab" class="tabpane">' in main
assert 'loadDynamicMailFlow()' in main
assert 'AMAVIS QUARANTINE' in main
assert 'INBOUND MAIL FLOW' in main and 'OUTBOUND MAIL FLOW' in main
print("Milestone 6 R2 learning-fix compatibility regression: PASS")
