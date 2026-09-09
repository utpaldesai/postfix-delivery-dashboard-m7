from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
s = (ROOT / 'full-rebuild.sh').read_text()
compose = (ROOT / 'docker-compose.yaml').read_text()
assert 'image: postfix-delivery-dashboard:m7' in compose
assert 'ROLLBACK_KEEP="${ROLLBACK_KEEP:-2}"' in s
assert 'ROLLBACK_PREFIX="rollback-r1118"' in s
assert 'prune_old_rollbacks(){' in s
assert 'sort -r' in s
assert 'docker image rm "$tag"' in s
assert 'current image + newest $ROLLBACK_KEEP rollback image(s) (N + 2)' in s
assert 'docker volume prune' not in s
assert 'docker system prune' not in s
assert 'docker image prune -a' not in s
wrapper = (ROOT / 'fullrebuild.sh').read_text()
assert 'full-rebuild.sh' in wrapper
print('R1.1.15 N+2 image retention regression checks passed')
