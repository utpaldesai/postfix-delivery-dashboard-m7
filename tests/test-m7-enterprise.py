from pathlib import Path
compose=Path('docker-compose.yaml').read_text()
rebuild=Path('full-rebuild.sh').read_text()
main=Path('app/main.py').read_text()
assert 'image: postfix-delivery-dashboard:m7' in compose
assert 'ROLLBACK_PREFIX="rollback-r1118"' in rebuild
assert 'ROLLBACK_KEEP="${ROLLBACK_KEEP:-2}"' in rebuild
assert 'prune_old_rollbacks(){' in rebuild
assert rebuild.index('docker compose build --no-cache "$APP_SERVICE"') < rebuild.index('docker compose stop "$APP_SERVICE"')
assert 'docker compose up -d --no-recreate "$DB_SERVICE"' in rebuild
assert 'rm -rf ./data/mariadb' not in rebuild
assert 'docker compose down -v' not in rebuild
assert 'id="mailFlowRefreshBtn"' in main
assert 'id="mailFlowFullscreenBtn"' in main
assert main.count('function toggleMailFlowFullscreen(){') == 1
assert 'visualFlowCanvas' not in main
print('Milestone 7 Enterprise regression passed')
