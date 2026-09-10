from pathlib import Path
root=Path(__file__).resolve().parents[1]
rebuild=(root/'full-rebuild.sh').read_text()
compose=(root/'docker-compose.yaml').read_text()
main=(root/'app/main.py').read_text()
db=(root/'app/db.py').read_text()
assert '. ./.env;' not in rebuild
assert 'docker compose down -v' not in rebuild
assert 'rm -rf ./data/mariadb' not in rebuild
assert 'up -d --force-recreate "$DB_SERVICE"' not in rebuild
assert 'python3 preflight-upgrade.py' in rebuild
assert 'image: postfix-delivery-dashboard:m7' in compose
assert 'HOME_DOMAINS: ${HOME_DOMAINS:?' in compose
assert 'os.getenv("HOME_DOMAINS", "nirma.co.in")' not in main
assert 'domains = ["nirma.co.in"]' not in db
print('R6.5 Fix 1 database-preservation regression passed')
