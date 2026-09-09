#!/usr/bin/env bash
set -euo pipefail
APP_CONTAINER="${APP_CONTAINER:-postfix-dashboard}"
env_value() { python3 scripts/env_value.py --file .env "$@" 2>/dev/null || true; }
WEB_PORT="$(env_value WEB_PORT)"; WEB_PORT="${WEB_PORT:-8095}"
docker compose config >/dev/null
docker inspect "$APP_CONTAINER" --format 'Image={{.Config.Image}} NetworkMode={{.HostConfig.NetworkMode}}'
docker exec "$APP_CONTAINER" perl -v | head -2
docker exec "$APP_CONTAINER" perl -MBSD::Resource -e 'print "BSD::Resource OK\n"'
docker exec "$APP_CONTAINER" perl -MArchive::Zip -e 'print "Archive::Zip OK\n"'
docker exec "$APP_CONTAINER" perl -MIO::String -e 'print "IO::String OK\n"'
docker exec "$APP_CONTAINER" ls -l /opt/host-amavis/amavisd-release
docker exec "$APP_CONTAINER" ls -l /usr/local/bin/amavisd-release-wrapper
docker exec "$APP_CONTAINER" env | grep -E '^(WEB_PORT|DB_HOST|DB_PORT|AMAVIS_PDP_SERVER|AMAVIS_RELEASE_CMD|AMAVIS_RELEASE_SOURCE|SESSION_IDLE_TIMEOUT_MINUTES|SESSION_COOKIE_NAME|SESSION_COOKIE_SECURE|SA_LEARN_MAX_SIZE|HOME_DOMAINS)='
echo "Bayes:"; docker exec "$APP_CONTAINER" sa-learn --dump magic -u amavis | grep -E "bayes db version|nspam|nham|ntokens" || true
echo "Live:"; curl -fsS "http://127.0.0.1:${WEB_PORT}/health/live"; echo
echo "Ready:"; curl -fsS "http://127.0.0.1:${WEB_PORT}/health/ready"; echo
