#!/usr/bin/env bash
set -euo pipefail
APP_SERVICE="${APP_SERVICE:-app}"
DB_SERVICE="${DB_SERVICE:-mariadb}"
APP_CONTAINER="${APP_CONTAINER:-postfix-dashboard}"
DB_CONTAINER="${DB_CONTAINER:-postfix-dashboard-db}"
APP_IMAGE="postfix-delivery-dashboard:m7"
ROLLBACK_REPO="postfix-delivery-dashboard"
ROLLBACK_PREFIX="rollback-r1118"
ROLLBACK_KEEP="${ROLLBACK_KEEP:-2}"
ROLLBACK_IMAGE="${ROLLBACK_REPO}:${ROLLBACK_PREFIX}-$(date '+%Y%m%d-%H%M%S')"

log(){ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
die(){ log "ERROR: $*"; exit 1; }
env_value(){ python3 scripts/env_value.py --file .env "$@" 2>/dev/null || true; }

DB_NAME_VALUE="$(env_value DB_NAME MYSQL_DATABASE)"
DB_USER_VALUE="$(env_value DB_USER MYSQL_USER)"
DB_PASSWORD_VALUE="$(env_value DB_PASSWORD MYSQL_PASSWORD)"
DB_ROOT_PASSWORD_VALUE="$(env_value DB_ROOT_PASSWORD MYSQL_ROOT_PASSWORD)"
HOME_DOMAINS_VALUE="$(env_value HOME_DOMAINS)"
WEB_PORT_VALUE="$(env_value WEB_PORT)"
DB_HOST_PORT_VALUE="$(env_value DB_HOST_PORT)"

[ -n "$DB_NAME_VALUE" ] || die "DB_NAME/MYSQL_DATABASE missing from .env"
[ -n "$DB_USER_VALUE" ] || die "DB_USER/MYSQL_USER missing from .env"
[ -n "$DB_PASSWORD_VALUE" ] || die "DB_PASSWORD/MYSQL_PASSWORD missing from .env"
[ -n "$DB_ROOT_PASSWORD_VALUE" ] || die "DB_ROOT_PASSWORD/MYSQL_ROOT_PASSWORD missing from .env"
[ -n "$HOME_DOMAINS_VALUE" ] || die "HOME_DOMAINS missing from .env"
export DB_NAME="$DB_NAME_VALUE" DB_USER="$DB_USER_VALUE" DB_PASSWORD="$DB_PASSWORD_VALUE" DB_ROOT_PASSWORD="$DB_ROOT_PASSWORD_VALUE" HOME_DOMAINS="$HOME_DOMAINS_VALUE"
WEB_PORT="${WEB_PORT_VALUE:-8095}"; DB_HOST_PORT="${DB_HOST_PORT_VALUE:-3307}"; export WEB_PORT DB_HOST_PORT

log "Milestone 7 Enterprise preflight"
python3 preflight-upgrade.py
./verify-source.sh
test -f /usr/sbin/amavisd-release || die "/usr/sbin/amavisd-release missing"
grep -q '^#!.*perl' /usr/sbin/amavisd-release || die "unexpected amavisd-release format"
ss -lnt 2>/dev/null | grep -qE '127\.0\.0\.1:9998[[:space:]]' || die "Amavis AM.PDP not listening on 127.0.0.1:9998"
docker compose config >/dev/null
mkdir -p ./data/mariadb ./data/amavis-mgr ./data/reader

log "Preserving existing MariaDB container and data"
docker compose up -d --no-recreate "$DB_SERVICE"
for _ in $(seq 1 60); do
  S="$(docker inspect "$DB_CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || true)"
  [ "$S" = healthy ] && break
  sleep 2
done
S="$(docker inspect "$DB_CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || true)"
[ "$S" = healthy ] || { docker logs --tail=100 "$DB_CONTAINER" || true; die "MariaDB unhealthy; application remains unchanged"; }

docker exec "$DB_CONTAINER" mariadb -uroot -p"$DB_ROOT_PASSWORD_VALUE" -Nse \
  "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '$(printf '%s' "$DB_NAME_VALUE" | sed "s/'/''/g")'" \
  | grep -Fxq "$DB_NAME_VALUE" || die "Configured database '$DB_NAME_VALUE' not found; no application replacement performed"
log "Existing database validated read-only: $DB_NAME_VALUE"

CURRENT_IMAGE_ID="$(docker inspect "$APP_CONTAINER" --format '{{.Image}}' 2>/dev/null || true)"
if [ -n "$CURRENT_IMAGE_ID" ]; then
  docker image tag "$CURRENT_IMAGE_ID" "$ROLLBACK_IMAGE"
  log "Rollback image prepared: $ROLLBACK_IMAGE"
else
  log "No existing application container found; first deployment path"
fi

prune_old_rollbacks(){
  # Keep the current deployed image plus the two newest managed rollback tags (N + 2).
  # Only tags created by this script are eligible for deletion. Other project images,
  # manually named checkpoints and database volumes are never touched here.
  local keep="${ROLLBACK_KEEP:-2}"
  local tags=()
  local tag

  while IFS= read -r tag; do
    [ -n "$tag" ] && tags+=("$tag")
  done < <(
    docker image ls "$ROLLBACK_REPO"       --format '{{.Repository}}:{{.Tag}}' 2>/dev/null       | grep -E "^${ROLLBACK_REPO}:${ROLLBACK_PREFIX}-[0-9]{8}-[0-9]{6}$"       | sort -r || true
  )

  if [ "${#tags[@]}" -le "$keep" ]; then
    log "Rollback retention: ${#tags[@]} managed rollback image(s) present; nothing to delete"
    return 0
  fi

  log "Rollback retention: keeping newest $keep rollback image(s) plus current image (N + 2 policy)"
  for tag in "${tags[@]:$keep}"; do
    # Remove the old managed tag only. Docker will retain image layers still referenced
    # by any other tag or container.
    log "Removing expired rollback tag: $tag"
    docker image rm "$tag" >/dev/null 2>&1 || log "WARNING: unable to remove $tag; retained"
  done
}

log "Building new application image while current application remains running"
docker compose build --no-cache "$APP_SERVICE"
NEW_IMAGE_ID="$(docker image inspect "$APP_IMAGE" --format '{{.Id}}')"
[ -n "$NEW_IMAGE_ID" ] || die "new application image was not created"
log "New image built: $NEW_IMAGE_ID"

rollback_app(){
  rc=$?
  trap - ERR
  if [ -n "$CURRENT_IMAGE_ID" ]; then
    log "Deployment failed; restoring prior application image"
    docker image tag "$ROLLBACK_IMAGE" "$APP_IMAGE" || true
    docker compose up -d --no-deps --force-recreate "$APP_SERVICE" || true
  fi
  exit "$rc"
}
trap rollback_app ERR

log "Replacing application container only"
docker compose stop "$APP_SERVICE" 2>/dev/null || true
docker compose rm -f "$APP_SERVICE" 2>/dev/null || true
if ss -lnt 2>/dev/null | grep -qE "[:.]${WEB_PORT}[[:space:]]"; then
  die "WEB_PORT $WEB_PORT still in use after stopping application"
fi
docker compose up -d --no-deps --force-recreate "$APP_SERVICE"

for _ in $(seq 1 30); do
  H="$(docker inspect "$APP_CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || true)"
  [ "$H" = healthy ] && break
  sleep 2
done
H="$(docker inspect "$APP_CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || true)"
[ "$H" = healthy ] || { docker logs --tail=120 "$APP_CONTAINER" || true; false; }

docker exec "$APP_CONTAINER" test -r /opt/host-amavis/amavisd-release
docker exec "$APP_CONTAINER" test -x /usr/local/bin/amavisd-release-wrapper
docker exec "$APP_CONTAINER" python - <<'PY2'
import os,socket,urllib.request
wp=int(os.getenv('WEB_PORT','8095')); dp=int(os.getenv('DB_PORT','3307'))
for h,p,n in [('127.0.0.1',9998,'Amavis'),('127.0.0.1',dp,'MariaDB')]:
    s=socket.create_connection((h,p),timeout=5); print('OK',n,h,p); s.close()
for path in ('/health/live','/health/ready'):
    r=urllib.request.urlopen(f'http://127.0.0.1:{wp}{path}',timeout=5)
    print(path,r.status,r.read().decode())
PY2
trap - ERR
prune_old_rollbacks
log "Milestone 7 Enterprise deployment verified"
log "Database guarantee: ./data/mariadb was not deleted, reset, restored backward, or force-recreated"
log "Rollback image retained as: $ROLLBACK_IMAGE"
log "Rollback retention policy: current image + newest $ROLLBACK_KEEP rollback image(s) (N + 2)"
