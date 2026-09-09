#!/bin/sh
set -eu
# Always verify relative to the project root, regardless of the caller's cwd.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"
export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile app/*.py scripts/*.py preflight-upgrade.py
python3 scripts/verify_inline_js.py
python3 audit-build.py
python3 stale-reference-audit.py
find tests -maxdepth 1 -type f -name 'test*.py' ! -name 'test_regression_suite.py' -print0 | xargs -0 -n1 -P4 sh -c 'timeout 60s env PYTHONPATH=. python3 "$0" >/dev/null'
grep -q '\["perl", "-T", str(TARGET)' amavisd-release-wrapper.py
grep -q 'network_mode: host' docker-compose.yaml
grep -q 'image: postfix-delivery-dashboard:m7' docker-compose.yaml
grep -q 'docker compose up -d --no-recreate "$DB_SERVICE"' full-rebuild.sh
grep -q 'docker compose build --no-cache "$APP_SERVICE"' full-rebuild.sh
grep -q 'ROLLBACK_KEEP="${ROLLBACK_KEEP:-2}"' full-rebuild.sh
grep -q 'ROLLBACK_PREFIX="rollback-r1118"' full-rebuild.sh
PYTHONPATH=. python3 tests/test-r1-1-16-compose-group-add-unique.py >/dev/null
grep -q 'prune_old_rollbacks' full-rebuild.sh
! grep -Eq 'docker compose down .*-[vV]|rm -rf .*data/mariadb|docker compose up .*--force-recreate.*\$DB_SERVICE' full-rebuild.sh
! grep -Eq '(^|[;[:space:]])\.([[:space:]]+|/)\.?/?\.env|source[[:space:]]+.*\.env' full-rebuild.sh verify-running.sh
printf '%s\n' 'Milestone 7 Enterprise source verification passed.'
