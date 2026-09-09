#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$ROOT_DIR/.." && pwd)"
API_SRC="$ROOT_DIR/mail-size-api.php"
API_DST="${MAIL_SIZE_API_DST:-/var/www/html/mail-size-api.php}"
KEY_DIR="/etc/postfix-web"
KEY_FILE="$KEY_DIR/mail-size-api.key"
ENV_FILE="${ENV_FILE:-$PROJECT_DIR/.env}"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "ERROR: run this installer as root." >&2
  exit 1
fi

test -f "$API_SRC" || { echo "ERROR: $API_SRC missing" >&2; exit 1; }
test -x /usr/local/bin/deploy_postfix.sh || {
  echo "ERROR: /usr/local/bin/deploy_postfix.sh missing or not executable" >&2
  exit 1
}

install -d -o root -g www-data -m 0750 "$KEY_DIR"
install -d -m 0750 /var/lib/postfix-web/backups

if [ ! -s "$KEY_FILE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "$KEY_FILE"
  else
    python3 - <<'PY' > "$KEY_FILE"
import secrets
print(secrets.token_hex(32))
PY
  fi
fi
chmod 0640 "$KEY_FILE"
chown root:www-data "$KEY_FILE" 2>/dev/null || true

install -m 0644 "$API_SRC" "$API_DST"

KEY="$(tr -d '\r\n' < "$KEY_FILE")"
touch "$ENV_FILE"

python3 - "$ENV_FILE" "$KEY" <<'PY'
from pathlib import Path
import sys

path=Path(sys.argv[1])
key=sys.argv[2]
text=path.read_text(encoding="utf-8") if path.exists() else ""

updates={
    "MAIL_SIZE_API_URL":"http://127.0.0.1/mail-size-api.php",
    "MAIL_SIZE_API_KEY":key,
}

lines=text.splitlines()
seen=set()
out=[]
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        name=line.split("=",1)[0].strip()
        if name in updates:
            out.append(f"{name}={updates[name]}")
            seen.add(name)
            continue
    out.append(line)

for name,value in updates.items():
    if name not in seen:
        out.append(f"{name}={value}")

path.write_text("\n".join(out).rstrip()+"\n",encoding="utf-8")
PY

echo "Installed native Mail Size host helper:"
echo "  API: $API_DST"
echo "  Key: $KEY_FILE"
echo "  Dashboard env updated: $ENV_FILE"
echo
echo "IMPORTANT: www-data must already have passwordless sudo access ONLY to:"
echo "  /usr/local/bin/deploy_postfix.sh"
echo
echo "Then run:"
echo "  cd $PROJECT_DIR"
echo "  ./full-rebuild.sh"
