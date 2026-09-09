#!/bin/bash
set -euo pipefail
ROOT="${1:-/opt/postfix-dashboard}"
MANIFEST="$ROOT/obsolete-files.manifest"
[ -f "$MANIFEST" ] || { echo "No obsolete-files.manifest found"; exit 0; }
while IFS= read -r rel; do
  rel="${rel%%#*}"; rel="${rel%${rel##*[![:space:]]}}"; rel="${rel#${rel%%[![:space:]]*}}"
  [ -n "$rel" ] || continue
  case "$rel" in data/*|.env|.env/*) echo "REFUSING protected path: $rel" >&2; exit 2;; esac
  target="$ROOT/$rel"
  if [ -e "$target" ]; then echo "Removing obsolete: $target"; rm -rf -- "$target"; fi
done < "$MANIFEST"
find "$ROOT/app" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
find "$ROOT/app" -type f -name '*.pyc' -delete 2>/dev/null || true
