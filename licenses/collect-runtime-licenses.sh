#!/usr/bin/env bash
set -euo pipefail
IMAGE="${1:?Usage: $0 <image-name>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT/runtime-report"
rm -rf "$OUT"
mkdir -p "$OUT/debian-copyright"

cid="$(docker create "$IMAGE")"
tmp="$(mktemp -d)"
cleanup(){ rm -rf "$tmp"; docker rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker cp "$cid:/var/lib/dpkg/status" "$OUT/dpkg-status" >/dev/null 2>&1 || true
docker cp "$cid:/usr/share/doc" "$tmp/doc" >/dev/null 2>&1 || true
find "$tmp/doc" -type f -name copyright -print0 2>/dev/null |
while IFS= read -r -d "" f; do
  pkg="$(basename "$(dirname "$f")")"
  cp "$f" "$OUT/debian-copyright/${pkg}.copyright" 2>/dev/null || true
done

docker run --rm --entrypoint python "$IMAGE" -c '
import importlib.metadata as md
for d in sorted(md.distributions(), key=lambda x:(x.metadata.get("Name") or "").lower()):
    n=d.metadata.get("Name") or "UNKNOWN"
    lic=d.metadata.get("License-Expression") or d.metadata.get("License") or ""
    print(f"{n}\t{d.version}\t{lic}")
' > "$OUT/python-packages.tsv"

echo "Runtime license report written to $OUT"
