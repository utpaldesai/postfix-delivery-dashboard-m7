#!/usr/bin/env python3
"""Read selected values from a Docker Compose .env file without executing it."""
from __future__ import annotations
import argparse
from pathlib import Path
import re
import sys

KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not KEY_RE.match(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            quote = value[0]
            value = value[1:-1]
            if quote == '"':
                value = (value.replace(r"\n", "\n")
                              .replace(r"\r", "\r")
                              .replace(r"\t", "\t")
                              .replace(r'\"', '"')
                              .replace(r"\\", "\\"))
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
    return values


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("keys", nargs="+", help="keys in priority order")
    p.add_argument("--file", default=".env")
    p.add_argument("--required", action="store_true")
    args = p.parse_args()
    values = parse_env(Path(args.file))
    for key in args.keys:
        if key in values and values[key] != "":
            sys.stdout.write(values[key])
            return 0
    return 2 if args.required else 0

if __name__ == "__main__":
    raise SystemExit(main())
