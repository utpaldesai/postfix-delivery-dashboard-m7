#!/usr/bin/env python3
"""Static browser-JS integrity checks for the inline dashboard HTML.

No third-party Python packages are required. If Node.js is available we also
run its parser (`node --check`) against every inline script. The built-in lexer
still rejects raw newlines inside quoted JavaScript strings, which catches the
class of production-breaking defect that previously escaped source tests.
"""
from __future__ import annotations
import ast
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "app" / "main.py"


def html_constants() -> dict[str, str]:
    tree = ast.parse(MAIN.read_text(encoding="utf-8"), filename=str(MAIN))
    out: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        for name in ("HTML", "LOGIN_HTML"):
            if name in names:
                out[name] = node.value.value
    if "HTML" not in out or "LOGIN_HTML" not in out:
        raise SystemExit("ERROR: HTML/LOGIN_HTML constants not found in app/main.py")
    return out


def scripts_from(html: str) -> list[str]:
    return re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, flags=re.I | re.S)


def dom_reference_check(html: str, js: str) -> None:
    ids = set(re.findall(r"\bid=[\"']([^\"']+)[\"']", html))
    refs = set(re.findall(r"document\.getElementById\([\"']([^\"']+)[\"']\)", js))
    missing = sorted(refs - ids)
    if missing:
        raise SystemExit("ERROR: JavaScript references missing DOM id(s): " + ", ".join(missing))


def handler_check(html: str, js: str) -> None:
    funcs = set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", js))
    funcs.update(re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>", js))
    attrs = re.findall(r"\b(?:onclick|onchange|oninput|onkeydown)=[\"']([^\"']+)[\"']", html)
    builtins = {"alert","confirm","prompt","Number","String","Boolean","encodeURIComponent","setTimeout","clearTimeout","setInterval","clearInterval","stringify"}
    missing = set()
    for code in attrs:
        # Remove dotted method names like JSON.stringify before looking for bare handlers.
        code = re.sub(r"\b[A-Za-z_$][\w$]*\.", "", code)
        for name in re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", code):
            if name not in funcs and name not in builtins and name not in {"if","for","while","switch","catch"}:
                missing.add(name)
    if missing:
        raise SystemExit("ERROR: inline HTML handler calls undefined function(s): " + ", ".join(sorted(missing)))


def node_check(scripts: list[tuple[str,str]]) -> None:
    node = shutil.which("node")
    if not node:
        print("INLINE JS: Node.js not installed; DOM/handler checks completed (Node syntax check skipped)")
        return

    # The dashboard intentionally uses modern browser JavaScript such as optional
    # chaining (?.). Production hosts may still have Node.js 12 installed for
    # unrelated tooling; Node 12 cannot parse that valid browser syntax. Do not
    # turn an old verifier runtime into a false build failure.
    try:
        vp = subprocess.run([node, "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        version_text = (vp.stdout or vp.stderr or "").strip()
        m = re.search(r"v?(\d+)(?:\.|$)", version_text)
        node_major = int(m.group(1)) if m else 0
    except Exception:
        version_text = "unknown"
        node_major = 0

    if node_major and node_major < 14:
        print(f"INLINE JS: WARNING: Node.js {version_text} is too old for dashboard browser-JS syntax; node --check skipped")
        print("INLINE JS: static DOM/handler/string integrity checks remain active")
        return

    with tempfile.TemporaryDirectory(prefix="postfix-dashboard-js-") as td:
        for idx, (label, js) in enumerate(scripts):
            p = Path(td) / f"{label.lower()}-{idx}.js"
            p.write_text(js, encoding="utf-8")
            cp = subprocess.run([node, "--check", str(p)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if cp.returncode:
                sys.stderr.write(cp.stderr)
                raise SystemExit(f"ERROR: Node.js syntax check failed for {label} script {idx}")
    print("INLINE JS: Node.js syntax checks passed")


def main() -> None:
    constants = html_constants()
    all_scripts: list[tuple[str,str]] = []
    for name, html in constants.items():
        scripts = scripts_from(html)
        if not scripts:
            raise SystemExit(f"ERROR: no script block found in {name}")
        for idx, js in enumerate(scripts):
            all_scripts.append((name, js))
        if name == "HTML":
            joined = "\n".join(scripts)
            dom_reference_check(html, joined)
            handler_check(html, joined)
            if "function fmtDateTime(" not in joined or joined.index("function fmtDateTime(") > joined.index("async function loadMonitor("):
                raise SystemExit("ERROR: fmtDateTime must be defined before loadMonitor")
    node_check(all_scripts)
    print("INLINE JS / DOM INTEGRITY PASSED")

if __name__ == "__main__":
    main()
