#!/usr/bin/env python3
from pathlib import Path
import ast,re,sys,yaml
errs=[]
for p in Path("app").glob("*.py"):
    try: ast.parse(p.read_text(),filename=str(p))
    except SyntaxError as e: errs.append(str(e))
for n in ("docker-compose.yaml",):
    c=yaml.safe_load(Path(n).read_text()); a=c["services"]["app"]; db=c["services"]["mariadb"]
    if a.get("network_mode")!="host": errs.append(n+": network_mode")
    if "networks" in a: errs.append(n+": app networks")
    if "ports" in a: errs.append(n+": app ports")
    if a["environment"].get("WEB_PORT")!="${WEB_PORT:-8095}": errs.append(n+": WEB_PORT")
    if a["environment"].get("SESSION_IDLE_TIMEOUT_MINUTES")!="${SESSION_IDLE_TIMEOUT_MINUTES:-15}": errs.append(n+": session timeout")
    if not db.get("ports"): errs.append(n+": DB publication")
d=Path("Dockerfile").read_text(); q=Path("app/quarantine.py").read_text(); m=Path("app/main.py").read_text(); w=Path("amavisd-release-wrapper.py").read_text(); dbs=Path("app/db.py").read_text()
if "8080" in d: errs.append("stale 8080")
for package in ("perl", "ca-certificates", "spamassassin", "libdbd-mysql-perl", "libbsd-resource-perl", "libarchive-zip-perl", "libio-string-perl"):
    if package not in d: errs.append("Dockerfile package missing: "+package)
if '["perl", "-T", str(TARGET)' not in w: errs.append("Perl -T missing")
if re.search(r"(?<!_)mark_id\(RELEASED_DB", q): errs.append("undefined mark_id")
if "_write_structured_audit(" in q: errs.append("undefined audit")
if "HTTPBasic" in m: errs.append("legacy HTTP Basic remains")
for token in ['@app.post("/api/login")','@app.post("/api/logout")','@app.get("/health/ready")','@app.get("/api/flow/{queue_id}")']:
    if token not in m: errs.append("missing "+token)
if "CREATE TABLE IF NOT EXISTS dashboard_audit" not in dbs: errs.append("audit DB missing")
if "signature = (stat.st_mtime_ns, stat.st_size)" not in q: errs.append("incremental quarantine signature missing")
if list(Path('.').glob('test*.py')): errs.append("test files present in project root")
if Path("docker-compose.yml").exists(): errs.append("duplicate docker-compose.yml present")
if errs:
    print("AUDIT FAILED"); [print(" -",x) for x in errs]; sys.exit(1)
print("AUDIT PASSED - Milestone 6")
