from pathlib import Path
import sys, types
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

pymysql=types.ModuleType("pymysql")
pymysql.connect=lambda **kwargs: None
cursors=types.ModuleType("pymysql.cursors")
cursors.DictCursor=object
pymysql.cursors=cursors
sys.modules["pymysql"]=pymysql
sys.modules["pymysql.cursors"]=cursors

from app.spam_lists import _parse_import_text

main=Path("app/main.py").read_text(encoding="utf-8")
module=Path("app/spam_lists.py").read_text(encoding="utf-8")

# Existing search retained and made explicit.
assert 'id="slSearch"' in main
assert 'onclick="loadSpamLists(1)">Search</button>' in main
assert 'function clearSpamListSearch()' in main
assert '(username LIKE %s OR preference LIKE %s OR value LIKE %s)' in module

# Bulk delete.
assert '@app.post("/api/spam-lists/bulk/delete")' in main
assert 'bulk_delete_entries as spam_bulk_delete_entries' in main
assert 'MAX_BULK_DELETE = 100' in module
assert 'id="slSelectVisible"' in main
assert 'id="slBulkDelete"' in main
assert 'function bulkDeleteSpamLists()' in main
assert 'SPAMLIST_BULK_DELETE' in main

# Import/export.
assert '@app.post("/api/spam-lists/bulk/import")' in main
assert '@app.get("/api/spam-lists/export", response_class=PlainTextResponse)' in main
assert 'preview_import as spam_preview_import' in main
assert 'import_entries as spam_import_entries' in main
assert 'export_entries as spam_export_entries' in main
assert 'Import .cf' in main
assert 'Export .cf' in main
assert 'preview before commit' in main
assert 'SPAMLIST_IMPORT' in main
assert 'SPAMLIST_EXPORT' in main
assert 'MAX_IMPORT_LINES = 0' in module

sample='''\n#### white list format email id is HAM whitout DKIM and SPF PASS\nwhitelist_from *@SquareGroup.COM\nwhitelist_from user@example.com\n\n### DKIM and SPF Pass\nwhitelist_auth *@20CUBE.COM\nwhitelist_auth process.jogi@gmail.com\n\n### blacklist format\nblacklist_from *@EXAMPLE.COM\nblacklist_from bad@domain.com\ninvalid_rule foo@example.com\n'''
parsed, invalid, skipped = _parse_import_text(sample)
assert [x["preference"] for x in parsed] == [
    "whitelist_from", "whitelist_from", "whitelist_auth", "whitelist_auth",
    "blacklist_from", "blacklist_from"
]
assert parsed[0]["value"] == "*@squaregroup.com"
assert parsed[2]["value"] == "*@20cube.com"
assert parsed[4]["value"] == "*@example.com"
assert len(invalid) == 1
assert invalid[0]["reason"] == "Unsupported directive"
assert skipped >= 4

# Export format headings are exactly the requested reusable SpamAssassin style.
assert '#### white list format email id is HAM whitout DKIM and SPF PASS' in module
assert '### DKIM and SPF Pass' in module
assert '### blacklist format' in module
assert 'output.append(f"whitelist_from {value}")' in module
assert 'output.append(f"whitelist_auth {value}")' in module
assert 'output.append(f"blacklist_from {value}")' in module

print("Milestone 5 Spam List bulk/search/import/export regression test passed")
