from pathlib import Path
import re
main=Path("app/main.py").read_text(encoding="utf-8")
expected={"deliveryTab":"Delivery","summaryTab":"Summary","quarantineTab":"Amavis Quarantine","spamListsTab":"Whitelist / Blacklist","mailSizeTab":"Mail Size","systemTab":"System Status","auditTab":"Audit","aclTab":"User ACL","helpTab":"Help"}
for tab,label in expected.items():
    assert re.search(rf'data-tab="{re.escape(tab)}"[^>]*data-tooltip="{re.escape(label)}"',main)
assert "content:attr(data-tooltip)" in main
assert "z-index:20000" in main
assert ".sidebar-collapsed .side-nav .tabbtn:hover::after" in main
assert ".sidebar-collapsed .side-nav .tabbtn:focus-visible::after" in main
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main
print("Milestone 5 collapsed sidebar tooltip regression test passed")
