from pathlib import Path

main=Path("app/main.py").read_text(encoding="utf-8")

for element in ("pgTop","qPgTop","auditPgTop"):
    assert f'id="{element}"' in main

assert 'const deliveryPageText=`Page ${p} of ${tp}`;' in main
assert 'document.getElementById("pgTop").textContent=deliveryPageText;' in main

assert 'const quarantinePageText=`Page ${qp} of ${qtp}`;' in main
assert 'document.getElementById("qPgTop").textContent=quarantinePageText;' in main

assert 'const auditPageText=`Page ${ap} of ${atp}`;' in main
assert 'document.getElementById("auditPgTop").textContent=auditPageText;' in main

assert "Milestone 5 R12 - upper-right page indicators" in main
assert "justify-content:flex-end" in main

# Existing bottom pagers retained.
for element in ("pg","qPg","auditPg"):
    assert f'id="{element}"' in main

# Existing key features retained.
assert 'data-tab="mailSizeTab"' in main
assert 'id="searchOperator"' in main
assert "grid-template-columns:180px minmax(360px,1fr) 160px 140px 180px" in main

print("Milestone 5 upper-right page indicator regression test passed")
