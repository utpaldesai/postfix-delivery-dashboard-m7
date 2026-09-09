from pathlib import Path
main=Path("app/main.py").read_text()
assert 'if(mode==="release" && !confirm(`Release ${pdpId}?`))return;' not in main
assert 'async function quarantineAction(mode,pdpId)' in main
assert 'new URLSearchParams({mode:mode,pdp_id:pdpId})' in main
print("Milestone 2 release no-prompt regression test passed")
