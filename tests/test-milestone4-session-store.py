from pathlib import Path as _Path
import sys as _sys
_ROOT=str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path: _sys.path.insert(0,_ROOT)
from app.session_auth import SessionStore
s=SessionStore()
t=s.create('admin')
assert s.get(t).username=='admin'
assert s.touch(t).username=='admin'
assert s.active_count()==1
assert s.destroy(t).username=='admin'
assert s.get(t) is None
print('Milestone 4 session store test passed')
