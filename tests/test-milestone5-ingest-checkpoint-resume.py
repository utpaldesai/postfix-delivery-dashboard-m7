from pathlib import Path
import ast
import json
import os
import tempfile
import time

source_path=Path('app/main.py')
source=source_path.read_text(encoding='utf-8')
compose=Path('docker-compose.yaml').read_text(encoding='utf-8')
rebuild=Path('full-rebuild.sh').read_text(encoding='utf-8')

for token in (
    'INGEST_CHECKPOINT_FILE',
    'def _load_ingest_checkpoint(',
    'def _write_ingest_checkpoint(',
    'def _position_from_checkpoint(',
    'os.fstat(handle.fileno())',
    'checkpoint["offset"] <= int(stat_result.st_size)',
):
    assert token in source, token

assert './data/reader:/data/reader' in compose
assert 'INGEST_CHECKPOINT_FILE: /data/reader/mail-log-checkpoint.json' in compose
assert 'mkdir -p ./data/mariadb ./data/amavis-mgr ./data/reader' in rebuild

# Execute the actual checkpoint helper function AST without importing app.main
# (which would require the production MariaDB driver in the host test runtime).
tree=ast.parse(source)
needed={
    '_load_ingest_checkpoint',
    '_write_ingest_checkpoint',
    '_bootstrap_without_checkpoint',
    '_position_from_checkpoint',
}
body=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in needed]
assert {node.name for node in body} == needed
module=ast.Module(body=body,type_ignores=[])
code=compile(module,'app/main.py','exec')

class DummyLogger:
    def warning(self,*args,**kwargs):
        pass

with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    log=td/'mail.log'
    checkpoint_file=td/'mail-log-checkpoint.json'
    log.write_text('one\ntwo\nthree\n',encoding='utf-8')
    captured=[]
    ns={
        'Path':Path,
        'json':json,
        'os':os,
        'time':time,
        'logger':DummyLogger(),
        'INGEST_CHECKPOINT_FILE':checkpoint_file,
        'LOG':log,
        'IMPORT':2,
        'store':lambda line: captured.append(line),
        'reader_state':{
            'checkpoint_mode':'uninitialized',
            'checkpoint_offset':0,
            'checkpoint_inode':0,
            'checkpoint_device':0,
            'checkpoint_updated_at':'',
        },
    }
    exec(code,ns)

    with log.open('r',encoding='utf-8') as handle:
        stat=log.stat()
        offset=ns['_position_from_checkpoint'](handle,stat,None)
        assert captured == ['two\n','three\n']
        assert offset == log.stat().st_size

    cp=ns['_load_ingest_checkpoint']()
    assert cp is not None
    assert cp['offset'] == log.stat().st_size

    # Lines appended while the dashboard is stopped must be read from the
    # previous durable byte offset after restart.
    with log.open('a',encoding='utf-8') as handle:
        handle.write('four\n')

    with log.open('r',encoding='utf-8') as handle:
        stat=log.stat()
        resumed=ns['_position_from_checkpoint'](handle,stat,cp)
        assert resumed == cp['offset']
        assert handle.readline() == 'four\n'

    # Replaced/rotated active file must be consumed from byte zero.
    replacement=td/'replacement.log'
    replacement.write_text('new-one\n',encoding='utf-8')
    log.unlink()
    replacement.rename(log)

    with log.open('r',encoding='utf-8') as handle:
        stat=log.stat()
        ns['_position_from_checkpoint'](handle,stat,cp)
        assert handle.tell() == 0
        assert handle.readline() == 'new-one\n'

print('Milestone 5 durable ingestion checkpoint/resume test passed')
