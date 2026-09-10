from pathlib import Path
import io, tempfile, zipfile
from email.message import EmailMessage

root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text(encoding='utf-8')
ai=(root/'app/ai_trainer.py').read_text(encoding='utf-8')

assert 'ai_ground_truth_current(source_sha256, pdp_id=pdp_id)' in main
assert 'result["admin_ground_truth"]' in main
assert 'Saved Admin Ground Truth' in main
assert 'initAiGroundTruthProposal(proposedLabel,proposedClass,data.admin_ground_truth||{})' in main
assert 'attachment_intelligence(source_path)' in ai
assert '_scan_zip_bytes' in ai
assert 'attach:embedded_executable_or_script' in ai
assert 'AI_ATTACHMENT_SCAN_MAX_DEPTH' in ai

from app.ai_trainer import attachment_intelligence

inner=io.BytesIO()
with zipfile.ZipFile(inner,'w',zipfile.ZIP_DEFLATED) as z:
    z.writestr('18777343_ITR.bat','@echo off\necho test\n')
outer=io.BytesIO()
with zipfile.ZipFile(outer,'w',zipfile.ZIP_DEFLATED) as z:
    z.writestr('18777343_ITR.zip',inner.getvalue())
msg=EmailMessage()
msg['From']='sender@example.test'; msg['To']='recipient@example.test'; msg['Subject']='test'
msg.set_content('test')
msg.add_attachment(outer.getvalue(),maintype='application',subtype='zip',filename='18777343_ITR.zip')
with tempfile.NamedTemporaryFile(suffix='.eml',delete=False) as f:
    f.write(msg.as_bytes()); path=Path(f.name)
try:
    evidence=attachment_intelligence(path)
    assert evidence['available'] is True
    assert evidence['nested_archive'] is True
    assert evidence['archive_depth'] >= 2
    assert evidence['dangerous_member_count'] >= 1
    assert any(x.get('name')=='18777343_ITR.bat' for x in evidence['dangerous_members'])
    assert evidence['risk']=='CRITICAL'
finally:
    path.unlink(missing_ok=True)
print('R1.1.48 ground-truth persistence + recursive attachment intelligence regression passed')
