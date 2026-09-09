from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
ai=(root/'app/ai_trainer.py').read_text()
compose=(root/'docker-compose.yaml').read_text()
env=(root/'.env.example').read_text()
db=(root/'app/db.py').read_text()
assert 'data-tab="backupRestoreTab"' not in main
assert 'data-tab="securityBlocksTab"' not in main
assert '/api/backup-restore' not in main
assert '/api/security/fail2ban' not in main
assert '"backup_restore"' not in db
assert '"security_blocks"' not in db
assert 'FAIL2BAN_API_URL' not in compose and 'BACKUP_RESTORE_API_URL' not in compose
assert 'FAIL2BAN_API_URL=' not in env and 'BACKUP_RESTORE_API_URL=' not in env
assert 'CURRENT_FEATURE_SCHEMA = 4' in ai
assert 'stylometry_structural' in ai
assert 'url:visible_href_mismatch' in ai
assert 'financial_request' in ai and 'secrecy_pressure' in ai and 'uce_language' in ai
for banned in ('SpamAssassin score','Amavis verdict'):
    assert banned not in ai.split('def _extract_features_and_meta',1)[1].split('def extract_features',1)[0] or 'deliberately excluded' in ai
print('R1.1.19 independent AI experimental regression passed')
