from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def test_three_tier_module_and_schema_are_local_shadow_only():
    ti=(ROOT/'app/ai_threat_intelligence.py').read_text()
    db=(ROOT/'app/db.py').read_text()
    main=(ROOT/'app/main.py').read_text()
    assert 'network_lookup": False' in ti
    assert 'authority": "NONE"' in ti
    assert 'ai_message_intelligence_observations' in db
    assert 'uq_ai_ti_source_sha' in db
    assert 'idx_ai_ti_template_time' in db
    assert 'idx_ai_ti_sender_time' in db
    assert '/api/ai-intelligence/status' in main
    assert 'OPERATIONAL_LOCAL_EVIDENCE' in main
    assert 'OPERATIONAL_LOCAL_CORRELATION' in main


def test_manual_analysis_does_not_pollute_campaign_repository():
    main=(ROOT/'app/main.py').read_text()
    assert 'source_kind="manual"' in main
    assert 'record_observation=False' in main
    assert 'source_kind="quarantine"' in main
    assert 'record_observation=True' in main


def test_authentication_is_not_ham_proof():
    ti=(ROOT/'app/ai_threat_intelligence.py').read_text()
    assert 'passes do not subtract risk or imply HAM' in ti
    assert 'Authentication success is identity evidence, never HAM proof' in ti
