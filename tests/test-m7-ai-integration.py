from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text(encoding='utf-8')
q=(root/'app/quarantine.py').read_text(encoding='utf-8')
compose=(root/'docker-compose.yaml').read_text(encoding='utf-8')
ai=(root/'app/ai_trainer.py').read_text(encoding='utf-8')
assert '@app.get("/api/ai-trainer/status")' in main
assert '@app.post("/api/ai-trainer/backfill")' in main
assert '@app.post("/api/ai-trainer/train")' in main
assert '@app.post("/api/ai-trainer/promote")' in main
assert '@app.get("/api/ai-trainer/predict")' in main
assert 'AI Shadow Intelligence' in main
assert 'Training Provenance Audit' in main
assert 'SHADOW ONLY' in main
assert 'SpamAssassin/Bayes learning remains completely' in q
assert 'Do not mirror sa-learn outcomes into' in q
assert 'AI_TRAINER_ENABLED' in compose
assert 'AI_SHADOW_MODE = True' in ai
assert 'Never participates in SMTP/Amavis delivery decisions' in ai
assert 'Never writes to SpamAssassin Bayes tables' in ai
print('M7 AI integration regression passed')
