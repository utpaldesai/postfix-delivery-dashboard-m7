from pathlib import Path
import json
import tempfile
from app import ai_trainer as ai

root = Path(__file__).resolve().parents[1]
main = (root/'app/main.py').read_text(encoding='utf-8')
compose = (root/'docker-compose.yaml').read_text(encoding='utf-8')
env = (root/'.env.example').read_text(encoding='utf-8')
help_text = main

assert 'balanced-logistic-regression-hashed-v4-authneutral-independent' in (root/'app/ai_trainer.py').read_text(encoding='utf-8')
assert 'AI_TRAINER_AUTO_TRAIN_AFTER_NEW_LABELS' in compose
assert 'AI_TRAINER_AUTO_TRAIN_AFTER_NEW_LABELS=250' in env
assert 'Balanced accuracy' in main
assert 'HAM precision / recall / F1' in main
assert 'SPAM precision / recall / F1' in main
assert 'HAM→SPAM false positive' in main
assert 'SPAM→HAM false negative' in main
assert 'Automatic retraining creates a candidate only' in main
assert 'AI trainer is shadow-only and independent of SpamAssassin/Amavis classification' in help_text

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    ai.STATE_DIR = td/'state'
    ai.DATASET = ai.STATE_DIR/'training_samples.jsonl'
    ai.CANDIDATE_MODEL = ai.STATE_DIR/'candidate_model.json'
    ai.ACTIVE_MODEL = ai.STATE_DIR/'active_model.json'
    ai.EVENT_LOG = ai.STATE_DIR/'events.jsonl'
    ai.MODEL_META = ai.STATE_DIR/'model_meta.json'
    ai.AI_ENABLED = True
    ai.MIN_PER_CLASS = 5
    ai.AUTO_TRAIN_AFTER_NEW_LABELS = 250
    # 60 diverse deterministic samples guarantee a real stratified holdout.
    for i in range(30):
        for label, words, spf, score in [
            ('HAM', f'project report meeting invoice approved colleague schedule {i}', 'pass', '-1.0'),
            ('SPAM', f'urgent password verify crypto prize click account suspended {i}', 'fail', '12.0'),
        ]:
            f = td/f'{label.lower()}-{i}.eml'
            f.write_text(f'From: sender{i}@example.test\nTo: user@example.test\nSubject: {words}\nX-Spam-Status: {"Yes" if label=="SPAM" else "No"}, score={score} tests=BAYES_99,SPF_FAIL\n\n{words}\n', encoding='utf-8')
            ai.record_human_label(f.name, label, f, {'spf':spf,'dkim':spf,'score':score}, 'tester')
    candidate = ai.train_candidate('tester')
    metrics = candidate['metrics']
    assert candidate['algorithm'] in {'balanced-logistic-regression-hashed-v4-authneutral-independent','multinomial-naive-bayes-hashed-v2-independent'}
    assert metrics['holdout_samples'] > 0
    assert metrics['holdout_ham'] > 0 and metrics['holdout_spam'] > 0
    for key in ('accuracy','balanced_accuracy','spam_precision','spam_recall','spam_f1','ham_precision','ham_recall','ham_f1','false_positive_rate','false_negative_rate','confusion_matrix'):
        assert key in metrics, key
    st = ai.status()
    assert st['auto_train_after_new_labels'] == 250
    assert st['labels_since_candidate'] == 0
    assert st['next_auto_train_in'] == 250
    assert not ai.ACTIVE_MODEL.exists(), 'candidate training must never auto-promote'

print('M7 AI R1.1.6 trainer v2 regression passed')
