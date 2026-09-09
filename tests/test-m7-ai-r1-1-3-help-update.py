from pathlib import Path
main = Path('app/main.py').read_text()
required = [
    '<h3>Quarantine Intelligence</h3>',
    '<h3>AI Shadow Intelligence</h3>',
    '<h3>Email Analysis</h3>',
    '<h3>SpamAssassin Learning & Human Correction</h3>',
    '<h3>Manage Email Size</h3>',
    '<h3>Mail Flow</h3>',
    '<h3>GEO-IP Database</h3>',
    'native Microsoft Outlook .msg file',
    'Submission — Port 587 and Webmail',
    'existing production Bayes database through sa-learn',
    'shadow-only and independent of SpamAssassin/Amavis classification',
]
for text in required:
    assert text in main, f'Missing Help content: {text}'
print('AI R1.1.3 Help update regression passed')
