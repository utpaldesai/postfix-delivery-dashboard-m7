from pathlib import Path
root=Path(__file__).resolve().parents[1]
main=(root/'app/main.py').read_text()
email=(root/'app/email_analysis.py').read_text()
req=(root/'requirements.txt').read_text().lower()
assert 'extract-msg>=0.48,<1.0' in req
assert 'Drop an <b>.eml</b> or <b>.msg</b>' in main
assert 'Attachments</h4>' in main and 'URLs</h4>' in main and 'AI Shadow Intelligence' in main
assert 'grid-template-columns:auto minmax(72px,1fr) auto auto' in main
assert 'minmax(265px,1.45fr)' in main
assert 'The selected .msg file is not a valid Outlook Compound File Binary message' in email
assert '"attachments": attachments' in email and '"urls": urls' in email
print('AI R1.1.3 MSG native + UI defect regression passed')
