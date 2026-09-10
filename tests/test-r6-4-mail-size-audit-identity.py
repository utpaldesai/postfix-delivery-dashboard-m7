from pathlib import Path
main=Path('app/main.py').read_text(encoding='utf-8')
php=Path('host-tools/mail-size-api.php').read_text(encoding='utf-8')
assert 'X-Dashboard-Client-IP' in main
assert 'X-Dashboard-Username' in main
assert 'request.client.host if request.client else "unknown"' in main
assert "HTTP_X_DASHBOARD_CLIENT_IP" in php
assert "HTTP_X_DASHBOARD_USERNAME" in php
assert "[USER:" in php and "[IP:" in php
assert "[API:127.0.0.1]" not in php
assert "in_array($remote, ['127.0.0.1', '::1'], true)" in php
print('R6.4 Mail Size audit identity regression passed')
