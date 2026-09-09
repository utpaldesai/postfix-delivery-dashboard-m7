from app.monitor import parse_dovecot_events
lines=[
'Aug 27 10:00:01 host dovecot: pop3-login: Login: user=<a@example.test>, method=PLAIN, rip=8.8.8.8, lip=10.0.0.1, mpid=1, TLS',
'Aug 27 10:01:01 host dovecot: imap-login: Login: user=<b@example.test>, method=PLAIN, rip=1.1.1.1, lip=10.0.0.1, mpid=2, TLS',
'Aug 27 10:02:01 host dovecot: imap-login: Disconnected: Connection closed (auth failed, 1 attempts in 2 secs): user=<b@example.test>, method=PLAIN, rip=9.9.9.9, lip=10.0.0.1',
]
e=parse_dovecot_events(lines)
assert [x['protocol'] for x in e]==['POP3']
assert [x['status'] for x in e]==['SUCCESS']
assert e[0]['remote_ip']=='8.8.8.8'
print('Monitor parser regression passed: IMAP intentionally ignored.')
