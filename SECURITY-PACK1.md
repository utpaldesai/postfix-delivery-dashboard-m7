
## R1.1.31 Amavis attachment history security note

Attachment history is sourced only from the existing read-only Amavis log. The dashboard does not open attachment files, execute MIME content, extract archives, fetch URLs, or weaken host log permissions. Persistence is additive in MariaDB and current-message lookup uses exact indexed identifiers rather than sender-only correlation.

# R1.1.29 Security / Data-Safety Addendum

R1.1.29 uses additive `CREATE TABLE IF NOT EXISTS` schema changes and conditional `ALTER TABLE ... ADD KEY` operations only. Existing populated MariaDB data is not recreated, truncated, reset, replaced, or rolled back. Amavis production logs and quarantine objects remain read-only. Current-message trace correlation does not use sender-only matching. Independent AI ground truth and conflict investigations do not invoke SpamAssassin learning or mail-flow actions.

# Milestone 5 Security Pack 1

This pack is based on the Milestone 5 corrected quarantine baseline.

## Implemented hardening

1. Login rate limiting
   - Default: 5 failed attempts within 60 seconds.
   - Default lockout: 300 seconds.
   - Successful authentication clears the failure state for the client IP.
   - HTTP 429 includes Retry-After.

2. Absolute session expiration
   - Default: 8 hours.
   - Idle expiration remains 15 minutes by default.
   - Both `get()` and `touch()` enforce absolute expiration.
   - Session cookie Max-Age follows the absolute session lifetime.

3. Cookie production setting
   - `.env.example` sets `SESSION_COOKIE_SECURE=true`.
   - If the dashboard is intentionally served over plain HTTP on a controlled LAN,
     the deployment `.env` must explicitly use `SESSION_COOKIE_SECURE=false`.

4. CSRF/origin hardening
   - Cookie-authenticated POST/PUT/PATCH/DELETE requests require either:
     - matching Origin/Referer, or
     - the dashboard's `X-Postfix-Dashboard: 1` header.
   - `/api/login` is exempt because it does not rely on an authenticated session cookie.

5. Readiness information exposure
   - `/health/ready` returns only `ready` or `not_ready`.
   - `/api/system/ready` is session-protected and retains detailed status.

6. Error disclosure
   - Quarantine refresh no longer returns raw exception text.
   - Detailed failure information is sent to the server log.

7. Build identity
   - Docker image tag is `legacy Milestone 5 image tag`.

## Explicitly unchanged

- Quarantine five-column layout.
- Checkbox location inside Category / Time.
- Message Details wrapping/ellipsis behavior.
- SPF / DKIM, Spam Score, and Actions column placement.
- Individual and bulk quarantine actions.
- 100-item server-side bulk limit.
- Read-only quarantine mount.
- Amavis PDP `127.0.0.1:9998`.
- Host `amavisd-release` wrapper and `perl -T`.
- No deletion, movement, rename, truncation, or overwrite of quarantine objects.


### R1.1.25 consistency note
The log-derived Home-Domain Email ID MIS is removed rather than treating parsed addresses as an authoritative mailbox inventory. No database reset or destructive migration is used. The Released KPI remains a persistent audit count and does not imply successful delivery.


## R1.1.37 harmful-email repository safety
Raw third-party email corpora are not bundled or executed. Registered research sources are metadata/provenance only in the release package. External research has no training authority, no delivery authority, and no automatic Set-2 Ground Truth path. Existing MariaDB history is preserved; no DROP/TRUNCATE/reset migration is introduced.
