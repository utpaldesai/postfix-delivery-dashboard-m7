# R1.1.46 — Quarantine Intelligence Grid Realignment

## R1.1.47 — Email Analysis realignment + safe Amavis dry-run adapter

- Email Analysis now uses a full-width Message Input card with a bounded 240–420px raw-source editor instead of the previous left-heavy 50/50 page split.
- Results are realigned into a balanced two-column primary review row: Independent AI Analysis and Amavis / SpamAssassin Dry Run.
- AI model metadata uses a wider three-column grid and long candidate IDs, ASN/domain values and signal names wrap safely.
- A full-width AI-vs-Amavis comparison strip and balanced Authentication / Production Evidence + Campaign / MIME / Attachment row follow the primary review cards.
- Responsive stacking starts at 1100px; no page-level horizontal overflow is introduced.
- Added an **analysis-only Amavis dry-run adapter** at `/api/email-analysis/amavis-dry-run`. It is disabled by default and only talks to an explicitly configured dedicated HTTP helper. The dashboard refuses production Amavis SMTP/after-filter/PDP ports 10024, 10025 and 9998.
- The helper result is accepted only when it attests `analysis_only=true` and reports no delivery, quarantine, release, `sa-learn`, Bayes update, AI ground-truth, or production-queue side effect.
- No production mail-flow, quarantine, release, Bayes, AI training or MariaDB schema behavior is changed by this release.


- Realigns Quarantine Intelligence with explicit desktop review and support rows so optional cards do not leave orphaned/blank grid columns.
- Keeps **AI Shadow Intelligence** and **Mail Admin Ground Truth** aligned side-by-side on wide screens and stacked responsively below 1100px.
- Aligns **Infrastructure AI** and **Campaign AI** into a consistent two-card nested evidence grid with uniform label/value columns and safe long-value wrapping.
- Pairs **GEO-IP Intelligence** with **Sender Policy** in a balanced evidence row; **Amavis Current Message Trace** and **Dashboard Learning History** remain full-width.
- UI-only change: no Postfix/Amavis/SpamAssassin flow change, no AI authority change, no database migration, and no existing MariaDB data modification.
- Preserves SHADOW ONLY AI, stable image `postfix-delivery-dashboard:m7`, BANNED/VIRUS behavior, and all R1.1.45 three-tier intelligence logic.

# Postfix Delivery Dashboard — R1.1.45 Local Three-Tier Threat Intelligence

R1.1.45 builds cumulatively on R1.1.44 and introduces the first operational self-contained three-tier SHADOW intelligence foundation: Message AI remains the independent schema-v4 candidate, Infrastructure AI adds local Received/PTR-HELO/IP/offline-ASN and identity-consistency evidence, Campaign AI adds privacy-reduced local fingerprint correlation for repeated templates/snowshoe/botnet-like source diversity/multi-ASN/URL-domain reuse, and an explainable Correlation Engine combines the available tiers without any mail-flow authority. No third-party runtime feed is required. Manual uploaded samples are analyzed but are not written into the production campaign corpus. Existing MariaDB, Postfix/Amavis evidence, login history, quarantine state and AI ground truth remain preserved.


- POP3/Webmail background ingestion now uses additive MariaDB device/inode/byte-offset checkpoints per source. Existing populated login history is adopted at EOF on upgrade; fresh installs bootstrap only the bounded tail. Appends, truncation, restart and inode rotation are handled without rereading the previous 2 MB every 30 seconds.
- Login parser GEO enrichment is deferred until after event-hash deduplication, so replay/restart protection cannot repeatedly re-enrich historical rows. Raw `mail_login_events` and the existing `mail_login_user_summary` remain authoritative/preserved.
- The main dashboard MariaDB path now uses a bounded reusable PyMySQL connection pool (default 8) instead of opening/closing a new connection for every query/background iteration. Connections are rollback-cleaned and ping-validated before reuse.
- Daily Bounced Domain Summary and bounce drill-down now use the additive indexed `postfix_bounce_projection`, avoiding repeated `STR_TO_DATE` / `SUBSTRING_INDEX` scans across the complete `postfix_delivery_final` history. Existing delivery data is untouched; terminal bounces maintain the projection transactionally.
- Mail Delivery keeps the R1.1.41 index-first live path and the R1.1.39 durable Postfix checkpoint model unchanged.
- R1.1.43 AI-status/polling corrections remain in place. `/health/live` remains active and constant-time.
- All schema work is forward-only/additive: no populated MariaDB tables are dropped, truncated, reset, recreated or rolled back. Stable deployment image remains `postfix-delivery-dashboard:m7`.

# Postfix Delivery Dashboard — R1.1.44

## R1.1.43 — Runtime I/O and Polling Correction

- AI live status reads compact MariaDB-backed counters instead of reparsing the full immutable training JSONL every refresh. The JSONL remains authoritative audit/training evidence and is scanned only to bootstrap/repair the compact snapshot.
- AI architecture status polling runs only while the AI Trainer Flow or AI Intelligence Layout Help visualization is actually open.
- Delivery global statistics are cached for 60 seconds and no longer fetched on every live Delivery refresh. Delivery refresh cadence is 15 seconds; Summary refresh is 30 seconds while visible.
- `/health/live` remains a constant-time liveness response; only its Uvicorn access-log line is filtered to reduce noise.
- All database changes are forward-only/additive. Existing MariaDB data, AI JSONL evidence, Postfix/Amavis evidence, quarantine state and mail flow are preserved.

## R1.1.42 — Login Summary Fast Paths + Help Visualization Tiles

- POP3 and Webmail live summaries use the additive `mail_login_user_summary` projection instead of grouping the full `mail_login_events` history for the normal unfiltered screen.
- Existing raw login history remains authoritative and untouched. The projection is bootstrapped once on upgrade, then maintained in the same transaction as newly inserted de-duplicated events.
- Monitor HTTP requests no longer synchronously rescan Dovecot/Roundcube log tails; background read-only ingestion owns log parsing and the UI reads MariaDB.
- Filtered/date-range login reports retain the historical raw-event path so report semantics remain unchanged.
- Monitor search is debounced by 350 ms and stale in-flight requests are cancelled.
- The dashboard lands on **Delivery** instead of the Mail Flow Chart.
- **Mail Flow Chart**, **AI Trainer Flow**, and **AI Intelligence Layout** are removed from the left navigation and exposed as three tile buttons at the top of **Help**.
- Each architecture view includes **Back to Help**. Mail Flow still honors the existing `mail_flow` ACL.
- Existing MariaDB tables/data are not dropped, truncated, recreated, reset or rolled back.

## R1.1.41 — Live Delivery Index Fast Path

- Fixes Mail Delivery live monitoring so the normal unfiltered view no longer performs a full-history `GROUP BY queue_id` before returning the newest page.
- Selects newest Queue-IDs from a covering `(last_updated, queue_id)` index in bounded windows, then aggregates recipient details only for the visible Queue-IDs.
- Keeps the historical analytical query only for explicit text/date filters and exact-total callers; the live page still uses R1.1.38 look-ahead pagination.
- Adds the secondary index only when missing through the existing forward-only index preflight. No table recreation, reset, truncate, or data rollback is performed.
- Corrects first continuous-Postfix-feed startup: an in-place upgrade with an already-populated `postfix_delivery_final` adopts EOF immediately instead of replaying up to `INITIAL_IMPORT_LINES` through thousands of one-row transactions.
- A fresh installation still honors `INITIAL_IMPORT_LINES`, but reads only the required tail by seeking backwards from EOF instead of scanning the entire active Postfix log into memory.
- Preserves R1.1.40 Quarantine Intelligence cleanup, R1.1.39 local-only intelligence, SHADOW-only AI, the professional Quarantine Intelligence layout, and stable image `postfix-delivery-dashboard:m7`.

## R1.1.40 — Quarantine Intelligence Cleanup

- Removes the **Bayes Learning** card from Quarantine Intelligence.
- Removes the generic **Host maildb Tables** inventory from Quarantine Intelligence.
- Stops querying Bayes statistics and information_schema table-row inventory on every Quarantine Intelligence open.
- Keeps message-relevant Sender Policy and Dashboard Learning History evidence unchanged.
- Does not delete, truncate, alter, or reset any host `maildb`/SpamAssassin tables. This is a Quarantine Intelligence UI/read-path cleanup only.
- Preserves R1.1.39 continuous Postfix ingestion, self-contained local intelligence, professional Quarantine layout, SHADOW-only AI, and populated MariaDB data.


## R1.1.39 — Self-contained Local Intelligence + Continuous Postfix Feed

- Removes the bundled `harmful-email-repo/` and every third-party corpus/source registry from the active package. No PhishTank, URLhaus, Sting9, SpamAssassin public corpus, Rspamd corpus, rf-peixoto corpus, or other Internet threat-intelligence service is required.
- Adds `local-email-intelligence-repo/` containing only locally authored defensive taxonomy/generic pattern families. It is evidence-only (`training_authority=false`); explicit Mail Admin Ground Truth remains the only supervised authority.
- Existing historical repository/corpus rows already present in populated MariaDB are preserved for audit/rollback safety but the R1.1.39 local repository becomes the only active seeded repository. No destructive delete/drop/truncate is performed.
- Converts the Postfix delivery reader to a MariaDB-backed continuous feed with additive `postfix_log_events` and `postfix_log_ingest_state` tables. Raw log lines are retained idempotently and the durable device/inode/offset checkpoint advances only after the delivery projection batch succeeds.
- Handles append, restart, truncate and active-log inode rotation while keeping the host Postfix log read-only. The Mail Delivery UI continues to read the prepared `postfix_delivery_final` projection, preserving R1.1.38 fast initial paint/server-side pagination behavior.
- Local intelligence grows only from administrator-controlled evidence: Postfix events, Amavis evidence, quarantine/action history, attachment/archive metadata, delivered observations, AI/admin conflict investigations and explicit Ground Truth. No runtime network lookup is introduced.
- Preserves the approved professional Quarantine Intelligence layout, SHADOW ONLY AI boundary, stable Docker image `postfix-delivery-dashboard:m7`, and existing populated MariaDB.

## R1.1.38 — Mail Delivery performance optimization

- Mail Delivery now paints the requested delivery page before loading global statistics, so slow category counters cannot block the visible table.
- Interactive delivery requests use server-side page limits plus one look-ahead row instead of running an exact grouped COUNT before first paint. Existing API callers retain exact-count behavior by default.
- Delivery search is debounced by 350 ms and stale in-flight requests are aborted when filters change, preventing overlapping database work while typing.
- Previous/Next navigation uses the look-ahead result immediately; report download, final Postfix status, multi-recipient grouping and Queue-ID drill-down semantics are unchanged.
- No table recreation, reset, destructive migration or data rollback is introduced. R1.1.37 Quarantine Intelligence and harmful-email repository behavior are preserved.


## Historical R1.1.37 — superseded external-corpus experiment

- Replaces the bundled legacy `fraud-repo/` package content with one curated `harmful-email-repo/`. No old repository JSON or broad old corpus registry is shipped. Historical MariaDB records remain untouched for audit and rollback safety.
- Registers only three high-confidence public research sources: Apache SpamAssassin Public Corpus, Rspamd Test Email Corpus, and rf-peixoto/phishing_pot. No raw third-party email sample is bundled.
- External research remains evidence-only (`training_authority=false`) and can never become Set-2 Ground Truth without explicit Mail Admin action.
- Implements the approved Quarantine Intelligence professional layout: 8-field identity strip, explicit candidate-vs-active semantics, complete Ground Truth proposal/admin workflow, reason dropdown, notes, Acknowledge / Save Changed / Reset actions, responsive two-column desktop layout, and no page-level horizontal overflow.
- Stable deployment image remains `postfix-delivery-dashboard:m7`. Existing MariaDB is never recreated/reset/reinitialized.


## R1.1.36 — Quarantine Intelligence professional layout reflow

- Reflows Quarantine Intelligence into a full-width current-message identity strip, a balanced desktop AI/Admin review row, responsive evidence sections, a full-width Amavis current-message trace, and bounded table scrolling.
- Eliminates modal-level horizontal overflow and forces long IDs, paths, model names, and filenames to wrap inside their own cards.
- Mail Admin Ground Truth now explicitly displays the candidate source and SHADOW ONLY / no-promoted-model status beside the pre-filled AI proposal.
- Existing ground-truth behavior is unchanged: only an explicit administrator save creates Set-2 truth; reversals and AI/admin conflicts retain their existing audit/investigation rules.
- Existing populated MariaDB is preserved; no destructive database migration is introduced.

# Historical R1.1.35 — superseded external corpus registry

## R1.1.35 changes

- Continues with the existing populated MariaDB. No database recreation, reset, truncate, destructive rollback, or data-volume replacement is introduced.
- Adds a versioned external email-corpus registry for selective research use: rf-peixoto/phishing_pot, Apache SpamAssassin Public Corpus, Rspamd Test Email Corpus, cw-l/email-corpus, and EPVME Malicious Email Dataset.
- External corpus material remains `EXTERNAL_RESEARCH` only and `training_authority=FALSE`; it never becomes Set-2 Mail Admin Ground Truth automatically.
- Adds forward-only MariaDB tables `fraud_corpus_sources` and `fraud_corpus_snapshots`. Existing fraud, AI, Amavis, audit, release, attachment, delivery and calibration data remain untouched.
- Adds `tools/corpus-checksum.py` to create deterministic per-file SHA-256 manifests plus one snapshot SHA-256 before any offline curation/import.
- EPVME is registered disabled by default and requires isolated offline parsing; the dashboard never executes attachments, renders active HTML, follows URLs, or extracts/executes archives as part of repository curation.
- The active bundled fraud repository becomes `fraud-intel-2026.09.03-v3`; older repository versions remain available for audit history.
- Adds `fraud-repo/CHECKSUMS.sha256` for bundled intelligence/registry files and a package-level `.zip.sha256` at release packaging time.
- Stable deployment image remains `postfix-delivery-dashboard:m7`; AI remains SHADOW ONLY.

# R1.1.33 Fraud Intelligence Repository + AI Ground-Truth Calibration

## R1.1.33 changes

- Continues with the existing populated MariaDB. No database recreation, volume reset, table truncation, or destructive rollback is introduced.
- Adds an idempotent, versioned Fraud Intelligence Repository to the existing database through `CREATE TABLE IF NOT EXISTS` plus hash-based insert/skip logic. The bundled seed is `fraud-intel-2026.09.03-v1`.
- Adds curated explainable fraud families for credential phishing, BEC, invoice fraud, advance-fee/investment fraud, inheritance/419, lottery/prize, fake jobs, charity fraud, tech-support/callback scams, fake e-commerce, SEO/directory spam and UCE.
- Repository entries are `EXTERNAL_RESEARCH` / evidence-only and explicitly `training_authority=FALSE`; they never become Set-2 Mail Admin Ground Truth automatically.
- Adds repository consumption to Quarantine Intelligence and manual Email Analysis. The engine reports hypothesis, severity, matched phrases/structural evidence and a suggested classification without changing mail flow.
- Calibrates **Mail Admin Ground Truth AI ONLY**: current candidate prediction plus repository subtype suggestion are pre-populated. The administrator can acknowledge the AI proposal or change HAM/SPAM/classification in the same form. Only explicit administrator submission creates authoritative ground truth.
- Adds `ai_ground_truth_calibration` to retain AI proposal vs final admin decision, confidence, acknowledgement state, candidate/generation and fraud-repository version for later calibration analysis.
- HAM/SPAM reversals now require a review reason. Previous truth remains immutable audit history and is not trained alongside the new truth.
- Expands the SPAM classification taxonomy while preserving SHADOW ONLY behavior and AI independence from SpamAssassin/Amavis.
- Stable deployment image remains `postfix-delivery-dashboard:m7`. The repository is copied into the image so an in-place rebuild can seed only missing intelligence into the existing database.

# R1.1.31 Amavis Attachment History

## R1.1.31 attachment-content restoration

- Re-adds the Amavis attachment-content view beneath the current-message Amavis trace. The view shows only attachment/archive evidence correlated to the selected message; it does not dump unrelated quarantine/release history.
- Adds forward-only MariaDB table `amavis_attachment_history` for persistent log-derived attachment history. Existing `amavis_log_events`, legacy evidence, quarantine data, AI data and populated MariaDB remain untouched.
- Continuous Amavis ingestion now writes normalized attachment/archive-member evidence to both the existing raw event repository and the new attachment-history table.
- A background bounded backfill copies retained attachment evidence from existing `amavis_log_events` into the new table without rereading or modifying the production log.
- Stores correlation identifiers (mail_id, Queue-ID, release Queue-ID, Message-ID, session ID, quarantine path), attachment/member name, Amavis-reported content text, source raw log and event time.
- Adds indexed current-message attachment lookup. No sender-only matching is used.
- The dashboard never opens or executes attachments and never extracts archives; it only retains what Amavis reports in the read-only log.
- Preserves R1.1.30 security correction, R1.1.29 intelligence performance/index tuning/current-message trace, authentication-neutral AI, SHADOW ONLY mode and stable image `postfix-delivery-dashboard:m7`.

## Historical R1.1.30 Security Regression Correction

## R1.1.30 correction

- Corrects the Milestone 5 Security Pack 1 regression failure introduced by the AI ground-truth endpoint.
- Invalid AI ground-truth requests now return a fixed client-safe message instead of exposing `str(exc)` through `HTTPException.detail`.
- Full exception detail remains server-side only.
- No database reset, table drop, data-volume replacement, mail-flow change, or AI promotion is introduced.
- R1.1.29 intelligence performance, current-message Amavis trace, index tuning, reverse-engineering, classification and label-history functionality is preserved.


- AI Intelligence live status now uses an 8-second server-side snapshot keyed to dataset/candidate/active-model file signatures, so the 10-second UI feed does not reparse the complete trainer dataset on every poll. Cache invalidates immediately on new ground truth, candidate training, or promotion.
- Amavis Intelligence now defaults to `CURRENT_MESSAGE_ONLY` and correlates by indexed exact identifiers in priority order: `mail_id` -> Queue-ID/release Queue-ID -> Message-ID -> quarantine path, then expands only the matching Amavis session. Sender-only and broad raw-log correlation are not used for the normal current-message trace.
- Historical Amavis evidence remains retained in MariaDB; the current-item card no longer presents unrelated quarantine/release traces. Live-log scanning remains emergency fallback only for explicit identifiers.
- Adds idempotent, forward-only secondary-index tuning through `INFORMATION_SCHEMA.STATISTICS`, including composite hot-path indexes for Amavis mail/queue/message/session/quarantine correlation, delivery status/queue recency, and audit PDP/action recency. No table/volume reset or destructive migration is used.
- Adds independent Mail Admin Ground Truth UI: HAM/SPAM plus context-sensitive classification dropdown. This does not call `sa-learn`, modify Bayes, release quarantine, or alter Postfix/Amavis flow.
- Label history is persisted in additive MariaDB table `ai_ground_truth_history`; a changed label supersedes the previous CURRENT row while preserving immutable history and reversal count.
- AI/human disagreement triggers bounded full-message local forensic re-analysis and persists the reduced investigation in `ai_conflict_investigations`. It never automatically changes the human label or model.
- Candidate validation now retains safe FP/FN sample references/probabilities and reports dedicated Hard-HAM holdout count/correct/false-positive/recall metrics.
- Authentication policy remains `identity-neutral-v1`: SPF/DKIM/DMARC PASS is identity evidence only, never positive HAM trust.
- Stable application image remains `postfix-delivery-dashboard:m7`; AI remains SHADOW ONLY.



### R1.1.28 AI authentication calibration

- SPF/DKIM/DMARC PASS is now explicitly identity/alignment evidence only, never positive HAM trust evidence.
- Direct authentication PASS tokens are excluded from newly extracted AI vectors.
- Historical approved training vectors are scrubbed in memory for legacy direct PASS tokens before candidate training; existing labels/audit history are preserved.
- Candidate models now carry `authentication_policy=identity-neutral-v1`; pre-R1.1.28 candidates without this policy are not considered current-compatible.
- Email Analysis labels authentication passes as `neutral` and explains that authenticated UCE/phishing can still be SPAM.
- No Postfix/Amavis delivery behavior, SpamAssassin/Bayes data, or existing MariaDB data is changed.

## R1.1.28 Authentication-Neutral UCE Calibration

- Corrects R1.1.26 lazy/on-demand Amavis evidence behavior. `/var/lib/amavis/logs/amavis.log` is now continuously ingested read-only into MariaDB in a background worker.
- Adds forward-only tables `amavis_log_events` and `amavis_log_ingest_state`; existing populated MariaDB data and the legacy `amavis_log_evidence` table are preserved untouched.
- First deployment imports the complete currently retained active Amavis log in the background, then follows new records incrementally. MariaDB stores the durable device/inode/offset checkpoint and never advances it past a failed database batch.
- Handles append, restart, truncate and active-path inode rotation without modifying the source log. The Amavis log directory is mounted read-only so log rotation remains visible inside the container.
- Persists raw log evidence plus best-effort Queue-ID, release Queue-ID, Message-ID, Amavis mail_id, Amavis session identifier, sender/recipient, verdict, spam score, quarantine path, virus/banned and attachment filename evidence.
- Email Analysis and Amavis Log Intelligence query continuous MariaDB evidence first. Legacy retained evidence remains searchable; a bounded live-log scan is emergency bootstrap fallback only.
- UI now distinguishes source readability, MariaDB storage, ingestion status and evidence correlation. `NO MATCH` no longer implies that Amavis never processed a message.
- Stable application image remains `postfix-delivery-dashboard:m7`; AI remains SHADOW ONLY and SpamAssassin/Amavis evidence remains observation-only for AI.

## R1.1.26 Live Multi-Tier Trainer + Trainer-Calibrated Email Analysis

- Replaces the compact trainer strip with a live graphical flow matching the approved Multi-Tier Threat Intelligence architecture.
- Places Message AI, Infrastructure AI and Campaign AI between schema-v4 feature extraction and shadow prediction, with an explicit SHADOW experimental correlation layer.
- Clearly marks Message AI as operational, Infrastructure AI as development/partial, and Campaign AI as building historical data; future capabilities are not presented as already implemented.
- Email Analysis now uses the current-generation trainer candidate for manual SHADOW ONLY analysis when available, even when no active model has been promoted.
- Email Analysis displays trainer generation, feature schema, candidate/active model identity and algorithm, and keeps SpamAssassin/Amavis evidence in a separate observation-only panel.
- No AI result automatically becomes ground truth. No Postfix/Amavis delivery action, Bayes learning, quarantine mutation or destructive MariaDB operation is introduced.
- Stable Docker deployment image remains `postfix-delivery-dashboard:m7`.

# Postfix Delivery Dashboard — Milestone 7 Enterprise

Current production baseline. Fail2Ban/CrowdSec integration is intentionally held and is not part of this build.

Enterprise deployment guarantees:
- existing populated MariaDB is preserved and validated read-only before application replacement;
- new application image is built before the running app is stopped;
- previous running application image is retained as a rollback image;
- failed application deployment automatically restores the prior app image;
- database data is never rolled back, reinitialized, or deleted;
- single `docker-compose.yaml`;
- root documentation is limited to `README.md` and `SECURITY-PACK1.md`;
- Mail Flow Refresh and Full Screen controls use explicit event bindings and a single fullscreen implementation.

---

# Postfix Delivery Dashboard — Milestone 6

Current production-development baseline: **Milestone 6**. Current deployment, upgrade, learning, security, and operational notes are consolidated in this `README.md`, `UPGRADE-MILESTONE6.txt`, and `SECURITY-PACK1.md`. Historical implementation-note Markdown files were intentionally removed to keep the source tree clean.

# Postfix Delivery Dashboard — Milestone 4

Milestone 4 branches from the Milestone 2 working baseline and keeps the existing Postfix parser, MariaDB data path, Amavis host-network design, quarantine retention rules, `perl -T` release wrapper, Release no-prompt behavior, Audit fixes, inactivity handling, and Quarantined counter behavior.

## Milestone 4 additions

### 1. Real server-side session authentication

HTTP Basic authentication has been removed.

The dashboard now provides `/login` and creates a cryptographically-random server-side session token stored in an `HttpOnly`, `SameSite=Strict` cookie. Real browser activity calls `/api/session/touch`; background dashboard refreshes do not extend inactivity. Default inactivity timeout is 15 minutes.

```dotenv
SESSION_IDLE_TIMEOUT_MINUTES=15
SESSION_COOKIE_NAME=postfix_dashboard_session
SESSION_COOKIE_SECURE=false
```

Set `SESSION_COOKIE_SECURE=true` only when the dashboard is served over HTTPS.

Audit actions include `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, and `AUTO_LOGOUT_INACTIVITY`.

### 2. MariaDB-backed Audit reporting

A new `dashboard_audit` table is created automatically. Existing JSONL audit data is idempotently migrated on startup in batches. JSONL remains an append-only secondary copy.

The Audit tab reads indexed MariaDB audit records and can display action, user, client IP, sender, recipient, subject, score, quarantine ID, and failure detail.

Failed release/Mark Spam attempts are audited as `RELEASE_FAILED` / `SPAM_MARK_FAILED` without exposing raw backend exceptions in the UI.

### 3. System Status / readiness

A new **System Status** tab reads `/health/ready` and checks:

- MariaDB
- Postfix `mail.log`
- quarantine directory
- audit/state directory
- OS-level Amavis PDP `127.0.0.1:9998`

`/health/live` remains the lightweight process liveness endpoint.

### 4. Incremental quarantine scanner

Quarantine scanning now tracks each recent file by:

```text
relative path + mtime_ns + size
```

Unchanged files reuse parsed metadata; only new or changed files are reparsed. Release/Mark Spam state is refreshed even when the email file itself is reused.

### 5. Queue-ID mail-flow drill-down

Queue IDs in the Delivery tab are clickable. The drawer calls:

```text
GET /api/flow/{queue_id}
```

and displays queue metadata plus final Postfix recipient events, targets, details, and raw log lines.

## Important retained Milestone behavior

The dashboard application continues to use:

```yaml
network_mode: host
```

so container `127.0.0.1:9998` reaches the host OS `amavisd-new` AM.PDP listener.

The Amavis wrapper still invokes:

```python
result = subprocess.run(
    ["perl", "-T", str(TARGET), *sys.argv[1:]],
    check=False,
)
```

Quarantine files remain read-only and are never deleted, moved, renamed, truncated, or overwritten.

## Test layout

Production root is clean. Test scripts are under:

```text
tests/
```

and excluded from the Docker image through `.dockerignore`.

Run all source checks:

```bash
./verify-source.sh
```

or:

```bash
python3 audit-build.py
for f in tests/test*.py; do PYTHONPATH=. python3 "$f" || exit 1; done
```

## Upgrade / rebuild

Existing data is preserved in:

```text
.env
./data/mariadb
./data/amavis-mgr
```

Before rebuild, confirm your `.env` contains the desired session values. Then run:

```bash
chmod +x full-rebuild.sh verify-running.sh verify-source.sh
./full-rebuild.sh
./verify-running.sh
```

`full-rebuild.sh` runs the source audit/tests before stopping the application container.

## Runtime note

Sessions are intentionally stored in-process because the supplied Uvicorn deployment runs one application worker. Restarting the dashboard invalidates active sessions, which is a secure default. If the application is later changed to multiple Uvicorn workers, session storage should be moved to MariaDB or Redis.


## Milestone 4 - Quarantine Enhancements Pack 1

This pack keeps the Milestone 4 backend architecture and adds only the agreed quarantine/UI packaging changes.

### Quarantine layout
The existing adjacent columns remain:
- Category / Time
- Message details
- SPF / DKIM
- Spam score
- Actions

Only the Message details column is reformatted to:
- From
- To
- Subject
- ID

Mailbox headers are normalized at parse time so duplicate quoted recipient addresses are not shown twice.

### Optional multi-selection
Each non-finalized visible quarantine item has a checkbox.
Bulk controls:
- Select all visible
- RELEASE SELECTED
- MARK SELECTED AS SPAM

Single-item RELEASE and MARK SPAM remain available.
Already released / marked-spam rows cannot be selected.
Each individual bulk operation uses the existing audited backend action, so every success/failure remains independently traceable in Audit.
Maximum bulk request size: 100 items.

### Packaging cleanup
Only `docker-compose.yaml` is included.
Host-side `verify-source.sh` uses `python3`.
Tests remain under `tests/` and are excluded from the production image.


## Quarantine Enhancements Pack 2 - Verification Fix

No application functionality changed from Pack 1.

The quarantine layout regression test now validates `From`, `To`, `Subject`,
and `ID` structurally with whitespace-tolerant regular expressions instead
of exact HTML substring matching.


## Quarantine Enhancements Pack 3 - Checkbox Visibility Fix

Fixed bulk-selection checkbox visibility. The global dashboard `input` rule
sets `min-width:240px`; checkbox-specific CSS now overrides width, minimum
width/height, flex and padding so checkboxes remain visible inside the
Category/Time column. Adjacent SPF/DKIM, Score and Action columns are unchanged.


## Quarantine Enhancements Pack 4 - Spam Score Column Fix

Desktop quarantine rows are explicitly fixed to five adjacent sections:

1. Category / Time / Select
2. Message Details: From / To / Subject / ID
3. SPF / DKIM
4. Spam Score
5. Release / Mark Spam

The Spam Score column is always visible between SPF/DKIM and Actions on the desktop layout.


## Milestone 4 - Approved Quarantine UI Bundle

The quarantine list now follows the approved visual reference:
- checkbox selection column
- Category / Time
- Message Details
- SPF / DKIM
- Spam Score
- Actions

Message Details remain compact inside the available width:
- From: one line, ellipsis, full value on hover
- To: one line, ellipsis, full value on hover
- Subject: maximum two lines, full value on hover
- ID: one line, ellipsis, full value on hover

Bulk Release and Mark Selected as Spam remain optional additions. Existing
single-item Release / Mark Spam actions and the Amavis release architecture are unchanged.


# Milestone 5 Baseline

Milestone 5 is promoted from the validated Milestone 4 Quarantine Correction 1 build.

Milestone 5 baseline preserves:
- five-column quarantine layout:
  Category / Time | Message Details | SPF / DKIM | Spam Score | Actions
- compact selection checkbox inside Category / Time
- From / To / ID single-line ellipsis with hover title
- Subject up to two lines with hover title
- individual RELEASE / MARK SPAM actions in the Actions column
- bulk Release Selected / Mark Selected as Spam
- server-side session authentication and inactivity expiry
- MariaDB-backed audit with JSONL secondary copy
- System Status/readiness
- incremental quarantine scanning
- Queue-ID mail-flow drill-down
- host-network Amavis PDP release at 127.0.0.1:9998
- Perl taint-safe amavisd-release wrapper
- read-only quarantine mount and no quarantine object deletion/move/rename/truncate/overwrite
- only docker-compose.yaml in the bundle


## Milestone 5 Security Pack 1

Security Pack 1 hardens the Milestone 5 baseline without changing the quarantine
five-column UI or the Amavis release workflow.

Changes:
- Login rate limiting: 5 failed attempts / 60 seconds, then 300-second lockout by default.
- Absolute session lifetime: 8 hours by default, in addition to the 15-minute idle timeout.
- Session cookie gets a Max-Age matching the absolute session lifetime.
- `.env.example` defaults `SESSION_COOKIE_SECURE=true` for HTTPS production use.
  Existing HTTP-only LAN deployments must explicitly retain `SESSION_COOKIE_SECURE=false`.
- Cookie-authenticated unsafe requests receive an Origin/custom-header CSRF guard.
- Public `/health/ready` exposes only ready/not_ready.
- Authenticated `/api/system/ready` provides the detailed System Status data.
- Quarantine refresh failures return a generic client error while logging details server-side.
- Docker image tag updated to `legacy Milestone 5 image tag`.

New environment settings:
- `SESSION_ABSOLUTE_TIMEOUT_HOURS=8`
- `LOGIN_RATE_LIMIT_ATTEMPTS=5`
- `LOGIN_RATE_LIMIT_WINDOW_SECONDS=60`
- `LOGIN_RATE_LIMIT_LOCKOUT_SECONDS=300`


## Milestone 5 Security Pack 1 R4 — User ACL + Help

R4 adds a MariaDB-backed User ACL administration panel and Help tab.

### User ACL
- Administrator-only User ACL tab.
- Dashboard users stored in MariaDB.
- Passwords stored as PBKDF2-HMAC-SHA256 hashes with per-user random salt.
- Bootstrap administrator is created from WEB_USERNAME / WEB_PASSWORD only when the user table is empty.
- Per-area access levels: None, View, Admin.
- Areas: Delivery, Summary, Amavis Quarantine, System Status, Audit, Mail Flow.
- Quarantine View users cannot Release, Mark Spam, bulk-action or Rescan.
- Quarantine Admin users retain management actions.
- Disabled/deleted users lose API access even if an old session cookie remains.
- Current administrator cannot delete, disable, or remove their own administrator role.
- ACL create/update/delete operations are written to the existing audit system.

### Help
The Help tab documents Delivery, Summary, Quarantine, Spam Score hover, System Status,
Audit, User ACL, session security, and quarantine safety.

The existing five-column quarantine layout and Amavis release workflow are unchanged.


## Milestone 5 Security Pack 1 R7 — Bounced Summary Drill-down

The Daily Bounced Domain Summary now makes each non-zero Sent and Received count
clickable. Selecting a count opens a detail table scoped to that exact date,
external domain and direction.

Columns:
- DATE
- FROM
- TO
- SUBJECT
- REASON FOR BOUNCE

The drill-down uses only BOUNCED rows from `postfix_delivery_final` and is
protected by Summary View permission.

Subject limitation: standard Postfix final-delivery log records do not contain
the original RFC Subject header. Historical/current rows therefore display
`Not captured` unless a trusted subject-ingestion source is added in a future
release. No subject value is fabricated.


## Milestone 5 Security Pack 1 R8 — Excel-style Text Filters

Delivery, Amavis Quarantine and Quarantine Audit now provide an operator selector
beside the existing text search field.

Operators:
- Equals
- Not equal
- Begins with
- Ends with
- Contains
- Does not contain

The operator is applied server-side so pagination and result counts remain
consistent with the selected filter. Negative operators require all searchable
fields to satisfy the exclusion condition.

Delivery Status also has additional top padding so the dashboard does not sit
against the browser's upper boundary.

Existing ACL, Help, bounce drill-down, Spam Score popup, five-column quarantine
layout and Amavis release safety remain unchanged.


## Milestone 5 Security Pack 1 R15 — Native Mail Size Dashboard

`Mail Size` is a native dashboard page positioned immediately before
`System Status`. It no longer embeds or opens the old external PHP page.

Browser flow:

`Browser -> Dashboard /api/mail-size/* -> loopback-only host JSON helper -> deploy_postfix.sh`

The browser communicates only with the dashboard. The host helper exists solely
to perform privileged operations that the read-only dashboard container must not
perform directly.

Native Mail Size features:
- Base64/MIME size calculator
- Outlook/submission message-size limit
- Webmail/465 message-size limit
- 30-second update cooldown
- recent backups and restore
- host-side Mail Size audit trail
- Mail Size Admin ACL requirement

Host helper:
- `host-tools/mail-size-api.php`
- accepts loopback requests only
- requires `X-Mail-Size-Key`
- reads `/etc/postfix/master.cf`
- uses the existing restricted `/usr/local/bin/deploy_postfix.sh`
- keeps backups/audit under `/var/lib/postfix-web`

Install once on the mail host:

```bash
sudo ./host-tools/install-mail-size-api.sh
```

The installer creates a random shared key in
`/etc/postfix-web/mail-size-api.key`, installs the helper as
`/var/www/html/mail-size-api.php`, and updates `.env` with:

```dotenv
MAIL_SIZE_API_URL=http://127.0.0.1/mail-size-api.php
MAIL_SIZE_API_KEY=<generated-secret>
```

After that run `./full-rebuild.sh`.


## Milestone 5 Security Pack 1 R12 — Upper Page Indicators

Delivery, Amavis Quarantine and Quarantine Audit now show `Page n of total`
at the upper-right of the paginated content area while retaining the existing
bottom pager controls.


## Milestone 5 Security Pack 1 R13 — Durable Log Resume

The Postfix log reader now stores a persistent byte-offset checkpoint in:

`./data/reader/mail-log-checkpoint.json`

The directory is bind-mounted to `/data/reader` and is preserved by
`full-rebuild.sh`.

Behavior:
- After each successful ingestion batch, the reader checkpoints the open log
  file device/inode and byte offset.
- On restart/rebuild, the same file resumes at that durable offset.
- The checkpoint is intentionally written after processing, so a crash may
  replay a small number of already-processed lines but will not advance beyond
  unprocessed lines.
- If the active log is replaced/rotated or truncated, the new active file is
  read from byte zero rather than reusing an invalid offset.
- Existing installations without a checkpoint perform the legacy
  `INITIAL_IMPORT_LINES` bootstrap once and then create the durable checkpoint.

Default checkpoint flush policy:
- every 2 seconds, or
- every 100 processed log lines,
whichever occurs first.

These can be changed with `INGEST_CHECKPOINT_FLUSH_SECONDS` and
`INGEST_CHECKPOINT_FLUSH_LINES`.


## Milestone 5 Security Pack 1 R16 — Dashboard IP Allowlist Removed

Dashboard user access no longer depends on `QUARANTINE_ALLOWED_IPS` or any
client-IP allowlist. Delivery, Summary, Amavis Quarantine, Quarantine Audit,
Mail Size, System Status and other dashboard areas are controlled by the
authenticated session and User ACL permissions.

The client IP is still recorded for quarantine action/audit attribution.

The Mail Size host helper remains loopback-only because it is a privileged
backend helper, not a user-facing dashboard access control.


## Milestone 5 Security Pack 1 R17 — SpamAssassin Whitelist / Blacklist

A native `Whitelist / Blacklist` tab manages SpamAssassin SQL preferences in
`maildb.userpref`.

Supported preferences:
- `whitelist_auth`
- `whitelist_from`
- `blacklist_from`

Scope storage follows the existing SpamAssassin custom query:
- Global: `username = '@GLOBAL'`
- Domain: `username = '%example.com'`
- User: `username = 'user@example.com'`

The UI supports list/search/filter, add, edit and delete. `prefid` is used as
the immutable row identifier for update/delete.

ACL:
- `Whitelist / Blacklist = View` permits listing/searching.
- `Whitelist / Blacklist = Admin` permits add/edit/delete.
- Dashboard administrators have full access.

Connection settings are read from `.env` and credentials are not embedded in
the application source:

```dotenv
SPAM_PREF_DB_HOST=127.0.0.1
SPAM_PREF_DB_PORT=3306
SPAM_PREF_DB_NAME=maildb
SPAM_PREF_DB_USER=spam
SPAM_PREF_DB_PASSWORD=<set-the-maildb-password>
```

The SQL account needs only `SELECT, INSERT, UPDATE, DELETE` on
`maildb.userpref`.

## Milestone 5 Security Pack 1 R18 — Spam List Bulk Operations

The native `Whitelist / Blacklist` tab now adds production-safe bulk management
on top of the existing SQL-backed SpamAssassin `maildb.userpref` manager.

### Search

Search remains server-side and covers `username`, `preference`, and `value`.
The UI now provides explicit Search and Clear controls; Enter in the search box
also executes the query. Preference and scope filters remain available.

### Bulk Delete

- Per-row checkbox selection
- Select all visible rows
- Selected-item counter
- `Delete Selected` with confirmation
- Maximum 100 entries per bulk request
- Transactional server-side validation/deletion
- `SPAMLIST_BULK_DELETE` audit record

### Bulk Import

Import accepts `.cf` or text files using SpamAssassin-compatible directives:

```text
#### white list format email id is HAM whitout DKIM and SPF PASS
whitelist_from *@squaregroup.com
whitelist_from user@example.com

### DKIM and SPF Pass
whitelist_auth *@example.com
whitelist_auth authenticated@example.com

### blacklist format
blacklist_from *@bad-example.com
blacklist_from bad@example.com
```

Rules:
- accepted directives: `whitelist_from`, `whitelist_auth`, `blacklist_from`
- directive names are case-insensitive
- blank lines and comment lines beginning with `#` are ignored
- domain portions are normalized to lowercase for duplicate detection
- duplicate entries are not inserted
- preview is mandatory before the Import button is enabled
- preview reports Add / Duplicate / Invalid / Skipped counts
- import has no line-count limit; the 2 MB upload-size safety limit remains
- target scope can be Global, Domain, or User; Global is the default
- committed imports create a `SPAMLIST_IMPORT` audit record

### Export

Export uses the currently selected Search / Preference / Scope filters and
produces a reusable `.cf` text file in the same three-section format above.
Export is available with Whitelist / Blacklist View permission and records a
`SPAMLIST_EXPORT` audit event.

The `.cf` directive/value format itself does not encode dashboard scope. When
exporting mixed Global/Domain/User rows, the exported SpamAssassin directives
contain the preference and value only.


## Milestone 5 Security Pack 1 R18.2 — UI refinements

- Mail Size no longer displays the Service Health panel.
- Help keeps the authenticated full-size flowchart viewer but removes dashboard download capability.
- SpamAssassin Whitelist / Blacklist selection checkboxes align with the compact table font.
- Amavis Quarantine search adds an `All fields / From / To` selector before the existing text operator.
- Existing quarantine actions, five-column layout, release safety, ACLs, durable log checkpoint, and Spam List import/export/bulk delete remain unchanged.

## Milestone 5 Security Pack 1 R18.3 — Delivery field filter

The Delivery tab now mirrors the Amavis Quarantine field-aware search with an `All fields / From / To` selector before the existing text operator. `From` searches sender only, `To` searches recipient only, and `All fields` preserves the previous broad search behavior. Delivery TXT export follows the same field selection.

## Milestone 5 Security Pack 1 R18.4 — User Experience Pack

- Filter state is remembered locally per browser for Delivery, Amavis Quarantine, Whitelist / Blacklist and Audit.
- Clear All controls and active-filter counters make filtered views obvious and easy to reset.
- Rows-per-page selectors were added to Delivery, Quarantine, Whitelist / Blacklist and Audit.
- Delivery, Spam List and Audit tables keep their headers visible while scrolling.
- Last-refreshed timestamps are displayed on operational list views.
- Queue ID and sender fields provide one-click copy controls in Delivery.
- Empty result states provide a direct Clear Filters action.
- Enter triggers search in the main searchable views; Escape closes flow/detail modals.
- Help no longer renders the large flowchart inline. A View System Flowchart button opens a responsive modal viewer with Fit / Zoom controls.
- The bundled flowchart asset is 3072×2048 for improved readability when zoomed.
- Existing RBAC, quarantine safety, Mail Size helper, SpamAssassin SQL management and durable log-reader checkpoint behavior are unchanged.

## Milestone 5 Security Pack 1 R18.5 — Operational Safety & Administration Pack

R18.5 adds dependency-aware System Status, non-secret dashboard configuration snapshots, SpamAssassin whitelist/blacklist conflict detection, Mail Size backup visibility, and audit actions for snapshot creation and conflict checks. Configuration snapshots are advisory/version-history records; they deliberately exclude passwords/API keys and do not automatically rewrite host configuration.

R18.5 also fixes the Mail Size helper installer directory ownership so `/etc/postfix-web` is created as `root:www-data` mode `0750`, avoiding the earlier PHP key-read traversal failure while keeping the secret outside the web root.


## Milestone 6 R6 — Dynamic Mail Flow

The Mail Flow Chart is a native HTML/CSS/JavaScript live view. Inbound and outbound paths feed one shared Amavis Quarantine node. Counters and recent final mail records refresh from existing dashboard APIs. No static flowchart image is required.


## Current Build — R6.5 Fix 4

- Single interactive SVG Mail Flow landing page.
- Shared Amavis Quarantine is centered between inbound and outbound flows.
- Existing database-preservation upgrade logic retained.
- Mail Size audit forwards authenticated dashboard username and client IP to the trusted loopback helper.
- Quarantine, Bayes, Release + HAM, Mark Spam, RBAC and security behavior retained.
- Historical root release-note Markdown files have been consolidated/removed to reduce source clutter.

### Milestone 7 approved Mail Flow landing visual
The Mail Flow landing tab now presents the approved INBOUND / COMMON-SHARED / OUTBOUND architecture image at `app/assets/mail-flow-approved-m7.png`. The previous interactive SVG remains in the source as a hidden compatibility runtime so existing live-data bindings and historical regression expectations remain intact. The approved visual is served through the authenticated, Mail-Flow-authorized endpoint `/api/mail-flow/approved-image`, and Full Screen targets the approved visual.

## AI branch: shadow trainer

This branch is derived from the frozen **before AI** baseline. The AI trainer is strictly shadow-only: it cannot change Postfix, Amavis, SpamAssassin, quarantine, release, or delivery decisions. After an administrator successfully performs SpamAssassin `Learn HAM` or `Learn SPAM`, the same explicit human verdict is captured best-effort as a privacy-reduced AI training sample. Raw message body and subject text are not stored in the AI dataset; bounded hashed feature vectors and a source SHA-256 are stored under `QUARANTINE_STATE_DIR/ai-trainer`.

Training creates a candidate model only. Candidate promotion is a separate administrator action, and even an active model remains shadow-only. R1.1.6 benchmarks the legacy multinomial Naive Bayes classifier against a class-balanced sparse logistic-regression classifier on the same deterministic holdout and keeps the better candidate by balanced accuracy, SPAM F1, then plain accuracy. Full confusion-matrix, per-class precision/recall/F1, false-positive rate and false-negative rate are recorded. A minimum number of HAM and SPAM labels is required before candidate training; configure this with `AI_TRAINER_MIN_PER_CLASS`. By default, after 250 additional approved labels beyond the current candidate, a new candidate is trained automatically in the background (`AI_TRAINER_AUTO_TRAIN_AFTER_NEW_LABELS=250`). Automatic training never promotes a candidate and never changes mail flow.

Administrators can use **Sync Existing Labels** in Quarantine Intelligence to import prior successful HAM/SPAM learning decisions into the AI dataset when the corresponding quarantine files are still retained. This reads the existing dashboard learning state and message files only; it does not run `sa-learn` again and does not modify the SpamAssassin Bayes database.

## AI R1.1: Offline GEO-IP + Email Analysis

This branch adds optional offline GEO-IP evidence to Quarantine Intelligence and a manual **Email Analysis** tab. The analysis tool processes pasted/locally-selected RFC822/EML data in memory for a single request and does not persist the supplied message. It does not alter Postfix, Amavis, SpamAssassin, Bayes, quarantine, release, or AI training state.

GEO-IP performs no Internet lookup. To enable country/city and ASN enrichment, place licensed MaxMind GeoLite2/GeoIP2 MMDB files at:

- `data/geoip/GeoLite2-City.mmdb`
- `data/geoip/GeoLite2-ASN.mmdb`

The database files are intentionally not bundled. Without them, the UI reports GEO-IP as unavailable while the rest of Quarantine Intelligence and Email Analysis continues to work.

The Email Analysis tab is governed by the existing Quarantine View permission and displays sender/recipient metadata, SPF/DKIM/DMARC evidence, SpamAssassin score/verdict/top rules, and offline GEO-IP evidence. Default request limit is 10 MiB (`EMAIL_ANALYSIS_MAX_BYTES=10485760`).

### AI R1.1.1: Outlook MSG analysis fix
The Email Analysis tab accepts browser-selected `.eml` and Microsoft Outlook `.msg` files. `.msg` files are decoded with `extract-msg` in a short-lived temporary file, normalized to RFC822 evidence, analyzed, then immediately deleted. Uploading a message does not add it to quarantine, Bayes learning, or the AI training dataset.

## AI R1.1.3 - Native MSG + UI defect corrections
- Outlook `.msg` manual analysis validates the Compound File Binary signature and parses with `extract-msg`.
- Email Analysis exposes message identity, authentication, SpamAssassin evidence, offline GEO-IP, attachments, URLs, and AI shadow output.
- Browser drag/drop supports `.eml` and `.msg`; uploads remain one-time/non-persistent and do not trigger Bayes or AI learning.
- Mail Size keeps the two side-by-side profile cards while stacking status and update controls vertically inside each card.
- Quarantine summary reserves adequate width for Last Updated and wraps responsively instead of compressing text.


### AI R1.1.6 - Trainer v2
- Adds class-balanced sparse logistic regression without an external AI/ML service.
- Benchmarks logistic regression and legacy multinomial Naive Bayes on the same deterministic holdout and selects the stronger candidate.
- Reports balanced accuracy, class precision/recall/F1, false-positive/false-negative rates and confusion matrix in addition to raw accuracy.
- Automatically retrains a candidate after 250 new approved labels by default. The threshold is configurable and automatic retraining never promotes or activates a model.
- Active AI remains SHADOW ONLY and cannot affect Postfix, Amavis, SpamAssassin, Bayes, release or quarantine decisions.

### AI R1.1.7 - Human Correction and Release Verification

- Adds per-message **Correct to HAM / Correct to SPAM** for previously learned quarantine messages. The correction workflow runs SpamAssassin `--forget` before opposite-class learning, keeps the original audit history, records the corrective event, and treats the newest approved AI label as authoritative for future candidate training.
- Correcting a previous manual SPAM decision to HAM clears the dashboard manual-spam flag so the retained quarantine object can be released separately if required. Correction never auto-releases a message.
- Adds persistent release verification metadata in `data/amavis-mgr/release_status.jsonl`. When the Amavis release response contains the new Postfix Queue ID, it is stored and surfaced under **Release Status**.
- Release Status follows the captured Queue ID through the existing Postfix delivery database and reports QUEUE_ACCEPTED/QUEUED/DELIVERED/DEFERRED/BOUNCED/etc. A release with no capturable Queue ID is explicitly shown as unverified rather than being treated as proof of final delivery.
- Fixes Quarantine Intelligence Bayes identity resolution to read the production `bayes_vars` identity directly. The misleading RFC Message-ID lookup against SpamAssassin `@sa_generated` `bayes_seen` IDs is removed from the UI; per-message evidence comes from Dashboard Learning History instead.


### AI R1.1.14 — R1.1.11 Baseline + Animated Flow + Amavis Log Access

This release branches from the authoritative `m7-enterprise-ai-r1.1.11-r117-rebase-stability` baseline. It retains the BANNED (amber) and VIRUS (red) quarantine row distinction, makes the existing baseline SVG Mail Flow the primary animated view using CSS-only moving connectors, and leaves the approved static flow image available as a collapsible reference. Animation is presentation-only and does not alter Postfix/Amavis/SpamAssassin behavior.

Amavis Log Intelligence continues to read the production host log `/var/lib/amavis/logs/amavis.log` through a read-only bind mount. For a host file owned `amavis:adm` with mode `0640`, the app receives the host `adm` GID using `AMAVIS_LOG_GID` (default `4`, verify with `getent group adm`). The existing quarantine group `AMAVIS_GID` remains separate. The application now reports log permission failure explicitly instead of presenting it as a simple evidence miss. The rejected historical global W/B module remains absent from the application and package.


## R1.1.18 Fix4 — AI hard-HAM features and Monitor simplification

The shadow-only AI trainer uses independent local evidence from message text/NLP phrase families, SPF/DKIM/DMARC results and alignment, From/Reply-To/Return-Path/DKIM relationships, sender/header anomalies, URL/domain structure, and MIME/attachment metadata. SpamAssassin scores/rules/verdicts and Amavis verdict/quarantine state are not inference features. Sandboxing and external network lookups are explicitly excluded. Human Learn HAM / Learn SPAM corrections remain the authoritative labels; suspicious-looking messages explicitly corrected to HAM can receive bounded extra training weight through `AI_TRAINER_HARD_HAM_WEIGHT` (default 1.75). AI remains SHADOW ONLY.

The Monitor page now exposes POP3 and Webmail only. New IMAP login events are ignored because routine IMAP refresh/login activity is noisy. Existing IMAP rows already present in MariaDB are not deleted or modified. No database reset or destructive migration is introduced.


## R1.1.18 Fix6 — Reserved future Amavis AI hook

The AI and SpamAssassin/Amavis paths remain fully independent in this release. A future-integration contract is reserved through `AI_AMAVIS_HOOK_MODE=disabled` and `AI_AMAVIS_HOOK_ENDPOINT=/api/ai/amavis-hook/v1`. The current release hard-reports the hook as disabled and not decision-capable; changing the environment value cannot make AI authoritative or feed Amavis/SpamAssassin results back into AI features. This reserve exists only so a later explicitly approved release can connect Amavis to the independent AI verdict without redesigning the trainer feature pipeline.

Current safety boundaries:
- AI remains SHADOW ONLY.
- SpamAssassin/Amavis results remain comparison/audit evidence only.
- Human HAM/SPAM verdicts remain authoritative training labels.
- No current Amavis delivery decision waits for AI.
- No AI prediction can release, quarantine, reject, or accept mail.



## R1.1.19 Experimental Independent AI Intelligence

This build retires the Dashboard Backup / Restore and Fail2Ban/Security Blocks tabs and their dedicated host helpers. It does not uninstall or alter host Fail2Ban. The Mail Size configuration backup mechanism remains separate and unchanged.

Independent AI feature schema 4 adds local, privacy-reduced contextual phrase families, financial/secrecy/callback/UCE indicators, structural stylometric buckets, and visible-link-versus-href mismatch detection. It performs no live URL browsing, no redirect following, no landing-page execution, no computer vision, and uses no SpamAssassin/Amavis verdicts, scores, rules, or Bayes signals as AI features.

## R1.1.20 Clean-Generation Isolation Correction

This correction fixes AI Shadow Intelligence status leakage after the independent clean start.

- Adds explicit AI generation identity (`independent-g1`, configurable with `AI_TRAINER_GENERATION`).
- New admin ground-truth rows and newly trained models carry `generation_id`.
- Persisted pre-generation active/candidate model files remain preserved as historical evidence but are excluded from the current status, prediction and promotion paths.
- Current AI status reports Active model = None and Candidate model = None until a current-generation model actually exists.
- Legacy candidate metrics are no longer displayed as current-generation accuracy/validation results.
- Clean-generation training no longer migrates legacy feature rows into the current dataset.
- Auto-train remaining-label calculation is scoped to the current generation; e.g. 3 eligible labels reports 247 remaining when the threshold is 250.
- Dashboard shows the current AI generation and uses N/A/Not trained for unavailable candidate metrics.
- Production safety remains unchanged: SHADOW ONLY, no Postfix/Amavis delivery dependency, and no destructive MariaDB operation.

## R1.1.21 Live AI Status Feed

- AI Shadow Intelligence now separates **Current Data** and **Metrics** into live panels.
- While Quarantine Intelligence is open, `/api/ai-trainer/status` is refreshed every 10 seconds using the existing authenticated `quarantine:view` permission boundary.
- Current generation, active/candidate model, label counts, Hard-HAM count/weight, schema, auto-train countdown, candidate algorithm and validation metrics update without reopening the modal.
- Backfill, candidate training and promotion trigger an immediate refresh after the operation completes.
- Polling stops when the modal closes and never changes Postfix, Amavis, SpamAssassin or quarantine behavior.
- No destructive database change is introduced.

## R1.1.22 consolidated change release
- Adds dedicated AI Trainer Flow and AI Intelligence Layout tabs with authenticated 10-second live trainer state.
- Adds persistent Released count to Amavis Quarantine Management from MariaDB dashboard audit evidence. Released is not treated as Delivered.
- [SUPERSEDED R1.1.25] The log-derived Home-Domain Email ID MIS was removed because Postfix log address strings are not an authoritative mailbox directory.
- Corrects Mail Size API audit identity: trusted proxy forwarding is honored only when the immediate peer is listed in `TRUSTED_PROXY_IPS`; direct clients retain their socket IP.
- Bundles pinned Node.js 24.20.0 inside the dashboard Docker image using a multi-stage image; no host Node.js dependency.
- Existing populated MariaDB remains upgrade-only and is never recreated or reset by this release.

## R1.1.23 Mail Direction MIS correction
- [SUPERSEDED R1.1.25] Home-Domain Email ID MIS removed from the Summary UI and API surface.
- Sent and Received counts are drill-down links to underlying final-delivery records within the active date range.
- Conservative address normalization suppresses malformed log tokens and unknown-recipient/bounced-only artefacts from the MIS.
- Compose uses the stable application image name `postfix-delivery-dashboard:m7`.
- Existing MariaDB remains upgrade-only; this change adds no destructive database operation.

## R1.1.24 Graphical AI + Live Feed + MIS correction
- Converts AI Trainer Flow from a text/card sequence to a graphical 7-stage pipeline with arrows and embedded live state for generation, schema, labels, active model, candidate and validation state.
- Converts AI Intelligence Layout into a graphical Message AI / Infrastructure AI / Campaign AI evidence map feeding an explicit SHADOW VERDICT and NO MAIL ACTION safety boundary.
- Corrects the AI architecture live-feed endpoint to the existing authenticated `/api/ai-trainer/status` route, fixing the `Live intelligence feed unavailable` defect caused by the stale `/api/ai/trainer/status` path.
- Retains 10-second authenticated live refresh and SHADOW ONLY behavior.
- [SUPERSEDED R1.1.25] Removed the Home-Domain Email ID MIS and its address drill-down to eliminate non-authoritative/fake log-derived identities.
- Improves Quarantine Intelligence live-panel wrapping for long schema/status values.
- Stable compose image remains `postfix-delivery-dashboard:m7`; Node.js remains pinned inside Docker.
- No destructive MariaDB operation is introduced.


## R1.1.25 Final Daily Consistency Audit

- Removes Home-Domain Email ID MIS from Mail Direction Summary, including its API, drill-down modal, JavaScript and DB query helpers.
- Keeps Mail Direction Summary totals and Daily Bounced Domain Summary.
- Daily Bounced Domain Summary now follows the approved compact report pattern: bounded to 760px, flexible Domain column, narrow right-aligned Sent/Recv/Total columns, and clickable Sent/Recv count drill-down.
- Released quarantine KPI is explicitly count-only/non-interactive. Release remains distinct from final delivery verification.
- Preserves graphical AI Trainer/Intelligence live feed and the authenticated `/api/ai-trainer/status` endpoint.
- Preserves stable compose image `postfix-delivery-dashboard:m7` and Node.js 24.20.0 from the official Docker node image stage.
- No destructive MariaDB initialization/reset is introduced.

## R1.1.34 — phishing_pot selective research-corpus integration

Adds an offline curator for the public `rf-peixoto/phishing_pot/email` corpus. The upstream repository describes the emails as real phishing samples collected through honeypots. This build deliberately **does not bundle or mass-import the raw corpus**. The source manifest records CC BY-NC 4.0 and keeps all imported candidates `EXTERNAL_RESEARCH`, `training_authority=false`, and outside Set-2 Mail Admin Ground Truth.

Use `tools/curate-phishing-pot.py /path/to/phishing_pot/email --limit 500` on a separately obtained local copy to deduplicate candidate `.eml` messages by normalized body hash and emit privacy-reduced research records for human curation. No network access is performed by the dashboard or curator.

Fraud Intelligence Repository seed advances to `fraud-intel-2026.09.03-v2` and adds generalized credential-phishing, BEC payment-redirection, invoice-fraud, and callback-phishing phrase families. Existing MariaDB is upgraded idempotently by the existing repository seeder; no database recreation is permitted.

## R1.1.52 — Clean Training Provenance + Provider-Aware Hop Intelligence

- AI candidate fitting and auto-train eligibility are restricted to explicit authoritative Mail Admin Ground Truth for the current independent generation/schema.
- Historical `sa-learn`, Bayes/learning-correction, legacy-feature and superseded rows remain preserved for audit but are excluded from clean Set-2 candidate fitting.
- SpamAssassin Learn HAM / Learn SPAM actions no longer silently create AI training labels.
- Infrastructure AI adds provider-aware trusted-hop context for Google Workspace, Microsoft 365 and other observed routes. MX/provider/authentication evidence is contextual only and never independently implies HAM or SPAM.
- Missing SPF/DKIM/DMARC/DNS evidence remains UNKNOWN rather than negative evidence.
- Feature schema v4, seven independent feature families, Hard-HAM weight 1.75 and SHADOW ONLY behavior remain unchanged.

## R1.1.53 — Semantic Impersonation & Action-Intent Intelligence

R1.1.53 keeps schema v4, the seven independent feature families, Hard-HAM weight 1.75, SHADOW ONLY operation, and the R1.1.52 clean-training-provenance boundary. Message AI adds relationship-derived features for recipient-domain mail-service impersonation, delivery/release lures, credential-action language, and action URLs external to both sender and recipient domains. A high-confidence semantic overlay requires multiple independent relationships and can only raise a shadow SPAM/CREDENTIAL_PHISHING proposal; it never changes Postfix/Amavis/SpamAssassin behavior and never creates Ground Truth. The underlying learned-model verdict/confidence is preserved alongside the overlay for calibration and audit.

