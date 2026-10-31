# Architecture

## Components and boundaries

- `scanner.scope` reads the approved configuration, normalizes hostnames, and
  validates individual port numbers and the expected-port subset.
- `scanner.dns_checker` queries A, AAAA, and CNAME separately.
- `scanner.tls_checker` uses Python's default trust store and hostname
  verification; it captures available certificate identity and expiry fields.
- `scanner.port_checker` opens a TCP connection only to ports provided by the
  validated scope. It distinguishes `OPEN`, `CLOSED`, `FILTERED_OR_NO_RESPONSE`,
  and `ERROR`, and records timing and error details.
- `monitor.scan_manager` owns scan creation, scanner invocation, persistence,
  completion checks, baseline creation, and comparison dispatch.
- `monitor.change_detector` compares normalized observations to the active
  baseline. It does not interpret timeouts or failed scans as removals.
- `monitor.baseline` provides guarded initial creation and explicit replacement.
- `monitor.scheduler` provides one process-local APScheduler instance with
  overlapping runs disabled.
- `database.db` centralizes SQLite schema, transactions, and query operations.
- `dashboard.py` reads persisted state and exposes manual scan, review, baseline,
  history, and report workflows.
- `reports.report_generator` generates a PDF from the persisted inventory and
  scan evidence.

## Data flow and scan lifecycle

1. Validate `config.json` before creating a scan or performing a network check.
2. Synchronize current configured assets as authorized while preserving
   historical asset rows.
3. Create a `running` scan with UTC timestamps.
4. Query configured DNS names, inspect TLS only for configured hosts with
   allowed port 443, and check every explicitly allowed TCP port.
5. Persist each result as an observation and each scanner/asset outcome as a
   status. A missing record, refused port, timeout, TLS trust error, and scanner
   exception remain distinct.
6. Continue independent scanners and assets after an individual check fails.
   Record the overall scan as `completed`, `completed_with_warnings`,
   `inconclusive`, or `failed`, based on required check outcomes.
7. Only a fully `completed` scan can become the initial baseline; it never
   replaces an existing baseline implicitly.
8. Compare only eligible current observations with the active baseline and
   persist supported findings. Partial scans never resolve older findings;
   complete scans reconcile findings while retaining review history.

## SQLite schema

All tables are in `database/attack_surface.db`. Foreign keys are enabled for
each connection, queries are parameterized, and database mutations use
transactions.

- `assets`: `id`, `asset_type`, `asset_value`, `is_authorized`, `created_at`.
- `scans`: `id`, scan timestamp/status, start/completion timestamps, error, and
  source (`manual`, `scheduled`, or `cli`).
- `scanner_statuses`: per-scan, per-asset scanner outcome and diagnostic message.
- `observations`: scan and asset foreign keys, scanner/observation type,
  normalized value, JSON metadata, observation timestamp.
- `baselines`: completed scan foreign key, name, created timestamp, active bit.
  A partial unique index permits one active baseline.
- `findings`: stable fingerprint, first and last-seen scan, asset, category,
  before/after, severity, evidence, description, recommendation, review status,
  and active bit.
- `finding_reviews`: append-only status, note, and timestamp for each review or
  automatic resolution decision.

The older `database/monitor.db` schema remains available through legacy helper
functions but is not the normalized dashboard data source.

## Change detection

DNS sets are normalized (IP address canonicalization and lowercased CNAME
targets) so ordering and formatting differences do not create alerts. DNS
comparison requires usable DNS outcomes. TLS compares serial, SHA-256
fingerprint, issuer, and expiry, while also checking current expiry and
certificate-validation errors. Port changes compare only persisted states for
ports explicitly authorized in the applicable scan. Timeout/error states are
inconclusive. CNAME pointers outside the configured scope generate a
low-severity `REVIEW_REQUIRED` lead; no external target check or ownership
claim is made.

## Scheduler

Scheduling is disabled unless `scheduled_scans_enabled` is true in
`config.json`. Streamlit caches the process-level scheduler handle, and the
job allows one active instance with coalescing. The scheduler stops with the
dashboard process; it is not a persistent service.
