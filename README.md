# Authorized Attack-Surface Inventory and Change Monitor

PS-011 is a defensive monitoring tool for inventorying explicitly authorized
domains and hosts, observing DNS/TLS/selected TCP-port state, and reviewing
changes between scans.

Project video: [Hackathon demonstration](https://youtu.be/CFCZ6hMw4Uk?si=5bE_guE9KVD_HHvu)

## Problem and proposed solution

Internet-facing DNS records, certificates, and services change over time.
Without an inventory and history, an owner may miss an expired certificate,
unexpected service, or an unexplained configuration change. This project
provides a small, local-first monitor that checks only configured targets,
persists observations in SQLite, compares complete scans to an explicit
baseline, and presents evidence and review status in a Streamlit dashboard.
Changes are signals for review; they are not automatically asserted to be
vulnerabilities.

## Features

- Validated authorized domains and hostnames from `config.json`.
- Independent A, AAAA, and CNAME queries with explicit DNS outcomes.
- TLS inspection using the platform trust store; certificate verification is
  never disabled.
- TCP connection checks only for individual `allowed_ports` in the config.
- SQLite scan history, normalized observations, a preserved baseline, findings,
  and auditable finding-review history.
- DNS record, TLS certificate/expiry, port-state, and cautious potential CNAME
  findings.
- False-positive, confirmed, and resolved review decisions with notes.
- Optional process-local APScheduler interval scans.
- Streamlit inventory, scan, findings, history, and PDF-report views.
- Mock-based tests for seeded change scenarios; tests make no external network
  requests.

## Architecture

`scanner/` validates scope and performs DNS, TLS, and explicit-port checks.
`monitor/scan_manager.py` owns full-scan lifecycle and persistence.
`monitor/change_detector.py` compares usable observations to the active
baseline. `database/db.py` stores inventory, scans, observations, baselines,
findings, and review decisions in `database/attack_surface.db`.
`dashboard.py` reads that store and calls the central scan manager.
`reports/report_generator.py` renders a PDF from persisted data.

The legacy `database/monitor.db` helpers remain available for compatibility;
the current dashboard and normalized scan workflow use `attack_surface.db`.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the schema and data flow.

## Technology

- Python 3.10+
- dnspython
- SQLite (Python standard library)
- Streamlit
- APScheduler 3
- ReportLab

## Project structure

```text
app.py                       CLI entry point and compatibility helpers
config.json                  Explicit monitoring scope and schedule settings
dashboard.py                 Streamlit dashboard
database/db.py               SQLite schema and persistence operations
monitor/baseline.py          Baseline lifecycle
monitor/change_detector.py   Normalized change and finding detection
monitor/scan_manager.py      Authorized full-scan orchestration
monitor/scheduler.py         Optional process-local scheduler
reports/report_generator.py  PDF report generation
scanner/dns_checker.py       A/AAAA/CNAME checks
scanner/port_checker.py      Explicit TCP port checks
scanner/scope.py             Target and configuration validation
scanner/tls_checker.py       Verified TLS certificate inspection
tests/                       Offline unittest suite
docs/                        Architecture, test, user, demo, and checklist docs
```

## Installation

From the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Initialize the normalized database:

```powershell
python -c "from database.db import initialize_database; initialize_database()"
```

## Deploy on Render

The included [render.yaml](render.yaml) defines a Python web service that runs
the Streamlit dashboard on Render's `$PORT` and mounts a persistent disk at
`/var/data` for both SQLite databases. The persistent disk requires a paid
Render instance plan. For an existing Render service, use:

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `streamlit run dashboard.py --server.address 0.0.0.0 --server.port $PORT --server.headless true`
- **Environment:** `ATTACK_SURFACE_DB_PATH=/var/data/attack_surface.db` and
  `ATTACK_SURFACE_LEGACY_DB_PATH=/var/data/monitor.db`

The dashboard is a Streamlit application, not a Flask WSGI application, so
Gunicorn is not its start command. `app.py` is the command-line scanner entry
point; `dashboard.py` is the Render web entry point. Back up the mounted disk
before redeploying or changing its mount path.

## Configuration and authorized scope

Edit `config.json` before running scans. `domains` contains DNS names to query.
`hosts` contains targets for explicit TCP checks. An entry's `allowed_ports`
is the complete set of ports that may be checked; `expected_ports` must be a
subset and defines which open services are expected. If `allowed_ports` is
omitted, the configured `expected_ports` (or legacy `ports`) list is also the
scan allowlist.

```json
{
  "domains": ["owned.example"],
  "hosts": [
    {
      "hostname": "service.owned.example",
      "expected_ports": [443],
      "allowed_ports": [443, 8443]
    }
  ],
  "connection_timeout_seconds": 3.0,
  "scan_interval_minutes": 60,
  "scheduled_scans_enabled": false
}
```

The example above is illustrative. Replace it with domains/hosts you are
authorized to monitor. A port can only be observed if it is explicitly
allowlisted; the application does not discover arbitrary IPs, scan networks,
or infer permission from a DNS result. Configuration validation occurs before
network requests. A syntactically valid name is not proof of authorization.

## Run scanners and full scan

Run the standalone DNS report:

```powershell
python scanner\dns_checker.py
```

TLS and port scanners are called by the central workflow, which enforces the
configured scope. Run a full scan:

```powershell
python app.py
```

Or launch the dashboard and use **Run full scan**:

```powershell
streamlit run dashboard.py
```

Only a fully completed scan can create the initial baseline. Later scans retain
their observations without replacing it. Baseline replacement is available in
the dashboard and requires an explicit confirmation checkbox, or can be called
programmatically with `monitor.baseline.replace_baseline(scan_id)`.

Each TCP check records its hostname, port, protocol, state, timestamp, response
time, and any error. A timeout is `FILTERED_OR_NO_RESPONSE`, not evidence that
the port is closed. Configure its connection limit with
`connection_timeout_seconds` (3 seconds by default). DNS, TLS, and port checks
continue independently; scan history shows `inconclusive`,
`completed_with_warnings`, or `failed` when warranted, along with per-scanner
statuses. Only fully completed scans can become baselines. Partial scans may
report changes supported by valid observations, but do not replace baselines
or resolve findings.

## Change detection and findings

Complete observations are compared with the active baseline. DNS values are
normalized and order is ignored. The monitor reports additions/removals,
certificate identity changes, expiry, and port-state changes. A port timeout is
not a closed-port observation. DNS timeout and resolver errors are not removals.
Potential CNAME risks are low-severity, review-required leads: targets outside
the allowlisted scope are not probed, claimed as confirmed dangling, or
registered.

Severity rules are intentionally bounded: record and identity changes are
informational/low or medium review signals; a certificate expiring within 30
days is medium (high within 7 days); an expired certificate is high; an
unexpected explicitly probed open port is medium. No automatic critical
severity or exploitability claim is inferred. Finding review decisions and
notes remain in the database history.

## Scheduled monitoring

Set `scheduled_scans_enabled` to `true` and configure
`scan_interval_minutes`. The dashboard starts a single in-process scheduler
instance with one concurrent scan maximum. Scheduled scans run only while the
dashboard process is active. Set the flag to `false` to disable scheduling.
Manual scanning remains available independently. Scan history records whether
each scan was manual, scheduled, or run from the command line.

## PDF reports

The dashboard's **Generate PDF report** button builds a downloadable PDF.
Generate one from the command line:

```powershell
python -c "from reports.report_generator import generate_pdf_report; generate_pdf_report('reports/attack_surface_report.pdf')"
```

Reports distinguish observed evidence from potential issues and include scope,
scan, baseline, findings, review states, and limitations. They do not label
every detected change as a vulnerability.

## Tests and seeded scenarios

Run all tests without live network access:

```powershell
python -m unittest discover -s tests -v
```

## Day 3: TLS Certificate Monitoring
The TLS checker validates DNS names from the `domains` array and hosts from the
`hosts`/`targets` scope in `config.json`. A configured domain is checked on port
443; a configured host is checked only on a port explicitly listed in its
`allowed_ports`. A host passed directly to `check_tls` is checked against that
same scope before any connection is made. Connections use Python's default
certificate trust and hostname verification, and SNI. Verification is never
disabled.

Run it from the project root:

```powershell
python scanner/tls_checker.py
```

The JSON report is printed and saved to `reports/tls_report.json`. Each result includes the hostname, port, UTC scan timestamp, certificate expiry timestamp and days remaining when available, expired and soon-to-expire flags, a status, and separate connection or verification error details. Statuses distinguish valid, soon-to-expire, expired, hostname mismatch, untrusted certificate, timeout, and other TLS or connection failures. If a TLS handshake fails verification, expiry information may be unavailable because the certificate is not accepted for inspection.

The soon-to-expire threshold defaults to 30 days. It can be changed by adding an integer `tls_warning_days` setting to `config.json`, for example `"tls_warning_days": 45`. The TLS checks use only the Python standard library, so no additional dependency is required.

Run only the mocked TLS tests with:

```powershell
python -m unittest discover -s tests -p test_tls_checker.py -v
```

Run the unit tests without relying on live DNS:

```powershell
python -m unittest discover -s tests -v
```

The finding tests use temporary SQLite databases and synthetic DNS, TLS, and
port observations for DNS address change, expired/changed certificates,
unexpected-open and changed ports, potential CNAME review, false-positive
handling, and scan failure. See [docs/TESTING.md](docs/TESTING.md).

## Known limitations and future work

- The tool is a scoped inventory/change monitor, not a vulnerability scanner.
- TLS data depends on successful verified connections and certificate fields
  exposed by Python's TLS implementation.
- CNAME targets outside approved scope are not resolved; ownership is not
  verified automatically.
- Scheduling is process-local and does not persist while the application is
  stopped.
- The dashboard is intended for local/operator use and does not implement
  authentication or multi-user authorization.
- Future improvements may include authenticated access, richer trend charts,
  managed retention/export, and opt-in owner-approved external CNAME validation.

## Documentation and submission

- [Architecture](docs/ARCHITECTURE.md)
- [Testing guide](docs/TESTING.md)
- [User guide](docs/USER_GUIDE.md)
- [Five-minute demo script](docs/DEMO_SCRIPT.md)
- [Deliverable checklist and screenshot checklist](docs/DELIVERABLE_CHECKLIST.md)

## Safety and responsible use

Use the application only for assets you are explicitly authorized to monitor.
It performs only DNS lookups, verified TLS handshakes, and individual TCP
connection checks against configured hosts and ports. It does not exploit,
brute-force, discover network ranges, or test unconfigured ports.
python -m unittest discover -s tests
```

## Day 4: Port Monitoring
Port monitoring uses only the `hosts` entries in `config.json`. Each host must explicitly provide `expected_ports` and `allowed_ports` as lists of individual integer port numbers from 1 to 65535. Expected ports must also be in the allowed list. Do not configure ranges. For example:

```json
{
   "hosts": [
      {
         "hostname": "127.0.0.1",
         "expected_ports": [8000],
         "allowed_ports": [8000, 8080]
      }
   ]
}
```

Run the checker from the project root:

```powershell
python scanner/port_checker.py
```

The report is printed and saved to `reports/port_report.json`. It records the host, TCP port, UTC scan time, expected and observed state, comparison result, any errors, safe service-identification evidence, and review findings.

The checker performs four distinct checks:

1. **TCP connectivity:** a successful connection is `OPEN`; this proves only that a TCP connection was accepted at that time, not which application is running or whether it is vulnerable.
2. **Expected-state comparison:** configured `expected_ports` are expected to be `OPEN`; other explicitly allowed ports are expected to be `CLOSED`. A refused TCP connection is reported as `CONNECTION_FAILED`. `TIMEOUT` is inconclusive, not closed.
3. **Unexpected-open detection:** an open allowed port absent from `expected_ports` is recorded as a review finding with evidence and a suggested next action. It is not automatically classified as a vulnerability.
4. **Safe service identification:** on conventional web ports in the approved list, the checker sends a minimal HTTP `HEAD /` request. It does not send exploit payloads. Other ports are not protocol-probed; the TCP result alone does not identify their service.

Statuses are `OPEN`, `CONNECTION_FAILED`, `TIMEOUT`, and `ERROR`. `ERROR` indicates another issue, such as invalid scope or a local/network socket error. A scan does not infer a closed state from a timeout, and transient firewall or network behavior can produce false positives or inconclusive results. Only the configured host and port allowlists are scanned; direct helper calls are also checked against that configuration. These checks do not replace service-owner review or a full security assessment.

Run only the mocked and loopback-only port tests with:

```powershell
python -m unittest discover -s tests -p test_port_checker.py -v
```

## Safety
Only run checks against assets explicitly authorised
for this project.
