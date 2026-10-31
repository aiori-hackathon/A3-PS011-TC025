# User guide

## Install

From the project root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -c "from database.db import initialize_database; initialize_database()"
```

## Configure scope

Edit `config.json` with domains and hostnames you are explicitly authorized to
monitor. Domains receive A/AAAA/CNAME checks. A host receives TCP checks only
on its `allowed_ports`. `expected_ports` must be a subset of `allowed_ports`;
open allowed ports outside the expected set are reported for review. TLS is
checked only if port 443 is explicitly allowed. TCP connection attempts use
`connection_timeout_seconds` (3 seconds by default).

`expected_ports` documents ports expected to be available;
`allowed_ports` is the authorization boundary for checks and may include other
ports.

Scheduling is opt-in. Set `scheduled_scans_enabled` to `true` and choose a
positive `scan_interval_minutes` to schedule scans while the dashboard process
is running.

## Run and inspect scans

Start the dashboard:

```powershell
streamlit run dashboard.py
```

Use **Run full scan** to initiate a scan. The latest overall status and
per-scanner statuses, timestamps, DNS outcomes, certificate information, and
per-port state appear in their respective sections. A port timeout is displayed
as inconclusive, with a reminder that no response is not proof the port is
closed. Select an earlier scan in **Inspect scan** to see its observations.
Incomplete scan observations and errors are retained; they do not replace the
baseline or resolve earlier findings.

Run one scan from a terminal instead:

```powershell
python app.py
```

The standalone DNS scanner is also available:

```powershell
python scanner\dns_checker.py
```

## Baselines and changes

The first fully completed scan becomes the baseline. Later scans do not
replace it. To change it, select a completed scan in **Baseline controls**, check
the confirmation box, and select **Replace active baseline**. This changes the
comparison reference and should be done intentionally.

Findings list category, severity, evidence, recommended action, and review
status. Potential CNAME concerns are labeled `REVIEW_REQUIRED` and are not
verified outside the approved scope. In the finding details, select
`CONFIRMED`, `FALSE_POSITIVE`, or `RESOLVED`, optionally add a note, and save.
The history remains viewable even after a finding is marked false positive.

## Generate reports

Click **Generate PDF report**, then **Download PDF report**. To save a report
directly from PowerShell:

```powershell
python -c "from reports.report_generator import generate_pdf_report; generate_pdf_report('reports/attack_surface_report.pdf')"
```

The report includes the current persisted inventory, latest successful scan,
baseline, review states, and limitations.

## Responsible-use limits

Only configure owned or explicitly authorized assets. Do not add broad IP
ranges, unapproved ports, or third-party assets. The application does not
exploit services, brute-force credentials, or automatically claim a CNAME is
vulnerable.
