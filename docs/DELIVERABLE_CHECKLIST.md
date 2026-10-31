# Deliverable checklist

Status reflects repository implementation and tests; it does not claim that a
live authorized scan or screenshot was produced.

| Capability | Status | Evidence |
|---|---|---|
| DNS A/AAAA/CNAME scanner | Completed | `scanner/dns_checker.py`, offline unit tests |
| Verified TLS inspection | Completed | `scanner/tls_checker.py`, compilation and certificate mock tests |
| Explicit TCP port checks | Completed | `scanner/port_checker.py`, state tests |
| Configured scope validation | Completed | `scanner/scope.py`, scope tests |
| SQLite scan/observation history | Completed | `database/db.py`, database tests |
| Initial and explicit baseline lifecycle | Completed | `monitor/baseline.py`, scan tests |
| DNS/TLS/port finding detection | Completed | `monitor/change_detector.py`, finding tests |
| False-positive/review history | Completed | Finding review tables and tests |
| Failure-safe comparison | Completed | Incomplete scans are failed and not compared |
| Streamlit dashboard | Completed | `dashboard.py`; import smoke check |
| Optional scheduled scans | Completed | `monitor/scheduler.py`; disabled by default |
| PDF generation/download | Completed | `reports/report_generator.py`; PDF test |
| Automated offline seeded cases | Completed | `tests/test_findings.py` |
| README and supporting docs | Completed | README plus architecture, testing, user, and demo guides |
| Live authorized production scan | Pending | Must be run by an authorized operator |
| Final report based on a real scan | Pending | Generate after an authorized scan |
| Screenshots | Pending | No screenshots are fabricated or currently included |
| Dashboard authentication/multi-user controls | Partial | Local operator dashboard only |

## Verification commands

```powershell
python -m unittest discover -s tests -v
python -c "import dashboard"
python -c "from reports.report_generator import generate_pdf_report; data = generate_pdf_report(); assert data.startswith(b'%PDF-')"
```

## Screenshot checklist

Capture these from an actual local run if screenshots are required for
submission. Do not populate them with synthetic data or report that they exist
until captured:

- [ ] Dashboard overview
- [ ] Authorized asset inventory
- [ ] DNS results
- [ ] TLS results
- [ ] Port results
- [ ] Active baseline
- [ ] Detected changes
- [ ] Findings and review decision
- [ ] Scan history
- [ ] Generated/downloadable PDF report
