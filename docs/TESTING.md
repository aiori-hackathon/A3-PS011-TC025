# Testing

## Strategy

Run the standard-library `unittest` suite from the repository root:

```powershell
python -m unittest discover -s tests -v
```

Tests use temporary SQLite files and mocked DNS/TLS behavior. TCP tests are
restricted to loopback, including a temporary local server on port 8000; tests
do not contact external systems. Run `python -m py_compile` on modified modules
when changing scanner/orchestration code.

## Coverage and expected outcomes

| Area | Expected result |
|---|---|
| Database schema, persistence, and foreign keys | Records survive re-query; invalid foreign keys are rejected |
| Baseline lifecycle | First fully completed scan may establish a baseline; incomplete or subsequent scans cannot replace it implicitly |
| DNS outcomes | A, AAAA, and CNAME outcomes are independent; timeouts/errors are not removals |
| DNS set comparison | Added/removed values are detected with order ignored |
| TLS | Expiry and certificate identity changes produce evidence-backed findings |
| Ports | Only configured ports are stored; open/refused/timeout/error states are distinguished; timeout is never a closed state |
| CNAME review | Out-of-scope target yields `REVIEW_REQUIRED`, not a confirmed dangling claim |
| Finding review | False-positive decision and note remain in append-only review history |
| Incomplete scan | No baseline replacement or finding resolution; inconclusive observations do not create state-change findings |
| Scope validation | Invalid hosts/ports and empty scope are rejected before a scan starts |

## Reproducible seeded scenarios

`tests/test_findings.py` builds synthetic observations inside a temporary
database, so it is safe to run on a developer machine:

```powershell
python -m unittest tests.test_findings -v
```

The test fixtures cover DNS `192.0.2.10` to `192.0.2.20`, an expired mocked
certificate, fingerprint/serial change, a closed-to-open unexpected allowed
port, a port timeout, an unconfigured CNAME target, false-positive review, and
a failed scan. `192.0.2.0/24` is reserved for documentation and is not contacted.

## Dashboard and PDF smoke checks

Check import/startup without triggering a scan:

```powershell
python -c "import dashboard"
```

Generate a PDF from the current local database:

```powershell
python -c "from reports.report_generator import generate_pdf_report; data = generate_pdf_report(); assert data.startswith(b'%PDF-')"
```

The PDF report test suite validates the file signature and non-empty output
without requiring a network scan.
