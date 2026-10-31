# Five-minute demo script

## 0:00–0:45 — Problem and safety boundary

Introduce PS-011: authorized asset changes are easy to miss. Show
`config.json` and explain that DNS names and exact TCP ports are explicitly
listed; no network discovery or exploit checks are performed.

## 0:45–1:30 — Inventory and baseline

Launch with `streamlit run dashboard.py`. Show the overview and authorized
inventory. If an authorized test scope has already been scanned, show its
baseline timestamp and scan history. Do not start a scan against an asset
without confirming authorization.

## 1:30–2:15 — Manual scan and observations

Click **Run full scan** only for configured authorized assets. Show DNS result
status, certificate fields when port 443 is allowlisted, and actual state for
each explicitly allowed port. Explain that timeouts are inconclusive.

## 2:15–3:20 — Seeded change scenarios

Show the automated offline fixtures with:

```powershell
python -m unittest tests.test_findings -v
```

Describe the deterministic cases: reserved documentation IP change,
certificate expiry/fingerprint replacement, allowed-port state change,
review-required CNAME lead, false-positive history, and failed scan. These
scenarios are mocked in a temporary database and do not touch production
systems.

## 3:20–4:15 — Review workflow

If a finding exists in the local database, expand it, inspect evidence and
recommended action, then record a review note and select a decision. Show that
the decision remains in the history. Do not mark an unverified finding
confirmed for the demo.

## 4:15–5:00 — Report and close

Generate and download a PDF. Summarize that it distinguishes observations,
potential issues, and review status and records scope and limitations.

## Presenter note

The repository does not include fabricated screenshots or pre-seeded
production findings. If the demo database is empty, rely on the tests for
change examples and present the dashboard's truthful empty states.
