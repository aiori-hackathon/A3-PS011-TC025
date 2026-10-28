
# Authorised Attack-Surface Inventory and Change Monitor

## Problem Statement
PS-011: Authorised Attack-Surface Inventory and Change Monitor.

## Objective
Build a monitoring tool that inventories approved digital assets,
checks DNS records, TLS certificates and selected service ports,
and detects changes between scans.

## Technology Stack
- Python
- dnspython
- Flask
- Streamlit
- SQLite
- APScheduler

## Current Progress
- Project structure created
- Python environment configured
- Approved-target configuration created
- Configuration loader implemented

## Run Locally
1. Create and activate a Python virtual environment.
2. Install dependencies using:
   pip install -r requirements.txt
3. Run:
   python app.py

## Day 2: DNS Discovery
The DNS discovery module reads authorized domain names from the `domains` array in `config.json`. It queries A (IPv4), AAAA (IPv6), and CNAME records independently, and records each query's status, answers, and any error details. A failed lookup or missing record is not, by itself, evidence of a vulnerability.

Run it from the project root:

```powershell
python scanner/dns_checker.py
```

The formatted report is printed in the terminal and saved to `reports/dns_report.json`. The `reports` directory is created as needed. Configuration errors, including malformed JSON and invalid domain names, are reported before queries begin. DNS lookups use a three-second timeout; a failure for one record type does not prevent the remaining record types or configured domains from being checked.

Run the unit tests without relying on live DNS:

```powershell
python -m unittest discover -s tests
```

## Safety
Only run checks against assets explicitly authorised
for this project.
