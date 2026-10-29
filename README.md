# AIORI-3-HACKATHON-PROJECTS
Youtube link for video: https://youtu.be/CFCZ6hMw4Uk?si=5bE_guE9KVD_HHvu


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

## Day 3: TLS Certificate Monitoring
The TLS checker reads approved hostnames from the `domains` array in `config.json` and validates them with the same domain allowlist used by DNS discovery. A host passed directly to `check_tls` is also checked against this allowlist before any connection is made. Connections use port 443 by default, Python's default certificate trust and hostname verification, and SNI. Verification is never disabled.

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
python -m unittest discover -s tests
```

## Safety
Only run checks against assets explicitly authorised
for this project.
