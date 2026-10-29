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
