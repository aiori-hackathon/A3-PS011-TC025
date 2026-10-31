"""Streamlit dashboard for authorized attack-surface monitoring."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from database.db import (
    DB_PATH,
    get_baseline,
    get_findings,
    get_finding_review_history,
    get_observations_by_scan,
    get_scan_history,
    get_scanner_statuses,
    initialize_database,
    list_assets,
    review_finding,
)
from monitor.baseline import replace_baseline
from monitor.scheduler import start_scheduler
from reports.report_generator import generate_pdf_report
from scanner.scope import load_scope

PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_ROOT / "config.json"

st.set_page_config(page_title="Attack Surface Monitor", page_icon="🛡️", layout="wide")
st.title("Authorized Attack-Surface Inventory and Change Monitor")
st.caption("Scoped DNS, verified TLS certificates, and explicitly configured TCP ports")


def _start_configured_scheduler():
    return start_scheduler(config_path=CONFIG_PATH)


def _parse_json(value: Any, default: Any = None) -> Any:
    if not isinstance(value, str):
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _load_observations(scan_id: int | None) -> list[dict[str, Any]]:
    return get_observations_by_scan(scan_id, DB_PATH) if scan_id is not None else []


initialize_database()
try:
    with CONFIG_PATH.open(encoding="utf-8") as config_file:
        config = json.load(config_file)
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object")
    domains = config.get("domains", [])
    targets = load_scope(CONFIG_PATH)
except (OSError, ValueError, json.JSONDecodeError) as error:
    st.error(f"Unable to load config.json: {error}")
    st.stop()

try:
    scheduler = _start_configured_scheduler()
    if scheduler is not None:
        st.sidebar.success(
            f"Scheduled scans enabled every {config.get('scan_interval_minutes', 60)} minutes "
            "(while this dashboard process is running)."
        )
    else:
        st.sidebar.info("Scheduled scans are disabled in config.json.")
except (OSError, ValueError) as error:
    st.sidebar.error(f"Scheduled monitoring is unavailable: {error}")

assets = list_assets(DB_PATH)
scans = get_scan_history(limit=200, db_path=DB_PATH)
baseline = get_baseline(db_path=DB_PATH)
findings = get_findings(db_path=DB_PATH)
active_findings = [finding for finding in findings if finding["is_active"]]
unresolved_findings = [
    finding
    for finding in active_findings
    if finding["review_status"] != "FALSE_POSITIVE"
]
high_critical = [
    finding
    for finding in unresolved_findings
    if finding["severity"] in {"HIGH", "CRITICAL"}
    and finding["review_status"] != "FALSE_POSITIVE"
]
latest_scan = scans[0] if scans else None
latest_successful = next(
    (scan for scan in scans if scan["scan_status"] == "completed"), None
)
latest_scan_observations = (
    get_observations_by_scan(latest_successful["id"], DB_PATH)
    if latest_successful
    else []
)
last_scanned_at = {
    observation["asset_value"]: observation["observed_at"]
    for observation in latest_scan_observations
}

overview = st.columns(4)
overview[0].metric("Authorized assets", sum(bool(a["is_authorized"]) for a in assets))
overview[1].metric("Configured domains", len(domains))
overview[2].metric("Configured hosts", len(targets))
overview[3].metric("Scan history", len(scans))
overview = st.columns(4)
overview[0].metric(
    "Last scan",
    latest_scan["scan_timestamp"] if latest_scan else "Never",
    latest_scan["scan_status"] if latest_scan else None,
)
overview[1].metric(
    "Active baseline",
    baseline["created_at"] if baseline else "Not set",
)
overview[2].metric("Current findings", len(unresolved_findings))
overview[3].metric("High / critical", len(high_critical))

st.header("Authorized asset inventory")
scope_rows = []
for domain in domains:
    scope_rows.append(
        {
            "Asset": domain,
            "Type": "domain",
            "Authorization": "Configured",
            "Expected ports": "—",
            "Allowed ports": "—",
            "Last scanned": last_scanned_at.get(domain, "Never"),
        }
    )
for target in targets:
    scope_rows.append(
        {
            "Asset": target.hostname,
            "Type": "host",
            "Authorization": "Configured",
            "Expected ports": ", ".join(map(str, target.expected_ports)) or "None",
            "Allowed ports": ", ".join(map(str, target.ports)) or "None",
            "Last scanned": last_scanned_at.get(target.hostname, "Never"),
        }
    )
if scope_rows:
    st.dataframe(pd.DataFrame(scope_rows), use_container_width=True, hide_index=True)
else:
    st.info("No authorized assets are configured.")

st.header("Scan management")
scan_column, status_column = st.columns([1, 2])
with scan_column:
    if st.button("Run full scan", type="primary", key="run-full-scan"):
        from monitor.scan_manager import run_full_scan

        with st.spinner("Scanning only configured assets and allowed ports..."):
            try:
                result = run_full_scan(CONFIG_PATH)
            except RuntimeError as error:
                st.warning(str(error))
            else:
                if result["scan_status"] == "completed":
                    st.success(
                        f"Scan {result['scan_id']} completed. "
                        f"{result.get('observations_saved', 0)} observations saved."
                    )
                elif result["scan_status"] == "failed":
                    st.error(
                        f"Scan {result['scan_id']} failed after retaining "
                        f"{result.get('observations_saved', 0)} observations. "
                        f"{result.get('error_message') or ''}"
                    )
                else:
                    st.warning(
                        f"Scan {result['scan_id']} finished as "
                        f"{result['scan_status']} after retaining "
                        f"{result.get('observations_saved', 0)} observations. "
                        f"{result.get('error_message') or ''}"
                    )
                st.rerun()
with status_column:
    if latest_scan:
        st.write(
            f"Latest scan **{latest_scan['id']}** — "
            f"{latest_scan['scan_status']} — {latest_scan['scan_timestamp']}"
        )
        if latest_scan["completed_at"]:
            started = datetime.fromisoformat(latest_scan["started_at"])
            completed = datetime.fromisoformat(latest_scan["completed_at"])
            st.caption(f"Elapsed: {(completed - started).total_seconds():.1f} seconds")
        if latest_scan["error_message"]:
            st.warning(latest_scan["error_message"])
    else:
        st.info("No scans have been recorded.")

st.subheader("Baseline controls")
if baseline:
    st.write(
        f"Active baseline: scan {baseline['scan_id']} created {baseline['created_at']}. "
        "It is not overwritten by later scans."
    )
completed_scans = [scan for scan in scans if scan["scan_status"] == "completed"]
if completed_scans:
    confirmed_replace = st.checkbox(
        "I understand replacing the baseline changes the comparison reference."
    )
    scan_options = {
        f"Scan {scan['id']} — {scan['scan_timestamp']}": scan["id"]
        for scan in completed_scans
    }
    selected_scan = st.selectbox("Completed scan", list(scan_options))
    if st.button(
        "Replace active baseline",
        disabled=not confirmed_replace,
        key="replace-baseline",
    ):
        try:
            replace_baseline(scan_options[selected_scan], DB_PATH)
        except (ValueError, RuntimeError) as error:
            st.error(f"Baseline replacement failed: {error}")
        else:
            st.success("Baseline replaced.")
            st.rerun()

st.header("Monitoring results")
selected_scan_label = st.selectbox(
    "Inspect scan",
    ["Latest successful scan"] + [
        f"Scan {scan['id']} ({scan['scan_status']}) — {scan['scan_timestamp']}"
        for scan in scans
    ],
)
if selected_scan_label == "Latest successful scan":
    selected_scan_id = latest_successful["id"] if latest_successful else None
else:
    selected_scan_id = int(selected_scan_label.split()[1])
observations = _load_observations(selected_scan_id)
if selected_scan_id is None:
    st.info("Run a full scan to populate DNS, TLS, and port observations.")
else:
    scanner_status_rows = get_scanner_statuses(selected_scan_id, DB_PATH)
    st.subheader("Scanner execution status")
    if scanner_status_rows:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Scanner": row["scanner_type"],
                        "Asset": row["asset_value"],
                        "Status": row["status"],
                        "Details": row["message"] or "",
                        "Completed": row["completed_at"],
                    }
                    for row in scanner_status_rows
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No per-scanner status records are available for this scan.")

dns_rows = []
tls_rows = []
port_rows = []
for observation in observations:
    details = _parse_json(observation.get("details"), {})
    if observation["scanner_type"] == "DNS":
        dns_rows.append(
            {
                "Asset": observation["asset_value"],
                "Record": observation["observation_type"],
                "Status": details.get("status", "UNKNOWN"),
                "Values": ", ".join(_parse_json(observation["observation_value"], []))
                or "—",
                "Error": (details.get("error") or {}).get("message", ""),
            }
        )
    elif observation["scanner_type"] == "TLS":
        value = _parse_json(observation["observation_value"], {})
        tls_rows.append(
            {
                "Hostname": observation["asset_value"],
                "Status": "Valid" if value.get("available") else "Unavailable",
                "Issuer": value.get("issuer", "—"),
                "Expires": value.get("expires_at", "—"),
                "Days remaining": value.get("days_remaining", "—"),
                "Fingerprint": value.get("fingerprint_sha256", "—"),
                "Error": value.get("error", ""),
            }
        )
    elif observation["scanner_type"] == "PORT":
        state = details.get("state", observation["observation_type"])
        port = details.get("port", observation["observation_type"])
        error_message = (details.get("error") or {}).get("message", "")
        if state == "FILTERED_OR_NO_RESPONSE":
            error_message = (
                f"Port {port} did not respond before the configured timeout. "
                "Its state is inconclusive; this is not proof that the port is closed."
            )
        elif state == "ERROR":
            error_message = f"Scanner error: {error_message or 'No details provided'}"
        port_rows.append(
            {
                "Host": observation["asset_value"],
                "Port": port,
                "Protocol": details.get("protocol", "TCP"),
                "Expected": "Yes" if details.get("expected") else "No",
                "Allowed": "Yes",
                "State": state,
                "Response time (ms)": details.get("response_time_ms", "—"),
                "Details": error_message,
            }
        )

dns_tab, tls_tab, port_tab = st.tabs(["DNS", "TLS", "Ports"])
with dns_tab:
    st.subheader("DNS records and status")
    if dns_rows:
        st.dataframe(pd.DataFrame(dns_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No DNS observations are available for this scan.")
with tls_tab:
    st.subheader("TLS certificates")
    if tls_rows:
        st.dataframe(pd.DataFrame(tls_rows), use_container_width=True, hide_index=True)
    else:
        st.info("TLS is checked only when port 443 is explicitly allowed.")
with port_tab:
    st.subheader("Configured TCP ports")
    if port_rows:
        st.dataframe(pd.DataFrame(port_rows), use_container_width=True, hide_index=True)
        expected_unavailable = [
            row
            for row in port_rows
            if row["Expected"] == "Yes"
            and row["State"] == "FILTERED_OR_NO_RESPONSE"
        ]
        if expected_unavailable:
            for row in expected_unavailable:
                st.warning(row["Details"])
        scanner_errors = [row for row in port_rows if row["State"] == "ERROR"]
        if scanner_errors:
            st.error(
                "One or more port checks encountered scanner errors. "
                "Review the details in the port table and scanner status above."
            )
    else:
        st.info("No configured port observations are available.")

st.header("Security findings and change detection")
if findings:
    filters = st.columns(5)
    asset_filter = filters[0].selectbox(
        "Asset filter", ["All"] + sorted({finding["asset_value"] for finding in findings})
    )
    severity_filter = filters[1].selectbox(
        "Severity filter", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )
    status_filter = filters[2].selectbox(
        "Review status", ["All", "NEW", "REVIEW_REQUIRED", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"]
    )
    active_filter = filters[3].selectbox(
        "Finding activity", ["Active and historical", "Active only"]
    )
    date_filter = filters[4].selectbox(
        "Detected within", ["Any time", "24 hours", "7 days", "30 days"]
    )
    filtered = findings
    if asset_filter != "All":
        filtered = [finding for finding in filtered if finding["asset_value"] == asset_filter]
    if severity_filter != "All":
        filtered = [finding for finding in filtered if finding["severity"] == severity_filter]
    if status_filter != "All":
        filtered = [
            finding for finding in filtered if finding["review_status"] == status_filter
        ]
    if active_filter == "Active only":
        filtered = [finding for finding in filtered if finding["is_active"]]
    if date_filter != "Any time":
        hours = {"24 hours": 24, "7 days": 168, "30 days": 720}[date_filter]
        cutoff = datetime.now().astimezone() - timedelta(hours=hours)
        filtered = [
            finding
            for finding in filtered
            if datetime.fromisoformat(finding["detected_at"]).astimezone() >= cutoff
        ]

    distribution = pd.DataFrame(
        [
            {"Severity": severity, "Findings": sum(
                finding["severity"] == severity
                and finding["is_active"]
                and finding["review_status"] != "FALSE_POSITIVE"
                for finding in findings
            )}
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        ]
    ).set_index("Severity")
    st.bar_chart(distribution)
    display_rows = [
        {
            "ID": item["id"],
            "Asset": item["asset_value"],
            "Category": item["category"],
            "Severity": item["severity"],
            "Status": item["review_status"],
            "Active": bool(item["is_active"]),
            "Evidence": item["evidence"],
            "Recommended action": item["recommended_action"],
            "Detected": item["detected_at"],
        }
        for item in filtered
    ]
    st.dataframe(pd.DataFrame(display_rows), use_container_width=True, hide_index=True)
    for finding in filtered:
        with st.expander(
            f"Review finding {finding['id']}: {finding['category']} "
            f"({finding['review_status']})"
        ):
            st.write(finding["description"])
            st.caption(f"Evidence: {finding['evidence']}")
            st.caption(f"Recommended action: {finding['recommended_action']}")
            history = get_finding_review_history(finding["id"], DB_PATH)
            if history:
                st.write("Review history")
                st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
            note = st.text_input("Review note", key=f"review-note-{finding['id']}")
            review_action = st.selectbox(
                "Decision",
                ["CONFIRMED", "FALSE_POSITIVE", "RESOLVED"],
                key=f"review-action-{finding['id']}",
            )
            if st.button("Save review", key=f"save-review-{finding['id']}"):
                try:
                    review_finding(finding["id"], review_action, note, DB_PATH)
                except ValueError as error:
                    st.error(f"Could not save review: {error}")
                else:
                    st.success("Review decision saved.")
                    st.rerun()
else:
    st.info("No findings are recorded.")

st.header("Scan history")
if scans:
    scan_counts = (
        pd.DataFrame(
            [
                {"Date": scan["scan_timestamp"][:10], "Scans": 1}
                for scan in scans
            ]
        )
        .groupby("Date", as_index=True)
        .sum()
        .sort_index()
    )
    st.line_chart(scan_counts)
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Scan ID": scan["id"],
                    "Source": scan.get("scan_source", "manual"),
                    "Timestamp": scan["scan_timestamp"],
                    "Status": scan["scan_status"],
                    "Assets checked": scan["assets_scanned"],
                    "Findings": scan["findings_count"],
                    "Started": scan["started_at"],
                    "Completed": scan["completed_at"] or "—",
                    "Error": scan["error_message"] or "",
                }
                for scan in scans
            ]
        ),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No scan history is available.")

st.header("Reports")
if st.button("Generate PDF report", key="generate-pdf"):
    try:
        pdf_bytes = generate_pdf_report(db_path=DB_PATH)
    except Exception as error:
        st.error(f"PDF report generation failed: {error}")
    else:
        st.download_button(
            "Download PDF report",
            data=pdf_bytes,
            file_name=f"attack_surface_report_{datetime.now():%Y%m%d_%H%M%S}.pdf",
            mime="application/pdf",
            key="download-pdf",
        )
