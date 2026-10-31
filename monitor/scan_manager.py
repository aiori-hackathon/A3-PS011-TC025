"""Run authorized scanners and persist their results as one scan."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from database.db import (
    DB_PATH,
    create_scan,
    resolve_missing_findings,
    initialize_database,
    register_asset,
    save_finding,
    save_observation,
    save_scanner_status,
    sync_authorized_assets,
    update_scan_status,
)
from monitor.baseline import create_initial_baseline, get_active_baseline
from monitor.change_detector import detect_scan_changes
from scanner.dns_checker import check_dns
from scanner.port_checker import check_ports
from scanner.scope import Target, load_scope, validate_domains
from scanner.tls_checker import check_tls

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SCAN_LOCK = Lock()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_authorized_targets(
    config_path: str | Path,
) -> tuple[list[str], list[Target]]:
    path = Path(config_path)
    try:
        with path.open(encoding="utf-8") as config_file:
            config = json.load(config_file)
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {path}: {error}") from error
    except OSError as error:
        raise ValueError(f"Could not read configuration file {path}: {error}") from error

    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object")
    domains = validate_domains(config.get("domains", []))
    targets = load_scope(path)

    for target in targets:
        try:
            ipaddress.ip_address(target.hostname)
        except ValueError:
            validate_domains([target.hostname])

    if not domains and not targets:
        raise ValueError("Configure at least one explicitly authorized domain or host")
    return domains, targets


def _save_dns_observations(
    scan_id: int,
    asset_id: int,
    result: dict[str, Any],
    db_path: str | Path,
) -> int:
    record_types = result.get("record_types")
    if not isinstance(record_types, dict) or set(record_types) != {"A", "AAAA", "CNAME"}:
        raise ValueError("DNS scanner returned an incomplete record_types result")

    count = 0
    for record_type in ("A", "AAAA", "CNAME"):
        record = record_types[record_type]
        if not isinstance(record, dict):
            raise ValueError(f"DNS scanner returned an invalid {record_type} result")
        values = record.get("values", record.get("answers"))
        if (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value.strip() for value in values)
        ):
            raise ValueError(f"DNS scanner returned invalid {record_type} values")
        status = record.get("status")
        if status not in {
            "RECORD_FOUND",
            "NO_RECORD",
            "DOMAIN_NOT_FOUND",
            "TIMEOUT",
            "DNS_ERROR",
        }:
            raise ValueError(f"DNS scanner returned an invalid {record_type} status")
        if (status == "RECORD_FOUND") != bool(values):
            raise ValueError(
                f"DNS scanner status and values disagree for {record_type}"
            )
        save_observation(
            scan_id,
            asset_id,
            "DNS",
            record_type,
            json.dumps(values, sort_keys=True),
            {"status": record.get("status"), "error": record.get("error")},
            observed_at=record.get("scanned_at"),
            db_path=db_path,
        )
        count += 1
    return count


def _save_port_observations(
    scan_id: int,
    asset_id: int,
    configured_ports: tuple[int, ...],
    expected_ports: tuple[int, ...],
    result: dict[str, Any],
    db_path: str | Path,
) -> int:
    open_ports = result.get("open")
    closed_ports = result.get("closed")
    if not isinstance(open_ports, list) or not isinstance(closed_ports, list):
        raise ValueError("Port scanner returned an invalid open/closed result")
    if any(type(port) is not int for port in open_ports + closed_ports):
        raise ValueError("Port scanner results must contain integer port numbers")
    if set(open_ports) & set(closed_ports):
        raise ValueError("Port scanner reported a port as both open and closed")
    states = result.get("results", {})
    if not isinstance(states, dict):
        raise ValueError("Port scanner returned an invalid per-port result")
    if not states:
        states = {
            **{
                port: {"state": "OPEN", "error": None}
                for port in open_ports
            },
            **{
                port: {"state": "CLOSED", "error": None}
                for port in closed_ports
            },
        }

    if set(open_ports) & set(closed_ports):
        raise ValueError("Port scanner reported a port as both open and closed")
    if not set(open_ports).issubset(configured_ports) or not set(closed_ports).issubset(
        configured_ports
    ):
        raise ValueError("Port scanner returned an out-of-scope port")
    if {int(port) for port in states} != set(configured_ports):
        raise ValueError("Port scanner returned an incomplete or out-of-scope result")

    for port in configured_ports:
        port_result = states.get(port, states.get(str(port)))
        if not isinstance(port_result, dict) or port_result.get("state") not in {
            "OPEN",
            "CLOSED",
            "FILTERED_OR_NO_RESPONSE",
            "ERROR",
        }:
            raise ValueError(f"Port scanner returned an invalid state for port {port}")
        state = port_result["state"]
        if state == "OPEN" and port not in open_ports:
            raise ValueError(f"Port scanner's open list disagrees for port {port}")
        if state == "CLOSED" and port not in closed_ports:
            raise ValueError(f"Port scanner's closed list disagrees for port {port}")
        if state in {"FILTERED_OR_NO_RESPONSE", "ERROR"} and (
            port in open_ports or port in closed_ports
        ):
            raise ValueError(f"Port scanner returned conflicting state for port {port}")
        save_observation(
            scan_id,
            asset_id,
            "PORT",
            f"PORT_STATE:{port}",
            state,
            {
                "port": port,
                "hostname": port_result.get("hostname", result.get("hostname")),
                "protocol": port_result.get("protocol", result.get("protocol", "TCP")),
                "state": state,
                "expected": port in expected_ports,
                "response_time_ms": port_result.get("response_time_ms"),
                "error": port_result.get("error"),
            },
            observed_at=port_result.get("scanned_at"),
            db_path=db_path,
        )
    return len(configured_ports)


def _run_full_scan(
    config_path: str | Path | None = None,
    db_path: str | Path = DB_PATH,
    scan_source: str = "manual",
) -> dict[str, Any]:
    """Scan only configured assets and return a structured lifecycle summary."""
    config_path = config_path or PROJECT_ROOT / "config.json"
    domains, targets = _load_authorized_targets(config_path)
    initialize_database(db_path)

    started_at = _utc_timestamp()
    scan_id = create_scan(db_path=db_path, scan_source=scan_source)
    summary: dict[str, Any] = {
        "scan_id": scan_id,
        "scan_status": "running",
        "started_at": started_at,
        "completed_at": None,
        "error_message": None,
        "assets_scanned": len(set(domains) | {target.hostname for target in targets}),
        "observations_saved": 0,
        "baseline_created": False,
        "baseline_id": None,
        "scanners": {"DNS": "SKIPPED", "TLS": "SKIPPED", "PORT": "SKIPPED"},
        "scanner_runs": [],
        "results": [],
    }

    try:
        sync_authorized_assets(
            domains,
            [target.hostname for target in targets],
            db_path,
        )
        domain_asset_ids = {
            domain: register_asset("domain", domain, True, db_path)
            for domain in domains
        }
        host_asset_ids = {
            target.hostname: register_asset("host", target.hostname, True, db_path)
            for target in targets
        }
        scanner_records: list[dict[str, str]] = []
        issue_messages: list[str] = []

        def record_status(
            scanner_type: str,
            asset_value: str,
            status: str,
            message: str | None = None,
        ) -> None:
            save_scanner_status(
                scan_id,
                scanner_type,
                asset_value,
                status,
                message,
                db_path,
            )
            scanner_records.append(
                {
                    "scanner": scanner_type,
                    "asset": asset_value,
                    "status": status,
                    "message": message or "",
                }
            )
            if message:
                issue_messages.append(message)

        dns_names = list(domains)
        for target in targets:
            if target.hostname not in domain_asset_ids:
                try:
                    ipaddress.ip_address(target.hostname)
                except ValueError:
                    dns_names.append(target.hostname)
        dns_names = list(dict.fromkeys(dns_names))

        dns_results: dict[str, dict[str, Any]] = {}
        for name in dns_names:
            scanner_failed = False
            try:
                result = check_dns(name)
            except Exception as error:
                scanner_failed = True
                timestamp = _utc_timestamp()
                error_details = {
                    "type": type(error).__name__,
                    "message": str(error) or "No additional details",
                }
                result = {
                    "domain": name,
                    "scanned_at": timestamp,
                    "record_types": {
                        record_type: {
                            "record_type": record_type,
                            "status": "DNS_ERROR",
                            "values": [],
                            "error": error_details,
                            "scanned_at": timestamp,
                        }
                        for record_type in ("A", "AAAA", "CNAME")
                    },
                }
            asset_id = domain_asset_ids.get(name, host_asset_ids.get(name))
            if asset_id is None:
                raise RuntimeError(f"No authorized asset record exists for {name}")
            summary["observations_saved"] += _save_dns_observations(
                scan_id, asset_id, result, db_path
            )
            record_statuses = {
                record.get("status") for record in result["record_types"].values()
            }
            dns_errors = [
                f"DNS {record_type} query for {name}: "
                f"{(record.get('error') or {}).get('message', record['status'])}"
                for record_type, record in result["record_types"].items()
                if record.get("status") in {"TIMEOUT", "DNS_ERROR"}
            ]
            if scanner_failed:
                status = "FAILED"
            elif "TIMEOUT" in record_statuses:
                status = "INCONCLUSIVE"
            elif "DNS_ERROR" in record_statuses:
                status = "COMPLETED_WITH_WARNINGS"
            else:
                status = "COMPLETED"
            record_status("DNS", name, status, "; ".join(dns_errors) or None)
            dns_results[name] = result

        host_results: dict[str, dict[str, Any]] = {}
        for target in targets:
            asset_id = host_asset_ids[target.hostname]
            port_scanner_failed = False
            if target.ports:
                try:
                    port_result = check_ports(
                        target.hostname,
                        target.ports,
                        timeout=target.connection_timeout_seconds,
                    )
                except Exception as error:
                    port_scanner_failed = True
                    timestamp = _utc_timestamp()
                    error_details = {
                        "type": type(error).__name__,
                        "message": str(error) or "No additional details",
                    }
                    port_result = {
                        "hostname": target.hostname,
                        "protocol": "TCP",
                        "open": [],
                        "closed": [],
                        "results": {
                            port: {
                                "hostname": target.hostname,
                                "port": port,
                                "protocol": "TCP",
                                "state": "ERROR",
                                "scanned_at": timestamp,
                                "response_time_ms": None,
                                "error": error_details,
                            }
                            for port in target.ports
                        },
                    }
            summary["observations_saved"] += _save_port_observations(
                scan_id,
                asset_id,
                target.ports,
                target.expected_ports,
                port_result,
                db_path,
            )
            port_errors = [
                f"Port {port} check for {target.hostname}: "
                f"{(port_result_data.get('error') or {}).get('message', port_result_data['state'])}"
                for port, port_result_data in port_result.get("results", {}).items()
                if port_result_data.get("state")
                in {"FILTERED_OR_NO_RESPONSE", "ERROR"}
            ]
            port_states = {
                item.get("state") for item in port_result.get("results", {}).values()
            }
            if port_scanner_failed or "ERROR" in port_states:
                port_status = "FAILED"
            elif "FILTERED_OR_NO_RESPONSE" in port_states:
                port_status = "INCONCLUSIVE"
            elif target.ports:
                port_status = "COMPLETED"
            else:
                port_status = "SKIPPED"
            record_status("PORT", target.hostname, port_status, "; ".join(port_errors) or None)

            if 443 in target.ports:
                tls_scanner_failed = False
                try:
                    tls_result = check_tls(
                        target.hostname,
                        port=443,
                        timeout=target.connection_timeout_seconds,
                    )
                except Exception as error:
                    tls_scanner_failed = True
                    tls_result = {
                        "available": False,
                        "check_completed": False,
                        "error": str(error) or "No additional details",
                        "error_type": type(error).__name__,
                        "hostname": target.hostname,
                        "port": 443,
                    }
                if not isinstance(tls_result, dict):
                    raise ValueError("TLS scanner returned an invalid result")
                save_observation(
                    scan_id,
                    asset_id,
                    "TLS",
                    "CERTIFICATE" if tls_result.get("available") else "TLS_RESULT",
                    json.dumps(tls_result, sort_keys=True, default=list),
                    {"available": tls_result.get("available")},
                    db_path=db_path,
                )
                summary["observations_saved"] += 1
                if tls_scanner_failed:
                    tls_status = "FAILED"
                elif not tls_result.get(
                    "check_completed", tls_result.get("available", False)
                ):
                    tls_status = (
                        "INCONCLUSIVE"
                        if tls_result.get("error_type")
                        in {"TimeoutError", "Timeout", "socket.timeout"}
                        else "FAILED"
                    )
                elif not tls_result.get("available"):
                    tls_status = "COMPLETED_WITH_WARNINGS"
                else:
                    tls_status = "COMPLETED"
                record_status(
                    "TLS",
                    target.hostname,
                    tls_status,
                    tls_result.get("error")
                    if tls_status
                    in {"FAILED", "INCONCLUSIVE", "COMPLETED_WITH_WARNINGS"}
                    else None,
                )
            else:
                tls_result = {
                    "available": False,
                    "skipped": True,
                    "reason": "Port 443 is not in this host's authorized port list",
                }
                record_status(
                    "TLS",
                    target.hostname,
                    "SKIPPED",
                    tls_result["reason"],
                )

            host_results[target.hostname] = {
                "hostname": target.hostname,
                "scanned_at": _utc_timestamp(),
                "dns": dns_results.get(target.hostname),
                "tls": tls_result,
                "ports": port_result,
                "scanners": {
                    record["scanner"]: record["status"]
                    for record in scanner_records
                    if record["asset"] == target.hostname
                },
            }

        summary["results"] = list(host_results.values())
        summary["scanner_runs"] = scanner_records
        for scanner_type in ("DNS", "TLS", "PORT"):
            statuses = [
                item["status"]
                for item in scanner_records
                if item["scanner"] == scanner_type
            ]
            if not statuses:
                summary["scanners"][scanner_type] = "SKIPPED"
            elif "FAILED" in statuses:
                summary["scanners"][scanner_type] = "FAILED"
            elif "INCONCLUSIVE" in statuses:
                summary["scanners"][scanner_type] = "INCONCLUSIVE"
            elif "COMPLETED_WITH_WARNINGS" in statuses:
                summary["scanners"][scanner_type] = "COMPLETED_WITH_WARNINGS"
            elif all(status == "SKIPPED" for status in statuses):
                summary["scanners"][scanner_type] = "SKIPPED"
            else:
                summary["scanners"][scanner_type] = "COMPLETED"

        statuses = {record["status"] for record in scanner_records}
        if "FAILED" in statuses:
            final_status = "failed"
        elif "INCONCLUSIVE" in statuses:
            final_status = "inconclusive"
        elif "COMPLETED_WITH_WARNINGS" in statuses:
            final_status = "completed_with_warnings"
        else:
            final_status = "completed"
        summary["error_message"] = "; ".join(issue_messages) or None
        summary["scan_status"] = final_status
        update_scan_status(
            scan_id,
            final_status,
            summary["error_message"],
            db_path,
        )
        summary["completed_at"] = _utc_timestamp()

        if final_status == "completed" and get_active_baseline(db_path) is None:
            baseline = create_initial_baseline(scan_id, db_path)
            summary["baseline_created"] = baseline["scan_id"] == scan_id
            summary["baseline_id"] = baseline["id"]
        findings = detect_scan_changes(scan_id, db_path)
        for finding in findings:
            save_finding(scan_id=scan_id, db_path=db_path, **finding)
        summary["findings_count"] = len(findings)
        if final_status == "completed":
            active_fingerprints = {finding["fingerprint"] for finding in findings}
            resolve_missing_findings(active_fingerprints, scan_id, db_path)
        return summary
    except Exception as error:
        update_scan_status(scan_id, "failed", str(error), db_path)
        summary["scan_status"] = "failed"
        summary["completed_at"] = _utc_timestamp()
        summary["error_message"] = str(error)
        return summary


def run_full_scan(
    config_path: str | Path | None = None,
    db_path: str | Path = DB_PATH,
    scan_source: str = "manual",
) -> dict[str, Any]:
    """Run at most one full scan in this process at a time."""
    if not _SCAN_LOCK.acquire(blocking=False):
        raise RuntimeError("A full scan is already running")
    try:
        return _run_full_scan(config_path, db_path, scan_source)
    finally:
        _SCAN_LOCK.release()
