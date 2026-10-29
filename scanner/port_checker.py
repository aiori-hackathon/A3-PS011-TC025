"""Check TCP reachability for explicitly approved hosts and ports."""

import json
import math
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TIMEOUT = 2.0
HTTP_PORTS = {80, 3000, 5000, 5001, 8000, 8080, 8888}

# Add the project root when this file is run directly instead of as a module.
if __package__ in (None, ""):
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scope import PortTarget, load_port_scope


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _error_details(error: Exception) -> dict[str, str]:
    return {"type": type(error).__name__, "message": str(error) or "No additional details"}


def _error_result(host: str, port: int, error: Exception) -> dict[str, Any]:
    return {
        "hostname": host,
        "port": port,
        "protocol": "TCP",
        "scanned_at": _utc_timestamp(),
        "status": "ERROR",
        "error": _error_details(error),
    }


def check_port(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Check TCP connectivity to one host/port, only when config authorizes it.

    OPEN proves that a TCP connection was accepted at scan time; it does not
    identify the application or establish that the service is vulnerable.
    """
    normalized_host = host.strip().rstrip(".").lower() if isinstance(host, str) else str(host)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return _error_result(normalized_host, port, ValueError("port must be an integer from 1 to 65535"))
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        return _error_result(normalized_host, port, ValueError("timeout must be a positive finite number"))

    path = Path(config_path) if config_path is not None else PROJECT_ROOT / "config.json"
    try:
        targets = load_port_scope(path)
    except ValueError as error:
        return _error_result(normalized_host, port, error)

    target = next((item for item in targets if item.hostname == normalized_host), None)
    if target is None or port not in target.allowed_ports:
        error = PermissionError("Host and port must both be explicitly listed in config.json")
        return _error_result(normalized_host, port, error)

    scanned_at = _utc_timestamp()
    try:
        with socket.create_connection((normalized_host, port), timeout=float(timeout)):
            status = "OPEN"
            error_details = None
    except (socket.timeout, TimeoutError) as error:
        status = "TIMEOUT"
        error_details = _error_details(error)
    except ConnectionRefusedError as error:
        status = "CONNECTION_FAILED"
        error_details = _error_details(error)
    except OSError as error:
        status = "ERROR"
        error_details = _error_details(error)

    return {
        "hostname": normalized_host,
        "port": port,
        "protocol": "TCP",
        "scanned_at": scanned_at,
        "status": status,
        "error": error_details,
    }


def _identify_service(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Make a safe HTTP HEAD request on conventional, approved web ports only."""
    if port not in HTTP_PORTS:
        return {
            "status": "not_attempted",
            "protocol": None,
            "evidence": "No protocol-specific identification is configured for this port.",
        }

    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            connection.sendall(request.encode("ascii"))
            response = connection.recv(256).decode("ascii", errors="replace").splitlines()
        if response:
            return {"status": "identified", "protocol": "HTTP", "evidence": response[0][:200]}
        return {"status": "no_response", "protocol": "HTTP", "evidence": "No HTTP status line received."}
    except (socket.timeout, TimeoutError):
        return {"status": "no_response", "protocol": "HTTP", "evidence": "HTTP HEAD timed out."}
    except OSError as error:
        return {"status": "error", "protocol": "HTTP", "evidence": str(error)}


def _scope_error_result(host: str, error: Exception) -> dict[str, Any]:
    return {
        "hostname": host,
        "scanned_at": _utc_timestamp(),
        "status": "ERROR",
        "error": _error_details(error),
        "ports": [],
        "findings": [],
    }


def _expected_match(expected_state: str, observed_status: str) -> bool | None:
    if observed_status in {"TIMEOUT", "ERROR"}:
        return None
    if expected_state == "OPEN":
        return observed_status == "OPEN"
    return observed_status == "CONNECTION_FAILED"


def _is_explicit_port_list(ports: object) -> bool:
    return (
        isinstance(ports, (list, tuple))
        and all(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 for port in ports)
        and len(set(ports)) == len(ports)
    )


def check_approved_ports(
    host: str,
    allowed_ports: list[int] | tuple[int, ...] | None = None,
    expected_ports: list[int] | tuple[int, ...] | None = None,
    config_path: str | Path | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Check a configured host's allowed ports and flag open ports outside inventory.

    The config remains authoritative: optional port lists must exactly match its
    lists, preventing callers from broadening the approved scan scope.
    """
    normalized_host = host.strip().rstrip(".").lower() if isinstance(host, str) else str(host)
    path = Path(config_path) if config_path is not None else PROJECT_ROOT / "config.json"
    try:
        targets = load_port_scope(path)
    except ValueError as error:
        return _scope_error_result(normalized_host, error)

    target = next((item for item in targets if item.hostname == normalized_host), None)
    if target is None:
        return _scope_error_result(
            normalized_host,
            PermissionError("Host is not explicitly listed in config.json"),
        )
    if allowed_ports is not None and not _is_explicit_port_list(allowed_ports):
        return _scope_error_result(normalized_host, ValueError("allowed_ports must be an explicit list of unique port numbers"))
    if expected_ports is not None and not _is_explicit_port_list(expected_ports):
        return _scope_error_result(normalized_host, ValueError("expected_ports must be an explicit list of unique port numbers"))
    if allowed_ports is not None and set(allowed_ports) != set(target.allowed_ports):
        return _scope_error_result(normalized_host, PermissionError("allowed_ports do not match config.json"))
    if expected_ports is not None and set(expected_ports) != set(target.expected_ports):
        return _scope_error_result(normalized_host, PermissionError("expected_ports do not match config.json"))

    results = []
    findings = []
    for port in target.allowed_ports:
        result = check_port(normalized_host, port, timeout=timeout, config_path=path)
        expected_state = "OPEN" if port in target.expected_ports else "CLOSED"
        result["expected_state"] = expected_state
        result["observed_state"] = result["status"]
        result["expected_match"] = _expected_match(expected_state, result["status"])
        if result["status"] == "OPEN":
            result["service_identification"] = _identify_service(normalized_host, port, timeout)

        if result["status"] == "OPEN" and port not in target.expected_ports:
            findings.append(
                {
                    "hostname": normalized_host,
                    "port": port,
                    "protocol": "TCP",
                    "observed_status": result["status"],
                    "expected_state": expected_state,
                    "observed_state": result["status"],
                    "scanned_at": result["scanned_at"],
                    "evidence": "TCP accepted a connection on an allowed port absent from expected_ports; review is required, and this is not by itself a vulnerability.",
                    "suggested_next_action": "Confirm whether this service is authorised and intentionally exposed; update the expected inventory if approved, otherwise investigate with the asset owner.",
                    "review_required": True,
                }
            )
        elif result["expected_match"] is False:
            findings.append(
                {
                    "hostname": normalized_host,
                    "port": port,
                    "protocol": "TCP",
                    "observed_status": result["status"],
                    "expected_state": expected_state,
                    "observed_state": result["status"],
                    "scanned_at": result["scanned_at"],
                    "evidence": "The observed TCP state differs from the configured expected state.",
                    "suggested_next_action": "Confirm the service state with the asset owner and review whether the expected inventory should change.",
                    "review_required": True,
                }
            )
        results.append(result)

    return {
        "hostname": normalized_host,
        "scanned_at": _utc_timestamp(),
        "status": "completed",
        "ports": results,
        "findings": findings,
    }


def run_port_checks(
    config_path: str | Path | None = None,
    report_path: str | Path | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """Check each configured host and save reports/port_report.json."""
    path = Path(config_path) if config_path is not None else PROJECT_ROOT / "config.json"
    targets: list[PortTarget] = load_port_scope(path)
    results = []
    for target in targets:
        try:
            results.append(
                check_approved_ports(
                    target.hostname,
                    allowed_ports=target.allowed_ports,
                    expected_ports=target.expected_ports,
                    config_path=path,
                    timeout=timeout,
                )
            )
        except Exception as error:
            results.append(_scope_error_result(target.hostname, error))

    destination = Path(report_path) if report_path is not None else PROJECT_ROOT / "reports" / "port_report.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    formatted_report = json.dumps(results, indent=2)
    destination.write_text(formatted_report + "\n", encoding="utf-8")
    print(formatted_report)
    return results


def check_ports(
    hostname: str,
    ports: list[int] | tuple[int, ...],
    timeout: float = DEFAULT_TIMEOUT,
    config_path: str | Path | None = None,
) -> dict[str, list[int]]:
    """Compatibility wrapper for callers of the earlier check_ports API.

    Only configured ports are checked. TIMEOUT and ERROR are kept separate
    rather than being incorrectly reported as closed.
    """
    path = Path(config_path) if config_path is not None else PROJECT_ROOT / "config.json"
    try:
        targets = load_port_scope(path)
    except ValueError:
        return {"open": [], "closed": [], "inconclusive": [], "errors": []}
    target = next((item for item in targets if item.hostname == hostname.strip().rstrip(".").lower()), None)
    if (
        target is None
        or not _is_explicit_port_list(ports)
        or any(port not in target.allowed_ports for port in ports)
    ):
        return {"open": [], "closed": [], "inconclusive": [], "errors": []}

    categorized = {"open": [], "closed": [], "inconclusive": [], "errors": []}
    for port in ports:
        status = check_port(hostname, port, timeout=timeout, config_path=path)["status"]
        if status == "OPEN":
            categorized["open"].append(port)
        elif status == "CONNECTION_FAILED":
            categorized["closed"].append(port)
        elif status == "TIMEOUT":
            categorized["inconclusive"].append(port)
        else:
            categorized["errors"].append(port)
    return categorized


if __name__ == "__main__":
    try:
        run_port_checks()
    except ValueError as error:
        print(f"Port monitoring configuration error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    except OSError as error:
        print(f"Could not write port report: {error}", file=sys.stderr)
        raise SystemExit(1) from error