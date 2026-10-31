
"""Run the attack-surface monitoring workflow for the configured scope."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from database.db import initialize_database, save_scan
from monitor.scan_manager import run_full_scan
from scanner.dns_checker import check_dns
from scanner.port_checker import check_ports
from scanner.scope import load_scope
from scanner.tls_checker import check_tls


def load_config() -> dict:
    config_path = Path(__file__).parent / "config.json"
    with config_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def scan_target(hostname: str, ports: tuple[int, ...] | list[int]) -> dict:
    config_path = Path(__file__).with_name("config.json")
    authorized_targets = {target.hostname: target for target in load_scope(config_path)}
    target = authorized_targets.get(hostname.strip().rstrip(".").lower())
    if target is None:
        raise ValueError(f"{hostname!r} is not an explicitly configured host")
    if not isinstance(ports, (tuple, list)) or any(
        isinstance(port, bool) or not isinstance(port, int) for port in ports
    ):
        raise ValueError("ports must be a list of explicitly configured integer ports")
    requested_ports = tuple(ports)
    if len(set(requested_ports)) != len(requested_ports) or not set(
        requested_ports
    ).issubset(target.ports):
        raise ValueError("Requested ports must be unique and explicitly allowed in config.json")

    dns_result = check_dns(target.hostname)
    port_result = check_ports(
        target.hostname,
        requested_ports,
        timeout=target.connection_timeout_seconds,
    )
    tls_result = (
        check_tls(target.hostname, port=443)
        if 443 in requested_ports
        else {"available": False, "error": "HTTPS not in configured ports"}
    )
    result = {
        "hostname": target.hostname,
        "scanned_at": _utc_timestamp(),
        "dns": dns_result,
        "tls": tls_result,
        "ports": port_result,
    }
    save_scan(result)
    return result


def scan_all(scan_source: str = "manual") -> dict:
    initialize_database()
    summary = run_full_scan(
        Path(__file__).with_name("config.json"),
        scan_source=scan_source,
    )
    for result in summary["results"]:
        save_scan(result)
    return summary


def main() -> None:
    config = load_config()

    print("Attack-Surface Monitor")
    print("======================")
    print("Configured domains:", config.get("domains", []))
    print("Configured hosts:", config.get("hosts", []))
    print("Scan interval:", config.get("scan_interval_minutes", 0), "minutes")

    summary = scan_all(scan_source="cli")
    print(
        f"Scan {summary['scan_id']} finished with status "
        f"{summary['scan_status']} ({len(summary['results'])} host(s))."
    )
    if summary["error_message"]:
        print("Scan details:", summary["error_message"])


if __name__ == "__main__":
    main()
