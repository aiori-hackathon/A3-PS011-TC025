"""Baseline lifecycle helpers for completed normalized scans."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from database.db import (
    get_baseline,
    get_observations_by_scan,
    replace_baseline_record,
    save_baseline,
)
from database.db import get_baseline as get_legacy_baseline
from database.db import set_baseline


def create_initial_baseline(
    scan_id: int,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create the first active baseline without replacing an existing one."""
    existing = get_active_baseline(db_path)
    if existing is not None:
        return existing

    kwargs = {} if db_path is None else {"db_path": db_path}
    try:
        save_baseline(scan_id, baseline_name="initial", **kwargs)
    except (sqlite3.IntegrityError, ValueError):
        active = get_active_baseline(db_path)
        if active is not None:
            return active
        raise
    active = get_active_baseline(db_path)
    if active is None:
        raise RuntimeError("The initial baseline was saved but could not be retrieved")
    return active


def get_active_baseline(
    db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    if db_path is None:
        return get_baseline()
    return get_baseline(hostname=None, db_path=db_path)


def get_baseline_observations(
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    baseline = get_active_baseline(db_path)
    if baseline is None:
        return []
    kwargs = {} if db_path is None else {"db_path": db_path}
    return get_observations_by_scan(baseline["scan_id"], **kwargs)


def replace_baseline(
    scan_id: int,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Explicitly replace the baseline with a completed scan."""
    kwargs = {} if db_path is None else {"db_path": db_path}
    replace_baseline_record(scan_id, baseline_name="replacement", **kwargs)
    baseline = get_active_baseline(db_path)
    if baseline is None:
        raise RuntimeError("The replacement baseline could not be retrieved")
    return baseline


def compare_and_update(scan: dict) -> list[dict]:
    """Retain the legacy comparison API for existing callers."""
    from monitor.change_detector import detect_changes

    if scan.get("scan_status", "completed") != "completed":
        return []
    dns = scan.get("dns")
    if isinstance(dns, dict):
        record_types = dns.get("record_types")
        if isinstance(record_types, dict) and any(
            not isinstance(record, dict)
            or record.get("status")
            not in {"RECORD_FOUND", "NO_RECORD", "DOMAIN_NOT_FOUND"}
            for record in record_types.values()
        ):
            return []
    ports = scan.get("ports")
    if isinstance(ports, dict):
        results = ports.get("results")
        if isinstance(results, dict) and any(
            not isinstance(result, dict)
            or result.get("state") not in {"OPEN", "CLOSED"}
            for result in results.values()
        ):
            return []

    previous = get_legacy_baseline(scan["hostname"])
    changes = detect_changes(previous, scan) if previous is not None else []
    set_baseline(scan["hostname"], scan)
    return changes
