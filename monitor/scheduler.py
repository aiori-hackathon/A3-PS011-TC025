"""Process-local scheduler for scans restricted to config.json scope."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from threading import Lock
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_ERROR

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_scheduler: BackgroundScheduler | None = None
_scheduler_lock = Lock()
_logger = logging.getLogger(__name__)


def _log_job_error(event: Any) -> None:
    _logger.error(
        "Scheduled authorized-scope scan failed: %s\n%s",
        event.exception,
        event.traceback,
    )


def _read_schedule(config_path: str | Path) -> tuple[bool, int]:
    path = Path(config_path)
    try:
        with path.open(encoding="utf-8") as file:
            config: Any = json.load(file)
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {path}: {error}") from error
    except OSError as error:
        raise ValueError(f"Could not read configuration file {path}: {error}") from error
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object")
    enabled = config.get("scheduled_scans_enabled", False)
    interval = config.get("scan_interval_minutes", 60)
    if not isinstance(enabled, bool):
        raise ValueError("scheduled_scans_enabled must be a boolean")
    if isinstance(interval, bool) or not isinstance(interval, int) or interval < 1:
        raise ValueError("scan_interval_minutes must be a positive integer")
    return enabled, interval


def start_scheduler(
    interval_minutes: int | None = None,
    config_path: str | Path | None = None,
) -> BackgroundScheduler | None:
    """Start one background scheduler; disabled schedules do not create an instance."""
    global _scheduler
    path = Path(config_path) if config_path is not None else PROJECT_ROOT / "config.json"
    enabled, configured_interval = _read_schedule(path)
    if interval_minutes is None:
        if not enabled:
            with _scheduler_lock:
                if _scheduler is not None and _scheduler.running:
                    _scheduler.shutdown(wait=True)
                _scheduler = None
            return None
        interval_minutes = configured_interval
    elif isinstance(interval_minutes, bool) or interval_minutes < 1:
        raise ValueError("interval_minutes must be at least 1")

    with _scheduler_lock:
        if _scheduler is not None and _scheduler.running:
            job = _scheduler.get_job("authorized-scope-scan")
            if (
                job is not None
                and job.trigger.interval.total_seconds() != interval_minutes * 60
            ):
                _scheduler.reschedule_job(
                    "authorized-scope-scan",
                    trigger="interval",
                    minutes=interval_minutes,
                )
            return _scheduler
        scheduler = BackgroundScheduler(timezone="UTC")

        def run_configured_scan() -> None:
            from monitor.scan_manager import run_full_scan

            result = run_full_scan(path, scan_source="scheduled")
            if result["scan_status"] != "completed":
                raise RuntimeError(
                    result["error_message"] or "Scheduled scan did not complete"
                )

        scheduler.add_job(
            run_configured_scan,
            "interval",
            minutes=interval_minutes,
            id="authorized-scope-scan",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        scheduler.add_listener(_log_job_error, EVENT_JOB_ERROR)
        scheduler.start()
        _scheduler = scheduler
        return scheduler


def stop_scheduler() -> None:
    global _scheduler
    with _scheduler_lock:
        if _scheduler is not None and _scheduler.running:
            _scheduler.shutdown(wait=True)
        _scheduler = None
