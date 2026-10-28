"""Run periodic scans for the configured scope."""

from apscheduler.schedulers.blocking import BlockingScheduler

from app import scan_all


def start_scheduler(interval_minutes: int = 60) -> None:
    if interval_minutes < 1:
        raise ValueError("interval_minutes must be at least 1")
    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(scan_all, "interval", minutes=interval_minutes, id="scope-scan")
    scheduler.start()