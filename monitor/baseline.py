"""Compare a scan with the previous saved state for its target."""

from database.db import get_baseline, set_baseline
from monitor.change_detector import detect_changes


def compare_and_update(scan: dict) -> list[dict]:
    previous = get_baseline(scan["hostname"])
    changes = detect_changes(previous, scan) if previous is not None else []
    set_baseline(scan["hostname"], scan)
    return changes