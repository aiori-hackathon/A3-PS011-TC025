"""Describe changes between two normalized scan results."""


def detect_changes(previous: dict | None, current: dict) -> list[dict]:
    if previous is None:
        return []

    changes = []
    for section in ("dns", "tls", "ports"):
        old_value = previous.get(section)
        new_value = current.get(section)
        if old_value != new_value:
            changes.append({"section": section, "before": old_value, "after": new_value})
    return changes