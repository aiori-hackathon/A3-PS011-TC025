"""Compare normalized scan observations and describe actionable differences."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any

from database.db import (
    DB_PATH,
    get_baseline,
    get_observations_by_scan,
    list_assets,
)

_DNS_USABLE = {"RECORD_FOUND", "NO_RECORD", "DOMAIN_NOT_FOUND"}


def detect_changes(previous: dict | None, current: dict) -> list[dict]:
    """Keep the original legacy comparison API available."""
    if previous is None:
        return []

    def usable(section: str, value: Any) -> bool:
        if not isinstance(value, dict):
            return True
        if section == "dns":
            records = value.get("record_types")
            return not isinstance(records, dict) or all(
                isinstance(record, dict)
                and record.get("status")
                in {"RECORD_FOUND", "NO_RECORD", "DOMAIN_NOT_FOUND"}
                for record in records.values()
            )
        if section == "tls":
            return value.get("check_completed", True) is not False
        if section == "ports":
            results = value.get("results")
            return not isinstance(results, dict) or all(
                isinstance(result, dict)
                and result.get("state") in {"OPEN", "CLOSED"}
                for result in results.values()
            )
        return True

    return [
        {"section": section, "before": previous.get(section), "after": current.get(section)}
        for section in ("dns", "tls", "ports")
        if previous.get(section) != current.get(section)
        and usable(section, current.get(section))
    ]


def _json_value(value: str | None, fallback: Any) -> Any:
    if value is None:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _finding(
    *,
    asset_id: int,
    asset_value: str,
    category: str,
    before: Any,
    after: Any,
    severity: str,
    evidence: str,
    description: str,
    recommendation: str,
    review_status: str = "NEW",
) -> dict[str, Any]:
    before_text = json.dumps(before, sort_keys=True)
    after_text = json.dumps(after, sort_keys=True)
    identity = _fingerprint(asset_value, category, before_text, after_text)
    return {
        "fingerprint": identity,
        "asset_id": asset_id,
        "category": category,
        "previous_value": before_text,
        "new_value": after_text,
        "severity": severity,
        "evidence": evidence,
        "description": description,
        "recommended_action": recommendation,
        "review_status": review_status,
    }


def _observations_by_key(observations: list[dict[str, Any]]) -> dict[tuple[int, str], dict]:
    return {
        (row["asset_id"], row["observation_type"]): row
        for row in observations
    }


def _normalized_dns_values(record_type: str, values: Any) -> list[str] | None:
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        return None
    normalized: set[str] = set()
    for value in values:
        candidate = value.strip()
        if not candidate:
            return None
        if record_type in {"A", "AAAA"}:
            try:
                candidate = ipaddress.ip_address(candidate).compressed
            except ValueError:
                return None
        elif record_type == "CNAME":
            candidate = candidate.rstrip(".").lower()
        normalized.add(candidate)
    return sorted(normalized)


def detect_scan_changes(
    scan_id: int,
    db_path: str | Path = DB_PATH,
) -> list[dict[str, Any]]:
    """Compare one completed scan to the unchanged active baseline."""
    baseline = get_baseline(db_path=db_path)
    if baseline is None or baseline["scan_id"] == scan_id:
        baseline_observations: list[dict[str, Any]] = []
    else:
        baseline_observations = get_observations_by_scan(
            baseline["scan_id"], db_path=db_path
        )
    current_observations = get_observations_by_scan(scan_id, db_path=db_path)
    old_by_key = _observations_by_key(baseline_observations)
    current_by_key = _observations_by_key(current_observations)
    findings: list[dict[str, Any]] = []
    asset_names = {
        asset["id"]: asset["asset_value"] for asset in list_assets(db_path)
    }
    authorized_ids_by_name: dict[str, set[int]] = {}
    for asset in list_assets(db_path):
        if asset["is_authorized"]:
            authorized_ids_by_name.setdefault(asset["asset_value"], set()).add(
                asset["id"]
            )

    for (asset_id, record_type), current in current_by_key.items():
        if current["scanner_type"] != "DNS":
            continue
        details = _json_value(current.get("details"), {})
        current_status = details.get("status")
        current_values = _normalized_dns_values(
            record_type, _json_value(current.get("observation_value"), [])
        )
        if current_status not in _DNS_USABLE or current_values is None:
            continue
        previous = old_by_key.get((asset_id, record_type))
        old_values: list[str] = []
        if previous is not None:
            old_details = _json_value(previous.get("details"), {})
            if old_details.get("status") not in _DNS_USABLE:
                previous = None
            else:
                normalized_old_values = _normalized_dns_values(
                    record_type, _json_value(previous.get("observation_value"), [])
                )
                if normalized_old_values is None:
                    previous = None
                else:
                    old_values = normalized_old_values
        if previous is not None and set(old_values) != set(current_values):
            removed = sorted(set(old_values) - set(current_values))
            added = sorted(set(current_values) - set(old_values))
            for value in removed:
                findings.append(
                    _finding(
                        asset_id=asset_id,
                        asset_value=asset_names[asset_id],
                        category=f"DNS_{record_type}_REMOVED",
                        before=value,
                        after=None,
                        severity="LOW",
                        evidence=f"{record_type} response changed from {old_values} to {current_values}",
                        description=f"A previously observed {record_type} value was removed.",
                        recommendation="Confirm the DNS change with the authorized DNS owner.",
                    )
                )
            for value in added:
                findings.append(
                    _finding(
                        asset_id=asset_id,
                        asset_value=asset_names[asset_id],
                        category=f"DNS_{record_type}_ADDED",
                        before=None,
                        after=value,
                        severity="LOW",
                        evidence=f"{record_type} response changed from {old_values} to {current_values}",
                        description=f"A new {record_type} value was observed.",
                        recommendation="Confirm the DNS change with the authorized DNS owner.",
                    )
                )

        if record_type == "CNAME" and current_status == "RECORD_FOUND":
            authorized_names = set(authorized_ids_by_name)
            for target in current_values:
                normalized_target = str(target).rstrip(".").lower()
                if normalized_target in authorized_names:
                    target_ids = authorized_ids_by_name[normalized_target]
                    target_statuses = {
                        row["observation_type"]: _json_value(row.get("details"), {}).get(
                            "status"
                        )
                        for (target_id, _), row in current_by_key.items()
                        if target_id in target_ids and row["scanner_type"] == "DNS"
                    }
                    is_authorized_nxdomain = all(
                        target_statuses.get(kind) == "DOMAIN_NOT_FOUND"
                        for kind in ("A", "AAAA", "CNAME")
                    )
                    if is_authorized_nxdomain:
                        findings.append(
                            _finding(
                                asset_id=asset_id,
                                asset_value=asset_names[asset_id],
                                category="POTENTIAL_DANGLING_DNS",
                                before=None,
                                after=target,
                                severity="LOW",
                                evidence=(
                                    f"CNAME target {target} is configured and returned "
                                    "NXDOMAIN for A, AAAA, and CNAME during this scan."
                                ),
                                description=(
                                    "The configured CNAME target was unresolvable in this "
                                    "scan; this remains a review lead, not a confirmed "
                                    "dangling-DNS vulnerability."
                                ),
                                recommendation=(
                                    "Ask the DNS owner to verify the target and remove or "
                                    "update the record if it is no longer intentionally used."
                                ),
                                review_status="REVIEW_REQUIRED",
                            )
                        )
                    continue
                findings.append(
                    _finding(
                        asset_id=asset_id,
                        asset_value=asset_names[asset_id],
                        category="POTENTIAL_DANGLING_DNS",
                        before=None,
                        after=target,
                        severity="LOW",
                        evidence=(
                            f"CNAME points to {target}; it is not in the approved asset list. "
                            "No lookup or ownership test was performed outside the approved scope."
                        ),
                        description=(
                            "A CNAME target is outside the configured scope and may warrant "
                            "owner review; this is not confirmation that the target is dangling."
                        ),
                        recommendation=(
                            "Ask the DNS owner to verify the target and remove or update the "
                            "record if it is no longer intentionally used."
                        ),
                        review_status="REVIEW_REQUIRED",
                    )
                )

    for (asset_id, observation_type), current in current_by_key.items():
        if current["scanner_type"] != "TLS":
            continue
        current_value = _json_value(current.get("observation_value"), {})
        if observation_type == "TLS_RESULT" or not current_value.get("available"):
            if current_value.get("is_expired") or current_value.get(
                "status"
            ) == "expired_certificate":
                findings.append(
                    _finding(
                        asset_id=asset_id,
                        asset_value=asset_names[asset_id],
                        category="TLS_CERTIFICATE_EXPIRED",
                        before=None,
                        after=current_value.get("expires_at"),
                        severity="HIGH",
                        evidence=json.dumps(current_value, sort_keys=True),
                        description="The observed TLS certificate is expired.",
                        recommendation="Renew and deploy a valid certificate for this hostname.",
                    )
                )
                continue
            error_type = current_value.get("error_type", "TLSUnavailable")
            if error_type not in {"TimeoutError", "Timeout", "socket.timeout"}:
                message = str(current_value.get("error", "")).lower()
                if "hostname" in message and "match" in message:
                    category = "TLS_HOSTNAME_MISMATCH"
                elif "certificate_verify_failed" in message or "certificate verify" in message:
                    category = "TLS_TRUST_FAILURE"
                else:
                    category = "TLS_VALIDATION_FAILURE"
                findings.append(
                    _finding(
                        asset_id=asset_id,
                        asset_value=asset_names[asset_id],
                        category=category,
                        before=None,
                        after=current_value.get("error", error_type),
                        severity="MEDIUM",
                        evidence=json.dumps(current_value, sort_keys=True),
                        description=(
                            "TLS hostname validation failed."
                            if category == "TLS_HOSTNAME_MISMATCH"
                            else "TLS certificate trust validation failed."
                            if category == "TLS_TRUST_FAILURE"
                            else "The TLS connection or certificate validation did not succeed."
                        ),
                        recommendation=(
                            "Check the certificate chain, hostname, and service availability; "
                            "do not disable certificate verification."
                        ),
                        review_status="REVIEW_REQUIRED",
                    )
                )
            continue

        days_remaining = current_value.get("days_remaining")
        if isinstance(days_remaining, int) and days_remaining < 0:
            findings.append(
                _finding(
                    asset_id=asset_id,
                    asset_value=asset_names[asset_id],
                    category="TLS_CERTIFICATE_EXPIRED",
                    before=None,
                    after=current_value.get("expires_at"),
                    severity="HIGH",
                    evidence=f"Certificate expiry {current_value.get('expires_at')}; expired.",
                    description="The observed TLS certificate is expired.",
                    recommendation="Renew and deploy a valid certificate for this hostname.",
                )
            )
        elif isinstance(days_remaining, int) and days_remaining <= 30:
            findings.append(
                _finding(
                    asset_id=asset_id,
                    asset_value=asset_names[asset_id],
                    category="TLS_CERTIFICATE_EXPIRING",
                    before=None,
                    after=current_value.get("expires_at"),
                    severity="HIGH" if days_remaining <= 7 else "MEDIUM",
                    evidence=f"Certificate expires in {days_remaining} day(s).",
                    description="The observed TLS certificate is approaching expiry.",
                    recommendation="Schedule certificate renewal before the expiry date.",
                )
            )

        previous = old_by_key.get((asset_id, observation_type))
        if previous is None:
            continue
        old_value = _json_value(previous.get("observation_value"), {})
        if not old_value.get("available"):
            continue
        changed_fields = (
            "serial_number",
            "fingerprint_sha256",
            "issuer",
            "expires_at",
        )
        differences = {
            field: [old_value.get(field), current_value.get(field)]
            for field in changed_fields
            if old_value.get(field) != current_value.get(field)
        }
        if differences:
            findings.append(
                _finding(
                    asset_id=asset_id,
                    asset_value=asset_names[asset_id],
                    category="TLS_CERTIFICATE_CHANGED",
                    before={field: pair[0] for field, pair in differences.items()},
                    after={field: pair[1] for field, pair in differences.items()},
                    severity="MEDIUM",
                    evidence=json.dumps(differences, sort_keys=True),
                    description="One or more TLS certificate identity fields changed.",
                    recommendation="Verify the certificate replacement with the service owner.",
                )
            )

    for (asset_id, observation_type), current in current_by_key.items():
        if current["scanner_type"] != "PORT" or not observation_type.startswith(
            "PORT_STATE:"
        ):
            continue
        details = _json_value(current.get("details"), {})
        state = details.get("state")
        port = details.get("port")
        if state not in {"OPEN", "CLOSED"}:
            continue
        previous = old_by_key.get((asset_id, observation_type))
        previous_details = _json_value(previous.get("details"), {}) if previous else {}
        previous_state = previous_details.get("state")
        expected = bool(details.get("expected"))
        if state == "OPEN" and not expected:
            findings.append(
                _finding(
                    asset_id=asset_id,
                    asset_value=asset_names[asset_id],
                    category="UNEXPECTED_OPEN_PORT",
                    before=previous_state,
                    after={"port": port, "state": state},
                    severity="MEDIUM",
                    evidence=f"Port {port} is open but is not in expected_ports.",
                    description="An explicitly probed, allowed port is open unexpectedly.",
                    recommendation="Confirm whether the service is intended; restrict or close it if not.",
                )
            )
        if previous_state and previous_state != state:
            findings.append(
                _finding(
                    asset_id=asset_id,
                    asset_value=asset_names[asset_id],
                    category="PORT_STATE_CHANGED",
                    before={"port": port, "state": previous_state},
                    after={"port": port, "state": state},
                    severity="MEDIUM",
                    evidence=f"Authorized TCP port {port} changed from {previous_state} to {state}.",
                    description="The state of an explicitly configured TCP port changed.",
                    recommendation="Verify the service state and confirm whether the change is intended.",
                )
            )

    return findings
