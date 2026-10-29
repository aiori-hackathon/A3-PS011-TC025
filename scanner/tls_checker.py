"""Check TLS certificates for explicitly authorized domains."""

import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WARNING_DAYS = 30
DEFAULT_TIMEOUT = 5.0

# Add the project root when this file is run directly instead of as a module.
if __package__ in (None, ""):
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scope import validate_domains


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Read configuration and validate the approved domain allowlist."""
    path = Path(config_path) if config_path is not None else PROJECT_ROOT / "config.json"
    try:
        with path.open(encoding="utf-8") as config_file:
            config = json.load(config_file)
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {path}: {error}") from error
    except OSError as error:
        raise ValueError(f"Could not read configuration file {path}: {error}") from error

    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object")
    config["domains"] = validate_domains(config.get("domains"))
    warning_days = config.get("tls_warning_days", DEFAULT_WARNING_DAYS)
    if isinstance(warning_days, bool) or not isinstance(warning_days, int) or warning_days < 0:
        raise ValueError("tls_warning_days must be a non-negative integer")
    config["tls_warning_days"] = warning_days
    return config


def _error_details(error: Exception) -> dict[str, str]:
    return {"type": type(error).__name__, "message": str(error) or "No additional details"}


def _base_result(host: str, port: int, scanned_at: str) -> dict[str, Any]:
    return {
        "hostname": host,
        "port": port,
        "scanned_at": scanned_at,
        "expires_at": None,
        "days_remaining": None,
        "is_expired": None,
        "is_soon_to_expire": None,
        "connection_error": None,
        "verification_error": None,
    }


def _verification_status(error: ssl.SSLCertVerificationError) -> str:
    """Map OpenSSL verification codes to useful report statuses."""
    verify_code = getattr(error, "verify_code", None)
    message = (getattr(error, "verify_message", None) or str(error)).lower()
    if verify_code == getattr(ssl, "CERT_HAS_EXPIRED", 10) or "expired" in message:
        return "expired_certificate"
    if verify_code == 62 or "hostname" in message or "doesn't match" in message:
        return "hostname_mismatch"
    return "untrusted_certificate"


def check_tls(
    host: str,
    port: int = 443,
    config_path: str | Path | None = None,
    warning_days: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Verify one approved host's certificate and return a structured result."""
    normalized_host = host.strip().rstrip(".").lower() if isinstance(host, str) else str(host)
    scanned_at = _utc_timestamp()
    result = _base_result(normalized_host, port, scanned_at)

    try:
        config = load_config(config_path)
        approved_domains = config["domains"]
        threshold = config["tls_warning_days"] if warning_days is None else warning_days
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
            raise ValueError("warning_days must be a non-negative integer")
        validate_domains([normalized_host])
    except ValueError as error:
        result.update(status="scope_error", connection_error=_error_details(error))
        return result

    if normalized_host not in approved_domains:
        result.update(
            status="out_of_scope",
            connection_error={"type": "ScopeError", "message": "Host is not in the approved domains list"},
        )
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((normalized_host, port), timeout=timeout) as raw_socket:
            # server_hostname preserves SNI and enables hostname verification.
            with context.wrap_socket(raw_socket, server_hostname=normalized_host) as tls_socket:
                certificate = tls_socket.getpeercert()
        expires_seconds = ssl.cert_time_to_seconds(certificate["notAfter"])
        expiry = datetime.fromtimestamp(expires_seconds, timezone.utc)
        scan_time = datetime.fromisoformat(scanned_at)
        remaining_seconds = (expiry - scan_time).total_seconds()
        expired = remaining_seconds <= 0
        days_remaining = int(remaining_seconds // 86400)
        soon = not expired and days_remaining <= threshold
        result.update(
            status="expired_certificate" if expired else "soon_to_expire" if soon else "valid",
            expires_at=expiry.isoformat(timespec="seconds"),
            days_remaining=days_remaining,
            is_expired=expired,
            is_soon_to_expire=soon,
        )
    except ssl.SSLCertVerificationError as error:
        result.update(
            status=_verification_status(error),
            verification_error=_error_details(error),
            is_expired=_verification_status(error) == "expired_certificate",
            is_soon_to_expire=False,
        )
    except (socket.timeout, TimeoutError) as error:
        result.update(status="timeout", connection_error=_error_details(error))
    except (ConnectionError, OSError) as error:
        result.update(status="connection_error", connection_error=_error_details(error))
    except ssl.SSLError as error:
        result.update(status="tls_error", connection_error=_error_details(error))
    except (KeyError, ValueError, OverflowError) as error:
        result.update(status="certificate_error", connection_error=_error_details(error))

    return result


def run_tls_checks(
    config_path: str | Path | None = None,
    report_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Check each approved domain, write reports/tls_report.json, and return results."""
    config = load_config(config_path)
    results = []
    for domain in config["domains"]:
        try:
            results.append(
                check_tls(
                    domain,
                    config_path=config_path,
                    warning_days=config["tls_warning_days"],
                )
            )
        except Exception as error:
            # A failure for one host must not prevent checks of later approved hosts.
            result = _base_result(domain, 443, _utc_timestamp())
            result.update(status="connection_error", connection_error=_error_details(error))
            results.append(result)

    destination = Path(report_path) if report_path is not None else PROJECT_ROOT / "reports" / "tls_report.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    formatted_report = json.dumps(results, indent=2)
    destination.write_text(formatted_report + "\n", encoding="utf-8")
    print(formatted_report)
    return results


if __name__ == "__main__":
    try:
        run_tls_checks()
    except ValueError as error:
        print(f"TLS configuration error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    except OSError as error:
        print(f"Could not write TLS report: {error}", file=sys.stderr)
        raise SystemExit(1) from error