"""Check TLS certificates for explicitly authorized domains."""

import hashlib
import ipaddress
import json
import math
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

from scanner.scope import load_scope, validate_domains


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load and validate configured DNS domains, TLS hosts, and expiry threshold."""
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
    domains = validate_domains(config.get("domains"))
    hosts = (
        {target.hostname: target.ports for target in load_scope(path)}
        if "hosts" in config or "targets" in config
        else {}
    )
    warning_days = config.get("tls_warning_days", DEFAULT_WARNING_DAYS)
    if (
        isinstance(warning_days, bool)
        or not isinstance(warning_days, int)
        or warning_days < 0
    ):
        raise ValueError("tls_warning_days must be a non-negative integer")
    return {
        "domains": domains,
        "hosts": hosts,
        "tls_warning_days": warning_days,
    }


def _error_details(error: Exception) -> dict[str, str]:
    return {"type": type(error).__name__, "message": str(error) or "No additional details"}


def _verification_status(error: ssl.SSLCertVerificationError) -> str:
    verify_code = getattr(error, "verify_code", None)
    message = (getattr(error, "verify_message", None) or str(error)).lower()
    if verify_code == getattr(ssl, "CERT_HAS_EXPIRED", 10) or "expired" in message:
        return "expired_certificate"
    if verify_code == 62 or "hostname" in message or "doesn't match" in message:
        return "hostname_mismatch"
    if any(phrase in message for phrase in ("issuer", "self-signed", "unknown ca")):
        return "untrusted_certificate"
    return "certificate_verification_error"


def _base_result(hostname: str, port: int, status: str) -> dict[str, Any]:
    return {
        "hostname": hostname,
        "port": port,
        "scanned_at": _utc_timestamp(),
        "status": status,
        "available": False,
        "check_completed": True,
        "expires_at": None,
        "days_remaining": None,
        "is_expired": False,
        "is_soon_to_expire": False,
        "verification_error": None,
        "connection_error": None,
        "error": None,
        "error_type": None,
    }


def check_tls(
    hostname: str,
    port: int = 443,
    config_path: str | Path | None = None,
    warning_days: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Inspect a verified TLS certificate for one configured domain or host."""
    config = load_config(config_path)
    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("hostname must be a non-empty string")
    normalized_host = hostname.strip().rstrip(".").lower()
    try:
        normalized_host = ipaddress.ip_address(normalized_host).compressed
    except ValueError:
        normalized_host = validate_domains([normalized_host])[0]
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise ValueError("port must be an integer from 1 to 65535")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("timeout must be a positive number")
    warning_threshold = (
        config["tls_warning_days"] if warning_days is None else warning_days
    )
    if (
        isinstance(warning_threshold, bool)
        or not isinstance(warning_threshold, int)
        or warning_threshold < 0
    ):
        raise ValueError("warning_days must be a non-negative integer")

    authorized_domain = normalized_host in config["domains"] and port == 443
    authorized_host = port in config["hosts"].get(normalized_host, ())
    if not authorized_domain and not authorized_host:
        result = _base_result(normalized_host, port, "out_of_scope")
        result["check_completed"] = False
        result["error"] = "Hostname and port are not in the configured TLS scope"
        result["error_type"] = "OutOfScope"
        return result

    result = _base_result(normalized_host, port, "tls_error")
    try:
        context = ssl.create_default_context()
        with socket.create_connection(
            (normalized_host, port), timeout=timeout
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=normalized_host
            ) as connection:
                certificate = connection.getpeercert()
                has_identity = any(
                    certificate.get(field)
                    for field in ("subject", "issuer", "serialNumber", "subjectAltName")
                )
                certificate_der = (
                    connection.getpeercert(binary_form=True) if has_identity else None
                )

        not_after = certificate.get("notAfter")
        if not not_after:
            result.update(
                {
                    "status": "certificate_unavailable",
                    "error": "Certificate expiry date was not provided",
                    "error_type": "CertificateUnavailable",
                }
            )
            return result

        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_remaining = (expires_at - datetime.now(timezone.utc)).days
        is_expired = days_remaining < 0
        is_soon_to_expire = 0 <= days_remaining <= warning_threshold
        if is_expired:
            status = "expired_certificate"
        elif is_soon_to_expire:
            status = "soon_to_expire"
        else:
            status = "valid"
        result.update(
            {
                "status": status,
                "available": True,
                "expires_at": expires_at.isoformat(),
                "days_remaining": days_remaining,
                "is_expired": is_expired,
                "is_soon_to_expire": is_soon_to_expire,
                "subject": certificate.get("subject", ()),
                "issuer": certificate.get("issuer", ()),
                "serial_number": certificate.get("serialNumber"),
                "fingerprint_sha256": (
                    hashlib.sha256(certificate_der).hexdigest()
                    if isinstance(certificate_der, bytes) and certificate_der
                    else None
                ),
                "subject_alt_name": certificate.get("subjectAltName", ()),
            }
        )
        return result
    except ssl.SSLCertVerificationError as error:
        message = str(error)
        status = _verification_status(error)
        if status == "expired_certificate":
            result["is_expired"] = True
        result.update(
            {
                "status": status,
                "verification_error": _error_details(error),
                "error": message or "No additional details",
                "error_type": type(error).__name__,
            }
        )
        return result
    except ssl.SSLError as error:
        result.update(
            {
                "status": "tls_error",
                "verification_error": _error_details(error),
                "error": str(error) or "No additional details",
                "error_type": type(error).__name__,
            }
        )
        return result
    except (OSError, ValueError) as error:
        status = "timeout" if isinstance(error, TimeoutError) else "connection_error"
        result.update(
            {
                "status": status,
                "check_completed": False,
                "connection_error": _error_details(error),
                "error": str(error) or "No additional details",
                "error_type": type(error).__name__,
            }
        )
        return result


def run_tls_checks(
    config_path: str | Path | None = None,
    report_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Check all configured domains, save a JSON report, and print it."""
    config = load_config(config_path)
    results = [
        check_tls(domain, config_path=config_path) for domain in config["domains"]
    ]
    destination = (
        Path(report_path)
        if report_path is not None
        else PROJECT_ROOT / "reports" / "tls_report.json"
    )
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