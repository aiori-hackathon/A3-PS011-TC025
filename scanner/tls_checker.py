"""Check TLS certificates for explicitly authorized domains."""

import hashlib
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
        with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as connection:
                certificate = connection.getpeercert()
                certificate_der = connection.getpeercert(binary_form=True)
        not_after = certificate.get("notAfter")
        if not not_after:
                    return {
                        "available": False,
                        "error": "Certificate expiry date was not provided",
                        "error_type": "CertificateUnavailable",
                        "hostname": hostname,
                        "port": port,
                    }
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_remaining = (expires_at - datetime.now(timezone.utc)).days
        return {
            "available": True,
            "check_completed": True,
            "subject": certificate.get("subject", ()),
            "issuer": certificate.get("issuer", ()),
            "expires_at": expires_at.isoformat(),
            "days_remaining": days_remaining,
            "serial_number": certificate.get("serialNumber"),
            "fingerprint_sha256": (
                hashlib.sha256(certificate_der).hexdigest()
                if certificate_der
                else None
            ),
            "subject_alt_name": certificate.get("subjectAltName", ()),
            "hostname": hostname,
        }
    except ssl.SSLCertVerificationError as error:
        return {
            "available": False,
            "check_completed": True,
            "error": str(error),
            "error_type": type(error).__name__,
            "hostname": hostname,
            "port": port,
        }
    except ssl.SSLError as error:
        return {
            "available": False,
            "check_completed": True,
            "error": str(error),
            "error_type": type(error).__name__,
            "hostname": hostname,
            "port": port,
        }
    except (OSError, ValueError) as error:
        return {
            "available": False,
            "check_completed": False,
            "error": str(error),
            "error_type": type(error).__name__,
            "hostname": hostname,
            "port": port,
        }