"""Inspect the certificate presented by a hostname on its HTTPS port."""

import hashlib
import socket
import ssl
from datetime import datetime, timezone


def check_tls(hostname: str, port: int = 443, timeout: float = 3.0) -> dict:
    context = ssl.create_default_context()
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