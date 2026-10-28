"""Inspect the certificate presented by a hostname on its HTTPS port."""

import socket
import ssl
from datetime import datetime, timezone


def check_tls(hostname: str, port: int = 443, timeout: float = 3.0) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as connection:
                certificate = connection.getpeercert()
        not_after = certificate.get("notAfter")
        if not not_after:
            return {"available": True, "error": "Certificate expiry date was not provided"}
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_remaining = (expires_at - datetime.now(timezone.utc)).days
        return {
            "available": True,
            "subject": certificate.get("subject", ()),
            "issuer": certificate.get("issuer", ()),
            "expires_at": expires_at.isoformat(),
            "days_remaining": days_remaining,
        }
    except (OSError, ssl.SSLError, ValueError) as error:
        return {"available": False, "error": str(error)}