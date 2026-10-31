"""Check TCP reachability for explicitly approved hosts and ports."""

import math
import socket
import time
from datetime import datetime, timezone
from typing import Any


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _error_details(error: Exception) -> dict[str, str]:
    return {
        "type": type(error).__name__,
        "message": str(error) or "No additional details",
    }


def check_ports(
    hostname: str, ports: tuple[int, ...], timeout: float = 3.0
) -> dict[str, Any]:
    """Attempt a TCP connection to each supplied port and retain every outcome."""
    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("hostname must be a non-empty string")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("timeout must be a positive number of seconds")

    result: dict[str, Any] = {
        "hostname": hostname,
        "protocol": "TCP",
        "open": [],
        "closed": [],
        "results": {},
    }
    for port in ports:
        started = time.perf_counter()
        state = "ERROR"
        error_details = None
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                state = "OPEN"
                result["open"].append(port)
        except (socket.timeout, TimeoutError) as error:
            state = "FILTERED_OR_NO_RESPONSE"
            error_details = _error_details(error)
        except ConnectionRefusedError as error:
            state = "CLOSED"
            result["closed"].append(port)
            error_details = _error_details(error)
        except OSError as error:
            state = "ERROR"
            error_details = _error_details(error)
        except Exception as error:
            state = "ERROR"
            error_details = _error_details(error)

        result["results"][port] = {
            "hostname": hostname,
            "port": port,
            "protocol": "TCP",
            "state": state,
            "scanned_at": _utc_timestamp(),
            "response_time_ms": round((time.perf_counter() - started) * 1000, 3),
            "error": error_details,
        }
    return result
