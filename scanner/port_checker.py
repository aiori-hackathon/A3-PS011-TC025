"""Check connectivity only on ports explicitly listed for a target."""

import socket


def check_ports(hostname: str, ports: tuple[int, ...], timeout: float = 2.0) -> dict:
    result = {"open": [], "closed": []}
    for port in ports:
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                result["open"].append(port)
        except OSError:
            result["closed"].append(port)
    return result