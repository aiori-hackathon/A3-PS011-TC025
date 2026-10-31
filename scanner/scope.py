"""Load and validate explicitly configured monitoring targets."""

import json
import ipaddress
import math
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Target:
    hostname: str
    ports: tuple[int, ...]
    expected_ports: tuple[int, ...] = ()
    connection_timeout_seconds: float = 3.0


def validate_domains(domains: object) -> list[str]:
    """Validate and normalize the domain names authorized in config.json."""
    if not isinstance(domains, list):
        raise ValueError("config.json must contain a 'domains' list")

    validated: list[str] = []
    seen: set[str] = set()
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    for domain in domains:
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("Each configured domain must be a non-empty string")
        domain = domain.strip().rstrip(".").lower()
        if len(domain) > 253 or any(
            not label_pattern.fullmatch(label) for label in domain.split(".")
        ):
            raise ValueError(f"Invalid domain name: {domain!r}")
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError(f"Configured domain must be a DNS name, not an IP address: {domain}")
        if domain in seen:
            raise ValueError(f"Duplicate configured domain: {domain}")
        seen.add(domain)
        validated.append(domain)

    return validated


def load_scope(config_path: str | Path = "config.json") -> list[Target]:
    path = Path(config_path)
    try:
        with path.open(encoding="utf-8") as config_file:
            config = json.load(config_file)
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {path}: {error}") from error
    except OSError as error:
        raise ValueError(f"Could not read configuration file {path}: {error}") from error
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object")
    connection_timeout = config.get("connection_timeout_seconds", 3.0)
    if (
        isinstance(connection_timeout, bool)
        or not isinstance(connection_timeout, (int, float))
        or not math.isfinite(connection_timeout)
        or connection_timeout <= 0
    ):
        raise ValueError("connection_timeout_seconds must be a positive number")

    raw_targets = config.get("targets")
    if raw_targets is None:
        raw_targets = config.get("hosts")
    if not isinstance(raw_targets, list):
        raise ValueError("config.json must contain a 'targets' or 'hosts' list")

    validated: list[Target] = []
    seen: set[str] = set()
    for item in raw_targets:
        if not isinstance(item, dict):
            raise ValueError("Each target must be an object")
        hostname = item.get("hostname")
        allowed_ports = item.get("allowed_ports", item.get("ports"))
        expected_ports = item.get("expected_ports", allowed_ports)
        if allowed_ports is None:
            allowed_ports = expected_ports
        if isinstance(allowed_ports, int) and not isinstance(allowed_ports, bool):
            allowed_ports = [allowed_ports]
        if isinstance(expected_ports, int) and not isinstance(expected_ports, bool):
            expected_ports = [expected_ports]
        if not isinstance(hostname, str) or not hostname.strip():
            raise ValueError("Each target needs a non-empty hostname")
        hostname = hostname.strip().rstrip(".").lower()
        if hostname in seen:
            raise ValueError(f"Duplicate target: {hostname}")
        for field_name, ports in (
            ("allowed_ports", allowed_ports),
            ("expected_ports", expected_ports),
        ):
            if not isinstance(ports, list) or any(
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
                for port in ports
            ):
                raise ValueError(
                    f"{field_name} for {hostname} must contain individual ports from 1 to 65535"
                )
            if len(set(ports)) != len(ports):
                raise ValueError(f"Duplicate {field_name} configured for {hostname}")
        if not set(expected_ports).issubset(allowed_ports):
            raise ValueError(
                f"Every expected port for {hostname} must also be explicitly allowed"
            )
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            validate_domains([hostname])
        seen.add(hostname)
        validated.append(
            Target(
                hostname=hostname,
                ports=tuple(allowed_ports),
                expected_ports=tuple(expected_ports),
                connection_timeout_seconds=float(connection_timeout),
            )
        )

    return validated