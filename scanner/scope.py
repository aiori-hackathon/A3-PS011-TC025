"""Load and validate explicitly configured monitoring targets."""

import json
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Target:
    hostname: str
    ports: tuple[int, ...]


@dataclass(frozen=True)
class PortTarget:
    hostname: str
    expected_ports: tuple[int, ...]
    allowed_ports: tuple[int, ...]


def load_port_scope(config_path: str | Path = "config.json") -> list[PortTarget]:
    """Load only explicitly configured hosts and individual authorized ports."""
    path = Path(config_path)
    try:
        with path.open(encoding="utf-8") as config_file:
            config = json.load(config_file)
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {path}: {error}") from error
    except OSError as error:
        raise ValueError(f"Could not read configuration file {path}: {error}") from error

    if not isinstance(config, dict) or not isinstance(config.get("hosts"), list):
        raise ValueError("config.json must contain a 'hosts' list")

    targets: list[PortTarget] = []
    seen_hosts: set[str] = set()
    for item in config["hosts"]:
        if not isinstance(item, dict):
            raise ValueError("Each configured host must be an object")
        hostname = item.get("hostname")
        if not isinstance(hostname, str) or not hostname.strip():
            raise ValueError("Each configured host needs a non-empty hostname")
        hostname = hostname.strip().rstrip(".").lower()
        try:
            hostname = ipaddress.ip_address(hostname).compressed
        except ValueError:
            validate_domains([hostname])
        if hostname in seen_hosts:
            raise ValueError(f"Duplicate configured host: {hostname}")

        port_sets = {}
        for field in ("expected_ports", "allowed_ports"):
            ports = item.get(field)
            if not isinstance(ports, list) or any(
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
                for port in ports
            ):
                raise ValueError(f"{field} for {hostname} must contain individual ports from 1 to 65535")
            if len(set(ports)) != len(ports):
                raise ValueError(f"Duplicate port configured in {field} for {hostname}")
            port_sets[field] = tuple(ports)

        expected_ports = port_sets["expected_ports"]
        allowed_ports = port_sets["allowed_ports"]
        if not set(expected_ports).issubset(allowed_ports):
            raise ValueError(f"expected_ports for {hostname} must be included in allowed_ports")
        seen_hosts.add(hostname)
        targets.append(
            PortTarget(
                hostname=hostname,
                expected_ports=expected_ports,
                allowed_ports=allowed_ports,
            )
        )

    return targets


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
    with path.open(encoding="utf-8") as config_file:
        config = json.load(config_file)

    targets = config.get("targets")
    if not isinstance(targets, list):
        raise ValueError("config.json must contain a 'targets' list")

    validated: list[Target] = []
    seen: set[str] = set()
    for item in targets:
        if not isinstance(item, dict):
            raise ValueError("Each target must be an object")
        hostname = item.get("hostname")
        ports = item.get("ports", [])
        if not isinstance(hostname, str) or not hostname.strip():
            raise ValueError("Each target needs a non-empty hostname")
        hostname = hostname.strip().rstrip(".").lower()
        if hostname in seen:
            raise ValueError(f"Duplicate target: {hostname}")
        if not isinstance(ports, list) or any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in ports
        ):
            raise ValueError(f"Ports for {hostname} must be individual integers from 1 to 65535")
        if len(set(ports)) != len(ports):
            raise ValueError(f"Duplicate port configured for {hostname}")
        seen.add(hostname)
        validated.append(Target(hostname=hostname, ports=tuple(ports)))

    return validated