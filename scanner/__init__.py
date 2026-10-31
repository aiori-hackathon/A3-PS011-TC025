"""Scoped DNS, TLS, and port checks for configured assets."""

from scanner.dns_checker import check_dns, run_dns_discovery
from scanner.port_checker import (
    check_approved_ports,
    check_port,
    check_ports,
    run_port_checks,
)
from scanner.scope import PortTarget, Target, load_port_scope, load_scope
from scanner.tls_checker import check_tls

__all__ = [
    "PortTarget",
    "Target",
    "check_approved_ports",
    "check_dns",
    "check_port",
    "check_ports",
    "run_dns_discovery",
    "run_port_checks",
    "check_tls",
    "load_port_scope",
    "load_scope",
]