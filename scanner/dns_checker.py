"""Discover configured DNS records and save a readable JSON report."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver

DNS_QUERY_TIMEOUT = 3.0
RECORD_TYPES = ("A", "AAAA", "CNAME")
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Add the project root when this file is run directly instead of as a module.
if __package__ in (None, ""):
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scope import validate_domains


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config(config_path: str | Path | None = None) -> list[str]:
    """Read and validate only the authorized domains from config.json."""
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
    return validate_domains(config.get("domains"))


def _error_details(error: Exception) -> dict[str, str]:
    return {"type": type(error).__name__, "message": str(error) or "No additional details"}


def check_record(domain: str, record_type: str) -> dict[str, Any]:
    """Query one record type and return its status, values, and any error."""
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(domain, record_type, lifetime=DNS_QUERY_TIMEOUT)
        values = sorted({item.to_text() for item in answer})
        return {
            "status": "RECORD_FOUND",
            "values": values,
            # Keep the older key available to callers that used the original report.
            "answers": values,
            "error": None,
        }
    except dns.resolver.NXDOMAIN as error:
        status = "DOMAIN_NOT_FOUND"
        error_details = _error_details(error)
    except dns.resolver.NoAnswer as error:
        status = "NO_RECORD"
        error_details = _error_details(error)
    except dns.exception.Timeout as error:
        status = "TIMEOUT"
        error_details = _error_details(error)
    except dns.resolver.NoNameservers as error:
        status = "DNS_ERROR"
        error_details = _error_details(error)
    except dns.exception.DNSException as error:
        status = "DNS_ERROR"
        error_details = _error_details(error)
    except OSError as error:
        status = "DNS_ERROR"
        error_details = _error_details(error)

    return {"status": status, "values": [], "answers": [], "error": error_details}


def check_dns(domain: str) -> dict[str, Any]:
    """Check A, AAAA, and CNAME records independently for one domain."""
    scanned_at = _utc_timestamp()
    record_results: dict[str, dict[str, Any]] = {}
    for record_type in RECORD_TYPES:
        try:
            result = check_record(domain, record_type)
        except Exception as error:
            # Keep an unexpected per-query failure from preventing the remaining lookups.
            result = {
                "status": "DNS_ERROR",
                "values": [],
                "answers": [],
                "error": _error_details(error),
            }
        result.update(
            {
                "domain": domain,
                "scanned_at": scanned_at,
                "record_type": record_type,
                # Accept older/custom check_record implementations that return answers.
                "values": result.get("values", result.get("answers", [])),
            }
        )
        record_results[record_type] = result

    return {
        "domain": domain,
        "scanned_at": scanned_at,
        "record_types": record_results,
    }


def print_report_summary(results: list[dict[str, Any]]) -> None:
    """Print a concise summary of the DNS records found for each domain."""
    print("DNS discovery summary")
    print("=====================")
    for domain_result in results:
        print(f"\nDomain: {domain_result['domain']}")
        for record_type, record_result in domain_result["record_types"].items():
            values = record_result.get("values", [])
            value_text = ", ".join(values) if values else "none"
            print(f"  {record_type}: {record_result['status']} ({value_text})")


def run_dns_discovery(
    config_path: str | Path | None = None,
    report_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Scan every configured domain, save the report, print it, and return results."""
    domains = load_config(config_path)
    results = []
    for domain in domains:
        try:
            results.append(check_dns(domain))
        except Exception as error:
            # Continue to later authorized domains if an unexpected scan error occurs.
            results.append(
                {
                    "domain": domain,
                    "scanned_at": _utc_timestamp(),
                    "record_types": {},
                    "error": _error_details(error),
                }
            )

    destination = (
        Path(report_path)
        if report_path is not None
        else PROJECT_ROOT / "reports" / "dns_report.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    formatted_report = json.dumps(results, indent=2)
    destination.write_text(formatted_report + "\n", encoding="utf-8")
    print_report_summary(results)
    return results


if __name__ == "__main__":
    try:
        run_dns_discovery()
    except ValueError as error:
        print(f"DNS discovery configuration error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    except OSError as error:
        print(f"Could not write DNS report: {error}", file=sys.stderr)
        raise SystemExit(1) from error