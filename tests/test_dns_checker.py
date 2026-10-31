import contextlib
import dns.exception
import dns.resolver
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scanner.dns_checker import check_dns, check_record, load_config, run_dns_discovery


class CheckRecordTests(unittest.TestCase):
    @patch("scanner.dns_checker.dns.resolver.Resolver")
    def test_successful_response_returns_answers(self, resolver_class):
        resolver_class.return_value.resolve.return_value = [
            SimpleNamespace(to_text=lambda: "192.0.2.10")
        ]

        result = check_record("example.com", "A")

        self.assertEqual(result["status"], "RECORD_FOUND")
        self.assertEqual(result["values"], ["192.0.2.10"])
        self.assertEqual(result["answers"], ["192.0.2.10"])
        self.assertIsNone(result["error"])
        resolver_class.return_value.resolve.assert_called_once_with(
            "example.com", "A", lifetime=3.0
        )

    def test_dns_errors_are_reported_by_category(self):
        cases = (
            (dns.resolver.NoAnswer(), "NO_RECORD"),
            (dns.resolver.NXDOMAIN(), "DOMAIN_NOT_FOUND"),
            (dns.exception.Timeout("timed out"), "TIMEOUT"),
            (dns.resolver.NoNameservers("no nameservers"), "DNS_ERROR"),
            (dns.exception.DNSException("DNS failure"), "DNS_ERROR"),
        )
        for error, expected_status in cases:
            with self.subTest(status=expected_status), patch(
                "scanner.dns_checker.dns.resolver.Resolver"
            ) as resolver_class:
                resolver_class.return_value.resolve.side_effect = error

                result = check_record("example.com", "AAAA")

                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["values"], [])
                self.assertEqual(result["answers"], [])
                self.assertEqual(result["error"]["type"], type(error).__name__)


class DnsDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

    def write_config(self, content):
        config_path = self.root / "config.json"
        config_path.write_text(content, encoding="utf-8")
        return config_path

    def test_config_rejects_malformed_json_and_invalid_domains(self):
        malformed_path = self.write_config('{"domains": [')
        with self.assertRaisesRegex(ValueError, "Invalid JSON"):
            load_config(malformed_path)

        invalid_path = self.write_config('{"domains": ["bad domain"]}')
        with self.assertRaisesRegex(ValueError, "Invalid domain"):
            load_config(invalid_path)

    def test_config_reads_multiple_authorized_domains(self):
        config_path = self.write_config(
            '{"domains": ["Example.com.", "status.example.org"]}'
        )

        self.assertEqual(
            load_config(config_path), ["example.com", "status.example.org"]
        )

    @patch("scanner.dns_checker.check_record")
    def test_checks_each_record_type_and_uses_utc_timestamp(self, check_record_mock):
        check_record_mock.side_effect = lambda domain, record_type: {
            "status": "NO_RECORD",
            "values": [],
            "answers": [],
            "error": {"type": "NoAnswer", "message": "no answer"},
        }

        result = check_dns("example.com")

        self.assertEqual(set(result["record_types"]), {"A", "AAAA", "CNAME"})
        self.assertTrue(result["scanned_at"].endswith("+00:00"))
        self.assertEqual(check_record_mock.call_count, 3)
        for record_type, record_result in result["record_types"].items():
            self.assertEqual(record_result["domain"], "example.com")
            self.assertEqual(record_result["record_type"], record_type)
            self.assertEqual(record_result["scanned_at"], result["scanned_at"])
            self.assertEqual(record_result["status"], "NO_RECORD")
            self.assertEqual(record_result["values"], [])

    @patch("scanner.dns_checker.check_dns")
    def test_writes_report_prints_summary_and_continues_domains(self, check_dns_mock):
        config_path = self.write_config(
            '{"domains": ["first.example", "second.example"]}'
        )
        report_path = self.root / "reports" / "dns_report.json"
        check_dns_mock.side_effect = [
            {"domain": "first.example", "record_types": {}},
            {"domain": "second.example", "record_types": {}},
        ]
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            results = run_dns_discovery(config_path, report_path)

        self.assertEqual(len(results), 2)
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), results)
        self.assertIn("DNS discovery summary", output.getvalue())
        self.assertIn("first.example", output.getvalue())
        self.assertIn("second.example", output.getvalue())
        self.assertEqual(check_dns_mock.call_count, 2)

    @patch("scanner.dns_checker.check_record")
    def test_one_record_failure_does_not_skip_later_types(self, check_record_mock):
        check_record_mock.side_effect = [RuntimeError("unexpected"), {
            "status": "RECORD_FOUND",
            "values": ["2001:db8::1"],
            "answers": ["2001:db8::1"],
            "error": None,
        }, {
            "status": "NO_RECORD", "values": [], "answers": [], "error": None
        }]

        result = check_dns("example.com")

        self.assertEqual(result["record_types"]["A"]["status"], "DNS_ERROR")
        self.assertEqual(result["record_types"]["AAAA"]["status"], "RECORD_FOUND")
        self.assertEqual(result["record_types"]["CNAME"]["status"], "NO_RECORD")


if __name__ == "__main__":
    unittest.main()