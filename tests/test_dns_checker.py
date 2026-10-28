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

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["answers"], ["192.0.2.10"])
        self.assertIsNone(result["error"])
        resolver_class.return_value.resolve.assert_called_once_with(
            "example.com", "A", lifetime=3.0
        )

    def test_dns_errors_are_reported_by_category(self):
        cases = (
            (dns.resolver.NoAnswer(), "no_answer"),
            (dns.resolver.NXDOMAIN(), "nxdomain"),
            (dns.exception.Timeout("timed out"), "timeout"),
            (dns.resolver.NoNameservers("no nameservers"), "nameserver_error"),
            (dns.exception.DNSException("DNS failure"), "dns_error"),
        )
        for error, expected_status in cases:
            with self.subTest(status=expected_status), patch(
                "scanner.dns_checker.dns.resolver.Resolver"
            ) as resolver_class:
                resolver_class.return_value.resolve.side_effect = error

                result = check_record("example.com", "AAAA")

                self.assertEqual(result["status"], expected_status)
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
            "status": "no_answer",
            "answers": [],
            "error": {"type": "NoAnswer", "message": "no answer"},
        }

        result = check_dns("example.com")

        self.assertEqual(set(result["record_types"]), {"A", "AAAA", "CNAME"})
        self.assertTrue(result["scanned_at"].endswith("+00:00"))
        self.assertEqual(check_record_mock.call_count, 3)

    @patch("scanner.dns_checker.check_dns")
    def test_writes_report_prints_json_and_continues_domains(self, check_dns_mock):
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
        self.assertEqual(json.loads(output.getvalue()), results)
        self.assertEqual(check_dns_mock.call_count, 2)

    @patch("scanner.dns_checker.check_record")
    def test_one_record_failure_does_not_skip_later_types(self, check_record_mock):
        check_record_mock.side_effect = [RuntimeError("unexpected"), {
            "status": "success", "answers": ["2001:db8::1"], "error": None
        }, {
            "status": "no_answer", "answers": [], "error": None
        }]

        result = check_dns("example.com")

        self.assertEqual(result["record_types"]["A"]["status"], "unexpected_error")
        self.assertEqual(result["record_types"]["AAAA"]["status"], "success")
        self.assertEqual(result["record_types"]["CNAME"]["status"], "no_answer")


if __name__ == "__main__":
    unittest.main()