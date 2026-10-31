import json
import unittest
from pathlib import Path
from unittest.mock import patch

from app import scan_target
from scanner.scope import load_scope


class AppScopeTests(unittest.TestCase):
    def test_checked_in_scope_contains_no_placeholder_external_domain(self):
        project_root = Path(__file__).resolve().parent.parent
        config = json.loads((project_root / "config.json").read_text(encoding="utf-8"))

        self.assertEqual(config["domains"], [])
        self.assertEqual(
            [
                (target.hostname, target.expected_ports, target.ports)
                for target in load_scope(project_root / "config.json")
            ],
            [("127.0.0.1", (8000,), (8000,))],
        )

    @patch("app.check_dns")
    @patch("app.check_ports")
    def test_scan_target_rejects_host_not_in_config_before_network_calls(
        self, ports_mock, dns_mock
    ):
        with self.assertRaisesRegex(ValueError, "not an explicitly configured host"):
            scan_target("not-approved.invalid", [80])

        dns_mock.assert_not_called()
        ports_mock.assert_not_called()

    @patch("app.check_dns")
    @patch("app.check_ports")
    def test_scan_target_rejects_ports_outside_config_before_network_calls(
        self, ports_mock, dns_mock
    ):
        with self.assertRaisesRegex(ValueError, "explicitly allowed"):
            scan_target("127.0.0.1", [443])

        dns_mock.assert_not_called()
        ports_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
