import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from database.db import (
    get_baseline,
    get_findings,
    get_observations_by_scan,
    get_scan_history,
    get_scanner_statuses,
)
from monitor.baseline import get_baseline_observations
from monitor.scan_manager import run_full_scan


class ScanManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name)
        self.config_path = root / "config.json"
        self.db_path = root / "attack_surface.db"
        self.config_path.write_text(
            json.dumps(
                {
                    "domains": ["approved.example"],
                    "hosts": [
                        {
                            "hostname": "127.0.0.1",
                            "allowed_ports": [8000],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    @staticmethod
    def dns_result(value="192.0.2.10"):
        return {
            "domain": "approved.example",
            "record_types": {
                record_type: {
                    "record_type": record_type,
                    "status": "RECORD_FOUND" if record_type == "A" else "NO_RECORD",
                    "values": [value] if record_type == "A" else [],
                    "error": None,
                }
                for record_type in ("A", "AAAA", "CNAME")
            },
        }

    @patch("monitor.scan_manager.check_ports", return_value={"open": [8000], "closed": []})
    @patch("monitor.scan_manager.check_dns")
    def test_first_successful_scan_creates_baseline(self, dns_mock, _ports_mock):
        dns_mock.return_value = self.dns_result()

        summary = run_full_scan(self.config_path, self.db_path)

        self.assertEqual(summary["scan_status"], "completed")
        self.assertTrue(summary["baseline_created"])
        baseline = get_baseline(db_path=self.db_path)
        self.assertEqual(baseline["scan_id"], summary["scan_id"])
        self.assertEqual(len(get_observations_by_scan(summary["scan_id"], self.db_path)), 4)
        self.assertEqual(len(get_baseline_observations(self.db_path)), 4)

    @patch("monitor.scan_manager.check_ports", return_value={"open": [], "closed": [8000]})
    @patch("monitor.scan_manager.check_dns")
    def test_second_scan_is_historical_and_does_not_replace_baseline(
        self, dns_mock, _ports_mock
    ):
        dns_mock.side_effect = [self.dns_result(), self.dns_result("192.0.2.11")]

        first = run_full_scan(self.config_path, self.db_path)
        second = run_full_scan(self.config_path, self.db_path)

        self.assertTrue(first["baseline_created"])
        self.assertFalse(second["baseline_created"])
        self.assertEqual(get_baseline(db_path=self.db_path)["scan_id"], first["scan_id"])
        self.assertEqual(len(get_scan_history(db_path=self.db_path)), 2)

    @patch("monitor.scan_manager.check_dns", side_effect=RuntimeError("DNS scanner crashed"))
    def test_failed_scan_does_not_create_baseline(self, _dns_mock):
        summary = run_full_scan(self.config_path, self.db_path)

        self.assertEqual(summary["scan_status"], "failed")
        self.assertIn("DNS scanner crashed", summary["error_message"])
        self.assertIsNone(get_baseline(db_path=self.db_path))

    @patch("monitor.scan_manager.check_dns")
    def test_dns_timeout_marks_scan_incomplete_and_prevents_baseline(self, dns_mock):
        timeout_result = self.dns_result()
        timeout_result["record_types"]["A"].update(
            {
                "status": "TIMEOUT",
                "values": [],
                "error": {"type": "Timeout", "message": "query timed out"},
            }
        )
        dns_mock.return_value = timeout_result

        summary = run_full_scan(self.config_path, self.db_path)

        self.assertEqual(summary["scan_status"], "inconclusive")
        self.assertIn("query timed out", summary["error_message"])
        self.assertIsNone(get_baseline(db_path=self.db_path))

    def test_dns_and_tls_results_are_saved_when_a_port_times_out(self):
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["hosts"][0]["allowed_ports"] = [443, 8000]
        config["hosts"][0]["expected_ports"] = [8000]
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        port_result = {
            "hostname": "127.0.0.1",
            "protocol": "TCP",
            "open": [443],
            "closed": [],
            "results": {
                443: {"state": "OPEN", "error": None},
                8000: {
                    "state": "FILTERED_OR_NO_RESPONSE",
                    "error": {"type": "TimeoutError", "message": "timed out"},
                },
            },
        }
        tls_result = {
            "available": True,
            "check_completed": True,
            "fingerprint_sha256": "test",
        }
        with (
            patch("monitor.scan_manager.check_dns", return_value=self.dns_result()),
            patch("monitor.scan_manager.check_ports", return_value=port_result),
            patch("monitor.scan_manager.check_tls", return_value=tls_result),
        ):
            summary = run_full_scan(self.config_path, self.db_path)

        self.assertEqual(summary["scan_status"], "inconclusive")
        observations = get_observations_by_scan(summary["scan_id"], self.db_path)
        self.assertEqual(
            sum(row["scanner_type"] == "DNS" for row in observations), 3
        )
        self.assertEqual(
            sum(row["scanner_type"] == "TLS" for row in observations), 1
        )
        port_observations = [
            row for row in observations if row["scanner_type"] == "PORT"
        ]
        self.assertEqual(len(port_observations), 2)
        timeout_observation = next(
            row for row in port_observations if "8000" in row["observation_type"]
        )
        self.assertEqual(
            timeout_observation["observation_value"],
            "FILTERED_OR_NO_RESPONSE",
        )
        statuses = {
            (row["scanner_type"], row["asset_value"]): row["status"]
            for row in get_scanner_statuses(summary["scan_id"], self.db_path)
        }
        self.assertEqual(statuses[("DNS", "approved.example")], "COMPLETED")
        self.assertEqual(statuses[("TLS", "127.0.0.1")], "COMPLETED")
        self.assertEqual(statuses[("PORT", "127.0.0.1")], "INCONCLUSIVE")
        self.assertIsNone(get_baseline(db_path=self.db_path))

    def test_configured_connection_timeout_is_passed_to_port_scanner(self):
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["connection_timeout_seconds"] = 1.25
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        with (
            patch("monitor.scan_manager.check_dns", return_value=self.dns_result()),
            patch(
                "monitor.scan_manager.check_ports",
                return_value={"open": [8000], "closed": []},
            ) as ports_mock,
        ):
            run_full_scan(self.config_path, self.db_path)

        ports_mock.assert_called_once_with(
            "127.0.0.1", (8000,), timeout=1.25
        )

    def test_port_timeout_keeps_baseline_and_creates_no_closed_port_finding(self):
        timeout_result = {
            "hostname": "127.0.0.1",
            "protocol": "TCP",
            "open": [],
            "closed": [],
            "results": {
                8000: {
                    "state": "FILTERED_OR_NO_RESPONSE",
                    "error": {"type": "TimeoutError", "message": "timed out"},
                }
            },
        }
        with (
            patch("monitor.scan_manager.check_dns", return_value=self.dns_result()),
            patch(
                "monitor.scan_manager.check_ports",
                side_effect=[
                    {"open": [8000], "closed": []},
                    timeout_result,
                ],
            ),
        ):
            first = run_full_scan(self.config_path, self.db_path)
            second = run_full_scan(self.config_path, self.db_path)

        self.assertEqual(first["scan_status"], "completed")
        self.assertEqual(second["scan_status"], "inconclusive")
        self.assertEqual(get_baseline(db_path=self.db_path)["scan_id"], first["scan_id"])
        self.assertFalse(
            any(finding["category"] == "PORT_STATE_CHANGED" for finding in get_findings(db_path=self.db_path))
        )

    def test_invalid_or_empty_authorized_scope_is_rejected_before_scan_creation(self):
        self.config_path.write_text(json.dumps({"domains": [], "hosts": []}), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "at least one"):
            run_full_scan(self.config_path, self.db_path)

        self.assertFalse(self.db_path.exists())

    def test_overlapping_full_scans_are_rejected(self):
        entered = threading.Event()
        release = threading.Event()

        def wait_for_release(*_args):
            entered.set()
            release.wait(timeout=5)
            return {"scan_status": "completed"}

        with patch("monitor.scan_manager._run_full_scan", side_effect=wait_for_release):
            worker = threading.Thread(target=run_full_scan)
            worker.start()
            try:
                self.assertTrue(entered.wait(timeout=2))
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    run_full_scan()
            finally:
                release.set()
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main()
