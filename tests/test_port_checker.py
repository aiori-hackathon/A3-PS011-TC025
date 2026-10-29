import contextlib
import http.server
import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.port_checker import check_approved_ports, check_port, run_port_checks
from scanner.scope import load_port_scope


class PortCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.config_path = self.root / "config.json"
        self.write_config()

    def write_config(self, hosts=None):
        config = {
            "domains": ["example.com"],
            "hosts": hosts if hosts is not None else [
                {
                    "hostname": "127.0.0.1",
                    "expected_ports": [8000],
                    "allowed_ports": [8000, 8080],
                }
            ],
            "scan_interval_minutes": 60,
        }
        self.config_path.write_text(json.dumps(config), encoding="utf-8")

    def test_successful_connection_is_open(self):
        connection = unittest.mock.MagicMock()
        connection.__enter__.return_value = connection
        with patch("scanner.port_checker.socket.create_connection", return_value=connection) as connect:
            result = check_port("127.0.0.1", 8000, config_path=self.config_path)

        self.assertEqual(result["status"], "OPEN")
        self.assertEqual(result["protocol"], "TCP")
        self.assertTrue(result["scanned_at"].endswith("+00:00"))
        connect.assert_called_once_with(("127.0.0.1", 8000), timeout=2.0)

    def test_connection_refusal_and_timeout_have_distinct_statuses(self):
        cases = (
            (ConnectionRefusedError("refused"), "CONNECTION_FAILED"),
            (socket.timeout("timed out"), "TIMEOUT"),
        )
        for error, expected_status in cases:
            with self.subTest(status=expected_status), patch(
                "scanner.port_checker.socket.create_connection", side_effect=error
            ):
                result = check_port("127.0.0.1", 8000, config_path=self.config_path)

                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["error"]["type"], type(error).__name__)

    def test_host_and_port_must_be_in_approved_scope(self):
        with patch("scanner.port_checker.socket.create_connection") as connect:
            wrong_host = check_port("192.0.2.10", 8000, config_path=self.config_path)
            wrong_port = check_port("127.0.0.1", 22, config_path=self.config_path)

        self.assertEqual(wrong_host["status"], "ERROR")
        self.assertEqual(wrong_port["status"], "ERROR")
        self.assertEqual(wrong_port["error"]["type"], "PermissionError")
        connect.assert_not_called()

    def test_expected_state_and_unexpected_open_port_finding(self):
        responses = {
            8000: {"hostname": "127.0.0.1", "port": 8000, "status": "OPEN", "scanned_at": "2026-10-29T00:00:00+00:00"},
            8080: {"hostname": "127.0.0.1", "port": 8080, "status": "OPEN", "scanned_at": "2026-10-29T00:00:01+00:00"},
        }
        with patch(
            "scanner.port_checker.check_port",
            side_effect=lambda host, port, **kwargs: dict(responses[port]),
        ), patch(
            "scanner.port_checker._identify_service",
            return_value={"status": "not_attempted", "protocol": None, "evidence": "test"},
        ):
            result = check_approved_ports("127.0.0.1", config_path=self.config_path)

        self.assertEqual(result["ports"][0]["expected_state"], "OPEN")
        self.assertTrue(result["ports"][0]["expected_match"])
        self.assertEqual(result["ports"][1]["expected_state"], "CLOSED")
        self.assertFalse(result["ports"][1]["expected_match"])
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["port"], 8080)
        self.assertEqual(finding["protocol"], "TCP")
        self.assertTrue(finding["review_required"])
        self.assertIn("not by itself a vulnerability", finding["evidence"])

    def test_timeout_is_inconclusive_for_expected_state(self):
        with patch(
            "scanner.port_checker.check_port",
            return_value={"hostname": "127.0.0.1", "port": 8000, "status": "TIMEOUT", "scanned_at": "2026-10-29T00:00:00+00:00"},
        ):
            result = check_approved_ports("127.0.0.1", config_path=self.config_path)

        self.assertEqual(result["ports"][0]["status"], "TIMEOUT")
        self.assertIsNone(result["ports"][0]["expected_match"])

    def test_invalid_configuration_is_rejected(self):
        self.write_config(
            [{"hostname": "127.0.0.1", "expected_ports": [8000], "allowed_ports": ["1-100"]}]
        )
        with self.assertRaisesRegex(ValueError, "allowed_ports"):
            load_port_scope(self.config_path)

        self.write_config(
            [{"hostname": "127.0.0.1", "expected_ports": [8000], "allowed_ports": [8080]}]
        )
        with self.assertRaisesRegex(ValueError, "included in allowed_ports"):
            load_port_scope(self.config_path)

    def test_explicit_lists_cannot_expand_config_scope(self):
        result = check_approved_ports(
            "127.0.0.1",
            allowed_ports=[8000, 8080, 9000],
            expected_ports=[8000],
            config_path=self.config_path,
        )

        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["error"]["type"], "PermissionError")

    def test_run_writes_report_for_configured_hosts(self):
        report_path = self.root / "reports" / "port_report.json"
        expected = [{"hostname": "127.0.0.1", "status": "completed", "ports": [], "findings": []}]
        output = io.StringIO()
        with patch("scanner.port_checker.check_approved_ports", return_value=expected[0]), contextlib.redirect_stdout(output):
            results = run_port_checks(self.config_path, report_path)

        self.assertEqual(results, expected)
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), expected)
        self.assertEqual(json.loads(output.getvalue()), expected)

    def test_loopback_http_server_is_checked_only_when_approved(self):
        class HeadHandler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(200)
                self.end_headers()

            def log_message(self, format_string, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HeadHandler)
        self.addCleanup(server.server_close)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        self.addCleanup(server.shutdown)
        test_port = server.server_address[1]
        self.write_config(
            [{"hostname": "127.0.0.1", "expected_ports": [test_port], "allowed_ports": [test_port]}]
        )

        # Treat this explicitly approved ephemeral test port as HTTP for this test only.
        with patch("scanner.port_checker.HTTP_PORTS", {test_port}):
            result = check_approved_ports("127.0.0.1", config_path=self.config_path)

        self.assertEqual(result["ports"][0]["status"], "OPEN")
        self.assertEqual(result["ports"][0]["service_identification"]["status"], "identified")
        self.assertTrue(result["ports"][0]["service_identification"]["evidence"].startswith("HTTP/"))


if __name__ == "__main__":
    unittest.main()