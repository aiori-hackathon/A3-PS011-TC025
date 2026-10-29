import contextlib
import datetime
import io
import json
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.tls_checker import check_tls, load_config, run_tls_checks


class TlsCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.config_path = self.root / "config.json"
        self.write_config({"domains": ["example.com"]})

    def write_config(self, content):
        self.config_path.write_text(json.dumps(content), encoding="utf-8")

    def mock_handshake(self, not_after):
        raw_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket
        tls_socket = MagicMock()
        tls_socket.__enter__.return_value = tls_socket
        tls_socket.getpeercert.return_value = {"notAfter": not_after}
        context = MagicMock()
        context.wrap_socket.return_value = tls_socket
        return raw_socket, tls_socket, context

    def test_valid_certificate_uses_default_verification_and_sni(self):
        expiration = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90))
        not_after = expiration.strftime("%b %d %H:%M:%S %Y GMT")
        raw_socket, tls_socket, context = self.mock_handshake(not_after)

        with patch("scanner.tls_checker.ssl.create_default_context", return_value=context) as create_context, patch(
            "scanner.tls_checker.socket.create_connection", return_value=raw_socket
        ) as connect:
            result = check_tls("Example.com", config_path=self.config_path)

        self.assertEqual(result["status"], "valid")
        self.assertFalse(result["is_expired"])
        self.assertFalse(result["is_soon_to_expire"])
        self.assertIsNone(result["verification_error"])
        self.assertTrue(result["scanned_at"].endswith("+00:00"))
        create_context.assert_called_once_with()
        connect.assert_called_once_with(("example.com", 443), timeout=5.0)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="example.com")
        tls_socket.getpeercert.assert_called_once_with()

    def test_expired_certificate_is_reported(self):
        expiration = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
        raw_socket, _, context = self.mock_handshake(expiration.strftime("%b %d %H:%M:%S %Y GMT"))

        with patch("scanner.tls_checker.ssl.create_default_context", return_value=context), patch(
            "scanner.tls_checker.socket.create_connection", return_value=raw_socket
        ):
            result = check_tls("example.com", config_path=self.config_path)

        self.assertEqual(result["status"], "expired_certificate")
        self.assertTrue(result["is_expired"])
        self.assertFalse(result["is_soon_to_expire"])
        self.assertLess(result["days_remaining"], 0)

    def test_soon_to_expire_certificate_uses_configurable_threshold(self):
        self.write_config({"domains": ["example.com"], "tls_warning_days": 45})
        expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=40)
        raw_socket, _, context = self.mock_handshake(expiration.strftime("%b %d %H:%M:%S %Y GMT"))

        with patch("scanner.tls_checker.ssl.create_default_context", return_value=context), patch(
            "scanner.tls_checker.socket.create_connection", return_value=raw_socket
        ):
            result = check_tls("example.com", config_path=self.config_path)

        self.assertEqual(result["status"], "soon_to_expire")
        self.assertFalse(result["is_expired"])
        self.assertTrue(result["is_soon_to_expire"])

    def test_hostname_mismatch_is_a_verification_error(self):
        error = ssl.SSLCertVerificationError(1, "hostname mismatch")
        context = MagicMock()
        context.wrap_socket.side_effect = error
        raw_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket

        with patch("scanner.tls_checker.ssl.create_default_context", return_value=context), patch(
            "scanner.tls_checker.socket.create_connection", return_value=raw_socket
        ):
            result = check_tls("example.com", config_path=self.config_path)

        self.assertEqual(result["status"], "hostname_mismatch")
        self.assertEqual(result["verification_error"]["type"], "SSLCertVerificationError")
        self.assertIsNone(result["connection_error"])

    def test_expired_verification_failure_is_distinguished(self):
        error = ssl.SSLCertVerificationError(1, "certificate has expired")
        context = MagicMock()
        context.wrap_socket.side_effect = error
        raw_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket

        with patch("scanner.tls_checker.ssl.create_default_context", return_value=context), patch(
            "scanner.tls_checker.socket.create_connection", return_value=raw_socket
        ):
            result = check_tls("example.com", config_path=self.config_path)

        self.assertEqual(result["status"], "expired_certificate")
        self.assertTrue(result["is_expired"])

    def test_untrusted_certificate_is_distinguished(self):
        error = ssl.SSLCertVerificationError(1, "unable to get local issuer certificate")
        context = MagicMock()
        context.wrap_socket.side_effect = error
        raw_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket

        with patch("scanner.tls_checker.ssl.create_default_context", return_value=context), patch(
            "scanner.tls_checker.socket.create_connection", return_value=raw_socket
        ):
            result = check_tls("example.com", config_path=self.config_path)

        self.assertEqual(result["status"], "untrusted_certificate")
        self.assertIsNotNone(result["verification_error"])

    def test_connection_errors_and_timeouts_are_distinguished(self):
        cases = (
            (ConnectionRefusedError("connection refused"), "connection_error"),
            (socket.timeout("timed out"), "timeout"),
        )
        for error, expected_status in cases:
            with self.subTest(status=expected_status), patch(
                "scanner.tls_checker.socket.create_connection", side_effect=error
            ):
                result = check_tls("example.com", config_path=self.config_path)

                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["connection_error"]["type"], type(error).__name__)

    def test_out_of_scope_host_is_not_connected(self):
        with patch("scanner.tls_checker.socket.create_connection") as connect:
            result = check_tls("other.example", config_path=self.config_path)

        self.assertEqual(result["status"], "out_of_scope")
        connect.assert_not_called()

    def test_run_writes_report_for_authorized_domains(self):
        self.write_config({"domains": ["example.com", "status.example.org"]})
        report_path = self.root / "reports" / "tls_report.json"
        output = io.StringIO()
        expected = [
            {"hostname": "example.com", "port": 443, "status": "valid"},
            {"hostname": "status.example.org", "port": 443, "status": "timeout"},
        ]

        with patch("scanner.tls_checker.check_tls", side_effect=expected), contextlib.redirect_stdout(output):
            results = run_tls_checks(self.config_path, report_path)

        self.assertEqual(results, expected)
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), expected)
        self.assertEqual(json.loads(output.getvalue()), expected)

    def test_config_uses_default_warning_threshold(self):
        self.assertEqual(load_config(self.config_path)["tls_warning_days"], 30)


if __name__ == "__main__":
    unittest.main()