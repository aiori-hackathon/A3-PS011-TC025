import hashlib
import socket
import ssl
import threading
import unittest
from unittest.mock import MagicMock, patch

from scanner.port_checker import check_ports
from scanner.tls_checker import check_tls


class PortCheckerTests(unittest.TestCase):
    @patch("scanner.port_checker.socket.create_connection")
    def test_only_requested_port_is_checked_and_open_state_is_reported(self, connect):
        connect.return_value.__enter__.return_value = MagicMock()

        result = check_ports("approved.example", (443,))

        connect.assert_called_once_with(("approved.example", 443), timeout=3.0)
        self.assertEqual(result["open"], [443])
        self.assertEqual(result["results"][443]["state"], "OPEN")
        self.assertEqual(result["results"][443]["protocol"], "TCP")
        self.assertEqual(result["results"][443]["hostname"], "approved.example")
        self.assertIsNotNone(result["results"][443]["scanned_at"])
        connect.return_value.__exit__.assert_called_once()

    @patch(
        "scanner.port_checker.socket.create_connection",
        side_effect=socket.timeout("timed out"),
    )
    def test_timeout_is_inconclusive_not_closed(self, _connect):
        result = check_ports("approved.example", (443,))

        self.assertEqual(result["closed"], [])
        self.assertEqual(
            result["results"][443]["state"], "FILTERED_OR_NO_RESPONSE"
        )
        self.assertEqual(result["results"][443]["error"]["type"], "TimeoutError")

    @patch(
        "scanner.port_checker.socket.create_connection",
        side_effect=ConnectionRefusedError("refused"),
    )
    def test_connection_refused_is_reported_as_closed(self, _connect):
        result = check_ports("approved.example", (443,))

        self.assertEqual(result["closed"], [443])
        self.assertEqual(result["results"][443]["state"], "CLOSED")

    @patch(
        "scanner.port_checker.socket.create_connection",
        side_effect=OSError("network interface failed"),
    )
    def test_unexpected_socket_error_is_reported_as_error(self, _connect):
        result = check_ports("approved.example", (443,))

        self.assertEqual(result["results"][443]["state"], "ERROR")
        self.assertEqual(
            result["results"][443]["error"]["message"], "network interface failed"
        )

    @patch(
        "scanner.port_checker.socket.create_connection",
        side_effect=RuntimeError("unexpected scanner failure"),
    )
    def test_unexpected_scanner_error_is_reported_as_error(self, _connect):
        result = check_ports("approved.example", (443,))

        self.assertEqual(result["results"][443]["state"], "ERROR")
        self.assertEqual(
            result["results"][443]["error"]["message"],
            "unexpected scanner failure",
        )

    def test_local_listening_server_is_reported_open_and_socket_is_closed(self):
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        accepted = threading.Event()
        received = []

        def receive_connection():
            connection, _ = listener.accept()
            with connection:
                received.append(connection.recv(1))
            accepted.set()

        worker = threading.Thread(target=receive_connection)
        worker.start()
        result = check_ports("127.0.0.1", (listener.getsockname()[1],))
        worker.join(timeout=3)

        self.assertTrue(accepted.is_set())
        self.assertEqual(received, [b""])
        self.assertEqual(
            result["results"][listener.getsockname()[1]]["state"], "OPEN"
        )

    def test_local_test_server_on_port_8000_is_reported_open(self):
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 8000))
        listener.listen()

        worker = threading.Thread(
            target=lambda: listener.accept()[0].close(),
            daemon=True,
        )
        worker.start()
        result = check_ports("127.0.0.1", (8000,))
        worker.join(timeout=3)

        self.assertFalse(worker.is_alive())
        self.assertEqual(result["results"][8000]["state"], "OPEN")

    def test_unused_local_port_is_reported_closed(self):
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        unused_port = reservation.getsockname()[1]
        reservation.close()

        result = check_ports("127.0.0.1", (unused_port,))

        self.assertEqual(result["results"][unused_port]["state"], "CLOSED")


class TLSCheckerTests(unittest.TestCase):
    def setUp(self):
        self.allowlisted_scope = patch(
            "scanner.tls_checker.load_config",
            return_value={
                "domains": ["approved.example"],
                "hosts": {},
                "tls_warning_days": 30,
            },
        )
        self.allowlisted_scope.start()
        self.addCleanup(self.allowlisted_scope.stop)

    @patch("scanner.tls_checker.ssl.create_default_context")
    @patch("scanner.tls_checker.socket.create_connection")
    def test_verified_certificate_identity_and_expiry_are_returned(
        self, connect, make_context
    ):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        certificate_der = b"test certificate"
        connection.getpeercert.side_effect = [
            {
                "notAfter": "Jan 01 00:00:00 2099 GMT",
                "issuer": ((("commonName", "Test CA"),),),
                "subject": ((("commonName", "approved.example"),),),
                "serialNumber": "1234",
                "subjectAltName": (("DNS", "approved.example"),),
            },
            certificate_der,
        ]
        make_context.return_value.wrap_socket.return_value = connection
        make_context.return_value.check_hostname = True
        connect.return_value.__enter__.return_value = MagicMock()

        result = check_tls("approved.example")

        self.assertTrue(result["available"])
        self.assertTrue(result["check_completed"])
        self.assertEqual(result["serial_number"], "1234")
        self.assertEqual(
            result["fingerprint_sha256"], hashlib.sha256(certificate_der).hexdigest()
        )
        make_context.assert_called_once_with()
        make_context.return_value.wrap_socket.assert_called_once()
        self.assertEqual(
            make_context.return_value.wrap_socket.call_args.kwargs["server_hostname"],
            "approved.example",
        )

    @patch("scanner.tls_checker.ssl.create_default_context")
    @patch("scanner.tls_checker.socket.create_connection")
    def test_certificate_validation_failure_is_completed_but_unavailable(
        self, connect, make_context
    ):
        raw_socket = MagicMock()
        raw_socket.__enter__.return_value = raw_socket
        connect.return_value = raw_socket
        make_context.return_value.check_hostname = True
        make_context.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "hostname mismatch"
        )

        result = check_tls("approved.example")

        self.assertFalse(result["available"])
        self.assertTrue(result["check_completed"])
        self.assertIn("hostname mismatch", result["error"])
        self.assertTrue(make_context.return_value.check_hostname)


if __name__ == "__main__":
    unittest.main()
