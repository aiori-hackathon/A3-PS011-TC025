import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database.db import (
    create_scan,
    get_baseline,
    get_findings,
    get_finding_review_history,
    initialize_database,
    register_asset,
    review_finding,
    save_baseline,
    save_observation,
    update_scan_status,
)
from monitor.change_detector import detect_scan_changes
from monitor.scan_manager import run_full_scan


class FindingTests(unittest.TestCase):
    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.root = Path(temporary_directory.name)
        self.db_path = self.root / "test.db"
        initialize_database(self.db_path)
        self.domain_id = register_asset("domain", "approved.example", db_path=self.db_path)
        self.host_id = register_asset("host", "127.0.0.1", db_path=self.db_path)

    def create_scan(self, observations):
        scan_id = create_scan(db_path=self.db_path)
        for asset_id, scanner, kind, value, details in observations:
            save_observation(
                scan_id,
                asset_id,
                scanner,
                kind,
                value,
                details,
                db_path=self.db_path,
            )
        update_scan_status(scan_id, "completed", db_path=self.db_path)
        return scan_id

    def test_detects_dns_ip_addition_and_removal(self):
        first = self.create_scan(
            [(self.domain_id, "DNS", "A", '["192.0.2.10"]', {"status": "RECORD_FOUND"})]
        )
        save_baseline(first, db_path=self.db_path)
        current = self.create_scan(
            [(self.domain_id, "DNS", "A", '["192.0.2.20"]', {"status": "RECORD_FOUND"})]
        )

        changes = detect_scan_changes(current, self.db_path)

        self.assertEqual(
            {change["category"] for change in changes},
            {"DNS_A_ADDED", "DNS_A_REMOVED"},
        )

    def test_detects_expired_tls_certificate(self):
        scan = self.create_scan(
            [
                (
                    self.host_id,
                    "TLS",
                    "CERTIFICATE",
                    json.dumps(
                        {
                            "available": True,
                            "days_remaining": -2,
                            "expires_at": "2020-01-01T00:00:00+00:00",
                        }
                    ),
                    {"available": True},
                )
            ]
        )

        findings = detect_scan_changes(scan, self.db_path)

        self.assertEqual(findings[0]["category"], "TLS_CERTIFICATE_EXPIRED")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_detects_expired_tls_certificate_rejected_during_handshake(self):
        scan = self.create_scan(
            [
                (
                    self.host_id,
                    "TLS",
                    "TLS_RESULT",
                    json.dumps(
                        {
                            "available": False,
                            "status": "expired_certificate",
                            "is_expired": True,
                            "error": "certificate has expired",
                        }
                    ),
                    {"available": False},
                )
            ]
        )

        findings = detect_scan_changes(scan, self.db_path)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "TLS_CERTIFICATE_EXPIRED")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_detects_certificate_fingerprint_change(self):
        first = self.create_scan(
            [
                (
                    self.host_id,
                    "TLS",
                    "CERTIFICATE",
                    json.dumps(
                        {
                            "available": True,
                            "serial_number": "1",
                            "fingerprint_sha256": "old",
                            "issuer": "CA",
                            "expires_at": "2030-01-01",
                        }
                    ),
                    {},
                )
            ]
        )
        save_baseline(first, db_path=self.db_path)
        current = self.create_scan(
            [
                (
                    self.host_id,
                    "TLS",
                    "CERTIFICATE",
                    json.dumps(
                        {
                            "available": True,
                            "serial_number": "2",
                            "fingerprint_sha256": "new",
                            "issuer": "CA",
                            "expires_at": "2030-01-01",
                        }
                    ),
                    {},
                )
            ]
        )

        self.assertIn(
            "TLS_CERTIFICATE_CHANGED",
            {finding["category"] for finding in detect_scan_changes(current, self.db_path)},
        )

    def test_detects_unexpected_and_closed_ports_but_not_timeouts_as_closed(self):
        first = self.create_scan(
            [
                (
                    self.host_id,
                    "PORT",
                    "PORT_STATE:8080",
                    "CLOSED",
                    {"port": 8080, "state": "CLOSED", "expected": False},
                )
            ]
        )
        save_baseline(first, db_path=self.db_path)
        opened = self.create_scan(
            [
                (
                    self.host_id,
                    "PORT",
                    "PORT_STATE:8080",
                    "OPEN",
                    {"port": 8080, "state": "OPEN", "expected": False},
                )
            ]
        )
        categories = {
            finding["category"] for finding in detect_scan_changes(opened, self.db_path)
        }
        self.assertIn("UNEXPECTED_OPEN_PORT", categories)
        self.assertIn("PORT_STATE_CHANGED", categories)

        timed_out = self.create_scan(
            [
                (
                    self.host_id,
                    "PORT",
                    "PORT_STATE:8080",
                    "TIMEOUT",
                    {"port": 8080, "state": "TIMEOUT", "expected": False},
                )
            ]
        )
        self.assertEqual(detect_scan_changes(timed_out, self.db_path), [])

    def test_detects_open_port_becoming_closed(self):
        first = self.create_scan(
            [
                (
                    self.host_id,
                    "PORT",
                    "PORT_STATE:443",
                    "OPEN",
                    {"port": 443, "state": "OPEN", "expected": True},
                )
            ]
        )
        save_baseline(first, db_path=self.db_path)
        current = self.create_scan(
            [
                (
                    self.host_id,
                    "PORT",
                    "PORT_STATE:443",
                    "CLOSED",
                    {"port": 443, "state": "CLOSED", "expected": True},
                )
            ]
        )

        findings = detect_scan_changes(current, self.db_path)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "PORT_STATE_CHANGED")

    def test_unconfigured_cname_is_review_required_not_confirmed(self):
        scan = self.create_scan(
            [
                (
                    self.domain_id,
                    "DNS",
                    "CNAME",
                    '["unconfigured.example.net"]',
                    {"status": "RECORD_FOUND"},
                )
            ]
        )

        finding = detect_scan_changes(scan, self.db_path)[0]

        self.assertEqual(finding["category"], "POTENTIAL_DANGLING_DNS")
        self.assertEqual(finding["review_status"], "REVIEW_REQUIRED")
        self.assertIn("No lookup or ownership test was performed", finding["evidence"])

    def test_review_keeps_finding_and_records_decision_history(self):
        scan = self.create_scan([])
        asset_id = self.host_id
        from database.db import save_finding

        finding_id = save_finding(
            fingerprint="test-finding",
            scan_id=scan,
            asset_id=asset_id,
            category="TEST",
            previous_value=None,
            new_value="value",
            severity="LOW",
            evidence="test evidence",
            description="test",
            recommended_action="review",
            db_path=self.db_path,
        )
        review_finding(finding_id, "FALSE_POSITIVE", "Owner confirmed expected.", self.db_path)

        stored = get_findings(db_path=self.db_path)
        history = get_finding_review_history(finding_id, self.db_path)

        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["review_status"], "FALSE_POSITIVE")
        self.assertEqual(history[0]["review_note"], "Owner confirmed expected.")

    @patch("monitor.scan_manager.check_dns", side_effect=RuntimeError("DNS unavailable"))
    def test_failed_scan_does_not_replace_baseline_or_create_findings(self, _dns_mock):
        config_path = self.root / "config.json"
        config_path.write_text(
            json.dumps({"domains": ["approved.example"], "hosts": []}),
            encoding="utf-8",
        )
        baseline_scan = self.create_scan([])
        save_baseline(baseline_scan, db_path=self.db_path)

        result = run_full_scan(config_path, self.db_path)

        self.assertEqual(result["scan_status"], "failed")
        self.assertEqual(get_baseline(db_path=self.db_path)["scan_id"], baseline_scan)
        self.assertEqual(get_findings(db_path=self.db_path), [])


if __name__ == "__main__":
    unittest.main()
