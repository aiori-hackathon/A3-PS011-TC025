import unittest
from unittest.mock import patch

from monitor.baseline import compare_and_update
from monitor.change_detector import detect_changes


class ChangeDetectorTests(unittest.TestCase):
    def test_reports_only_changed_sections(self):
        previous = {
            "dns": {"A": ["192.0.2.1"]},
            "tls": {"available": True},
            "ports": {"open": [443], "closed": []},
        }
        current = {
            "dns": {"A": ["192.0.2.2"]},
            "tls": {"available": True},
            "ports": {"open": [443], "closed": []},
        }

        self.assertEqual(
            detect_changes(previous, current),
            [{"section": "dns", "before": previous["dns"], "after": current["dns"]}],
        )

    def test_first_scan_has_no_changes(self):
        self.assertEqual(detect_changes(None, {"hostname": "example.com"}), [])

    def test_inconclusive_port_does_not_create_a_state_change(self):
        previous = {
            "ports": {
                "results": {8000: {"state": "OPEN"}},
                "open": [8000],
                "closed": [],
            }
        }
        current = {
            "ports": {
                "results": {
                    8000: {
                        "state": "FILTERED_OR_NO_RESPONSE",
                        "error": {"message": "timed out"},
                    }
                },
                "open": [],
                "closed": [],
            }
        }

        self.assertEqual(detect_changes(previous, current), [])

    def test_failed_dns_check_does_not_create_a_removal(self):
        previous = {
            "dns": {
                "record_types": {
                    "A": {"status": "RECORD_FOUND", "values": ["192.0.2.10"]}
                }
            }
        }
        current = {
            "dns": {
                "record_types": {
                    "A": {"status": "DNS_ERROR", "values": [], "error": "timeout"}
                }
            }
        }

        self.assertEqual(detect_changes(previous, current), [])

    @patch("monitor.baseline.set_baseline")
    @patch("monitor.baseline.get_legacy_baseline")
    def test_incomplete_legacy_scan_does_not_replace_baseline(
        self, get_baseline, set_baseline
    ):
        scan = {
            "hostname": "127.0.0.1",
            "scan_status": "inconclusive",
            "ports": {
                "results": {
                    8000: {"state": "FILTERED_OR_NO_RESPONSE"}
                }
            },
        }

        self.assertEqual(compare_and_update(scan), [])
        get_baseline.assert_not_called()
        set_baseline.assert_not_called()


if __name__ == "__main__":
    unittest.main()