import unittest

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


if __name__ == "__main__":
    unittest.main()