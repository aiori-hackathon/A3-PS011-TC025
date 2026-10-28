import json
import tempfile
import unittest
from pathlib import Path

from scanner.scope import load_scope


class ScopeTests(unittest.TestCase):
    def load_config(self, config):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        config_path = Path(temporary_directory.name) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        return load_scope(config_path)

    def test_normalizes_hostname_and_keeps_only_explicit_ports(self):
        targets = self.load_config(
            {"targets": [{"hostname": "Example.COM.", "ports": [443, 8443]}]}
        )

        self.assertEqual(targets[0].hostname, "example.com")
        self.assertEqual(targets[0].ports, (443, 8443))

    def test_rejects_port_ranges_and_invalid_ports(self):
        with self.assertRaises(ValueError):
            self.load_config({"targets": [{"hostname": "example.com", "ports": ["1-100"]}]})


if __name__ == "__main__":
    unittest.main()