import json
import tempfile
import unittest
from pathlib import Path

from monitor.scheduler import start_scheduler, stop_scheduler


class SchedulerTests(unittest.TestCase):
    def tearDown(self):
        stop_scheduler()

    def test_schedule_is_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "config.json"
            config.write_text(json.dumps({"scan_interval_minutes": 5}), encoding="utf-8")

            self.assertIsNone(start_scheduler(config_path=config))

    def test_enabled_scheduler_is_a_single_running_instance(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "scheduled_scans_enabled": True,
                        "scan_interval_minutes": 60,
                    }
                ),
                encoding="utf-8",
            )

            first = start_scheduler(config_path=config)
            second = start_scheduler(config_path=config)

            self.assertIsNotNone(first)
            self.assertIs(first, second)
            self.assertTrue(first.running)

    def test_disabling_schedule_stops_the_running_instance(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "scheduled_scans_enabled": True,
                        "scan_interval_minutes": 60,
                    }
                ),
                encoding="utf-8",
            )
            scheduler = start_scheduler(config_path=config)
            config.write_text(json.dumps({"scheduled_scans_enabled": False}), encoding="utf-8")

            self.assertIsNone(start_scheduler(config_path=config))
            self.assertFalse(scheduler.running)

    def test_schedule_interval_updates_without_creating_another_instance(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "scheduled_scans_enabled": True,
                        "scan_interval_minutes": 60,
                    }
                ),
                encoding="utf-8",
            )
            scheduler = start_scheduler(config_path=config)
            config.write_text(
                json.dumps(
                    {
                        "scheduled_scans_enabled": True,
                        "scan_interval_minutes": 120,
                    }
                ),
                encoding="utf-8",
            )

            updated = start_scheduler(config_path=config)

            self.assertIs(scheduler, updated)
            self.assertEqual(
                updated.get_job("authorized-scope-scan").trigger.interval.total_seconds(),
                7200,
            )


if __name__ == "__main__":
    unittest.main()
