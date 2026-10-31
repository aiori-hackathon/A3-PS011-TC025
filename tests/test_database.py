import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from database.db import (
    create_scan,
    get_baseline,
    get_latest_scan,
    get_observations_by_scan,
    get_scan_history,
    get_scanner_statuses,
    initialize_database,
    register_asset,
    save_baseline,
    save_observation,
    update_scan_status,
)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.db_path = Path(self.temporary_directory.name) / "test.db"
        initialize_database(self.db_path)

    def create_completed_scan(self):
        scan_id = create_scan(db_path=self.db_path)
        update_scan_status(scan_id, "completed", db_path=self.db_path)
        return scan_id

    def test_initialization_creates_required_tables(self):
        connection = sqlite3.connect(self.db_path)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        finally:
            connection.close()

        self.assertTrue({"assets", "scans", "observations", "baselines"} <= tables)

    def test_initialization_migrates_scan_source_for_existing_database(self):
        legacy_path = Path(self.temporary_directory.name) / "legacy.db"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                """
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY,
                    scan_timestamp TEXT NOT NULL,
                    scan_status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_message TEXT
                )
                """
            )
            connection.execute(
                """
                INSERT INTO scans
                    (scan_timestamp, scan_status, started_at, completed_at, error_message)
                VALUES ('2026-01-01T00:00:00+00:00', 'completed',
                        '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00', NULL)
                """
            )
            connection.commit()
        finally:
            connection.close()

        initialize_database(legacy_path)

        self.assertEqual(get_scan_history(db_path=legacy_path)[0]["scan_source"], "manual")
        self.assertEqual(get_scan_history(db_path=legacy_path)[0]["id"], 1)
        inconclusive_scan = create_scan(db_path=legacy_path)
        update_scan_status(
            inconclusive_scan,
            "inconclusive",
            "TCP port did not respond",
            legacy_path,
        )
        self.assertEqual(
            get_latest_scan(legacy_path)["scan_status"],
            "inconclusive",
        )
        self.assertEqual(
            len(get_scan_history(db_path=legacy_path)),
            2,
        )

    def test_scan_status_migration_preserves_existing_observations_and_baseline(self):
        legacy_path = Path(self.temporary_directory.name) / "existing.db"
        timestamp = "2026-01-01T00:00:00+00:00"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE assets (
                    id INTEGER PRIMARY KEY,
                    asset_type TEXT NOT NULL,
                    asset_value TEXT NOT NULL,
                    is_authorized INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_timestamp TEXT NOT NULL,
                    scan_status TEXT NOT NULL
                        CHECK (scan_status IN ('running', 'completed', 'failed')),
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_message TEXT
                );
                CREATE TABLE observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id),
                    asset_id INTEGER NOT NULL REFERENCES assets(id),
                    scanner_type TEXT NOT NULL,
                    observation_type TEXT NOT NULL,
                    observation_value TEXT NOT NULL,
                    details TEXT NOT NULL,
                    observed_at TEXT NOT NULL
                );
                CREATE TABLE baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id),
                    baseline_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT INTO assets VALUES (1, 'host', '127.0.0.1', 1, ?)",
                (timestamp,),
            )
            connection.execute(
                """
                INSERT INTO scans
                    (id, scan_timestamp, scan_status, started_at, completed_at, error_message)
                VALUES (1, ?, 'completed', ?, ?, NULL)
                """,
                (timestamp, timestamp, timestamp),
            )
            connection.execute(
                """
                INSERT INTO observations
                    (scan_id, asset_id, scanner_type, observation_type,
                     observation_value, details, observed_at)
                VALUES (1, 1, 'PORT', 'PORT_STATE:8000', 'OPEN', '{}', ?)
                """,
                (timestamp,),
            )
            connection.execute(
                """
                INSERT INTO baselines
                    (scan_id, baseline_name, created_at, is_active)
                VALUES (1, 'initial', ?, 1)
                """,
                (timestamp,),
            )
            connection.commit()
        finally:
            connection.close()

        initialize_database(legacy_path)

        self.assertEqual(get_baseline(db_path=legacy_path)["scan_id"], 1)
        observations = get_observations_by_scan(1, legacy_path)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["observation_value"], "OPEN")
        self.assertEqual(len(get_scan_history(db_path=legacy_path)), 1)

    def test_approved_asset_can_be_registered(self):
        asset_id = register_asset("domain", "approved.example", db_path=self.db_path)

        self.assertGreater(asset_id, 0)
        self.assertEqual(
            register_asset("domain", "approved.example", db_path=self.db_path),
            asset_id,
        )

    def test_scan_can_be_created_and_updated(self):
        scan_id = create_scan(db_path=self.db_path)
        update_scan_status(scan_id, "completed", db_path=self.db_path)

        scan = get_latest_scan(self.db_path)
        self.assertEqual(scan["id"], scan_id)
        self.assertEqual(scan["scan_status"], "completed")
        self.assertIsNotNone(scan["completed_at"])
        self.assertIsNone(scan["error_message"])

    def test_scan_source_is_retained_in_history(self):
        create_scan(db_path=self.db_path, scan_source="scheduled")

        self.assertEqual(get_latest_scan(self.db_path)["scan_source"], "scheduled")

    def test_scanner_status_is_persisted_per_asset(self):
        scan_id = create_scan(db_path=self.db_path)
        register_asset("host", "127.0.0.1", db_path=self.db_path)

        from database.db import save_scanner_status

        save_scanner_status(
            scan_id,
            "PORT",
            "127.0.0.1",
            "INCONCLUSIVE",
            "Port 8000 timed out",
            self.db_path,
        )

        statuses = get_scanner_statuses(scan_id, self.db_path)
        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0]["status"], "INCONCLUSIVE")
        self.assertEqual(statuses[0]["message"], "Port 8000 timed out")

    def test_dns_tls_and_port_observations_are_retrievable(self):
        scan_id = self.create_completed_scan()
        asset_id = register_asset("host", "approved.example", db_path=self.db_path)
        observations = (
            ("DNS", "A", '["192.0.2.10"]'),
            ("TLS", "CERTIFICATE", '{"expires_at":"2030-01-01T00:00:00+00:00"}'),
            ("PORT", "OPEN_PORT", "443"),
        )
        for scanner_type, observation_type, value in observations:
            save_observation(
                scan_id,
                asset_id,
                scanner_type,
                observation_type,
                value,
                {"source": "test"},
                db_path=self.db_path,
            )

        rows = get_observations_by_scan(scan_id, self.db_path)
        self.assertEqual(
            [(row["scanner_type"], row["observation_type"]) for row in rows],
            [("DNS", "A"), ("TLS", "CERTIFICATE"), ("PORT", "OPEN_PORT")],
        )
        self.assertEqual(json.loads(rows[0]["details"]), {"source": "test"})

    def test_baseline_can_be_created_and_retrieved(self):
        scan_id = self.create_completed_scan()

        baseline_id = save_baseline(scan_id, db_path=self.db_path)
        baseline = get_baseline(db_path=self.db_path)

        self.assertGreater(baseline_id, 0)
        self.assertEqual(baseline["scan_id"], scan_id)
        self.assertEqual(baseline["baseline_name"], "initial")
        self.assertEqual(baseline["is_active"], 1)

    def test_second_scan_preserves_first_scan_and_baseline(self):
        first_scan_id = self.create_completed_scan()
        save_baseline(first_scan_id, db_path=self.db_path)
        second_scan_id = self.create_completed_scan()
        asset_id = register_asset("host", "approved.example", db_path=self.db_path)
        save_observation(
            second_scan_id,
            asset_id,
            "PORT",
            "OPEN_PORT",
            "8443",
            db_path=self.db_path,
        )

        self.assertEqual(get_baseline(db_path=self.db_path)["scan_id"], first_scan_id)
        self.assertEqual(len(get_scan_history(db_path=self.db_path)), 2)
        self.assertEqual(len(get_observations_by_scan(first_scan_id, self.db_path)), 0)
        self.assertEqual(len(get_observations_by_scan(second_scan_id, self.db_path)), 1)

    def test_failed_scan_cannot_become_baseline(self):
        scan_id = create_scan(db_path=self.db_path)
        update_scan_status(scan_id, "failed", "scanner failed", self.db_path)

        with self.assertRaisesRegex(ValueError, "completed scan"):
            save_baseline(scan_id, db_path=self.db_path)
        self.assertIsNone(get_baseline(db_path=self.db_path))

    def test_foreign_keys_reject_missing_scan_and_asset(self):
        scan_id = self.create_completed_scan()
        asset_id = register_asset("host", "approved.example", db_path=self.db_path)

        with self.assertRaises(sqlite3.IntegrityError):
            save_observation(
                scan_id + 100,
                asset_id,
                "DNS",
                "A",
                "[]",
                db_path=self.db_path,
            )
        with self.assertRaises(sqlite3.IntegrityError):
            save_observation(
                scan_id,
                asset_id + 100,
                "DNS",
                "A",
                "[]",
                db_path=self.db_path,
            )


if __name__ == "__main__":
    unittest.main()
