"""SQLite persistence for normalized inventory and legacy dashboard data."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

DB_PATH = Path(__file__).with_name("attack_surface.db")
LEGACY_DB_PATH = Path(__file__).with_name("monitor.db")
_ASSET_TYPES = {"domain", "host"}
_SCAN_STATUSES = {
    "running",
    "completed",
    "completed_with_warnings",
    "inconclusive",
    "failed",
}
_SCAN_SOURCES = {"manual", "scheduled", "cli"}
_SCANNER_TYPES = {"DNS", "TLS", "PORT"}
_SCANNER_STATUSES = {
    "COMPLETED",
    "COMPLETED_WITH_WARNINGS",
    "FAILED",
    "SKIPPED",
    "INCONCLUSIVE",
}


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_connection(db_path: str | Path = DB_PATH) -> sqlite3.Connection:
    """Create a connection with row access and foreign-key enforcement enabled."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _migrate_scan_status_check(db_path: str | Path) -> None:
    """Expand scan statuses without discarding existing scan history or references."""
    path = Path(db_path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'scans'"
        ).fetchone()
        if row is None or "completed_with_warnings" in row[0]:
            connection.commit()
            return

        connection.execute(
            """
            CREATE TABLE scans_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_timestamp TEXT NOT NULL,
                scan_status TEXT NOT NULL
                    CHECK (scan_status IN
                    ('running', 'completed', 'completed_with_warnings',
                     'inconclusive', 'failed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT,
                scan_source TEXT NOT NULL DEFAULT 'manual'
                    CHECK (scan_source IN ('manual', 'scheduled', 'cli'))
            )
            """
        )
        connection.execute(
            """
            INSERT INTO scans_new
                (id, scan_timestamp, scan_status, started_at, completed_at,
                 error_message, scan_source)
            SELECT id, scan_timestamp, scan_status, started_at, completed_at,
                   error_message, scan_source
            FROM scans
            """
        )
        connection.execute("DROP TABLE scans")
        connection.execute("ALTER TABLE scans_new RENAME TO scans")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS scans_timestamp "
            "ON scans(scan_timestamp DESC)"
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


@contextmanager
def _transaction(db_path: str | Path) -> Generator[sqlite3.Connection, None, None]:
    connection = (
        _connect()
        if Path(db_path).resolve() == LEGACY_DB_PATH.resolve()
        else get_connection(db_path)
    )
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database(db_path: str | Path = DB_PATH) -> None:
    """Create the normalized inventory schema and preserve legacy dashboard storage."""
    path = Path(db_path)
    with _transaction(path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_type TEXT NOT NULL CHECK (asset_type IN ('domain', 'host')),
                asset_value TEXT NOT NULL,
                is_authorized INTEGER NOT NULL CHECK (is_authorized IN (0, 1)),
                created_at TEXT NOT NULL,
                UNIQUE (asset_type, asset_value)
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_timestamp TEXT NOT NULL,
                scan_status TEXT NOT NULL
                    CHECK (scan_status IN
                    ('running', 'completed', 'completed_with_warnings',
                     'inconclusive', 'failed')),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT,
                scan_source TEXT NOT NULL DEFAULT 'manual'
                    CHECK (scan_source IN ('manual', 'scheduled', 'cli'))
            );

            CREATE TABLE IF NOT EXISTS scanner_statuses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                scanner_type TEXT NOT NULL CHECK (scanner_type IN ('DNS', 'TLS', 'PORT')),
                asset_value TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN
                    ('COMPLETED', 'COMPLETED_WITH_WARNINGS', 'FAILED',
                     'SKIPPED', 'INCONCLUSIVE')),
                message TEXT,
                completed_at TEXT NOT NULL,
                UNIQUE (scan_id, scanner_type, asset_value)
            );

            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
                scanner_type TEXT NOT NULL CHECK (scanner_type IN ('DNS', 'TLS', 'PORT')),
                observation_type TEXT NOT NULL,
                observation_value TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                observed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
                baseline_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL CHECK (is_active IN (0, 1))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
                last_seen_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
                asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
                category TEXT NOT NULL,
                previous_value TEXT,
                new_value TEXT,
                detected_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                severity TEXT NOT NULL CHECK
                    (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                evidence TEXT NOT NULL,
                description TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                review_status TEXT NOT NULL CHECK
                    (review_status IN
                    ('NEW', 'RESOLVED', 'REVIEW_REQUIRED', 'CONFIRMED', 'FALSE_POSITIVE')),
                is_active INTEGER NOT NULL CHECK (is_active IN (0, 1))
            );
            CREATE TABLE IF NOT EXISTS finding_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE RESTRICT,
                review_status TEXT NOT NULL CHECK
                    (review_status IN
                    ('NEW', 'RESOLVED', 'REVIEW_REQUIRED', 'CONFIRMED', 'FALSE_POSITIVE')),
                review_note TEXT NOT NULL DEFAULT '',
                reviewed_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS observations_scan_id
                ON observations(scan_id);
            CREATE INDEX IF NOT EXISTS observations_asset_id
                ON observations(asset_id);
            CREATE INDEX IF NOT EXISTS observations_scanner_type
                ON observations(scanner_type);
            CREATE INDEX IF NOT EXISTS scanner_statuses_scan_id
                ON scanner_statuses(scan_id);
            CREATE INDEX IF NOT EXISTS scans_timestamp
                ON scans(scan_timestamp DESC);
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_baseline
                ON baselines(is_active) WHERE is_active = 1;
            CREATE INDEX IF NOT EXISTS findings_active_severity
                ON findings(is_active, severity);
            CREATE INDEX IF NOT EXISTS finding_reviews_finding
                ON finding_reviews(finding_id, id DESC);
            """
        )
        scan_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(scans)")
        }
        if "scan_source" not in scan_columns:
            connection.execute(
                """
                ALTER TABLE scans ADD COLUMN scan_source TEXT NOT NULL
                    DEFAULT 'manual'
                    CHECK (scan_source IN ('manual', 'scheduled', 'cli'))
                """
            )

    _migrate_scan_status_check(path)

    # Existing app/dashboard functionality uses this separate database and schema.
    if path.resolve() == DB_PATH.resolve():
        with _transaction(LEGACY_DB_PATH) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    result_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS scans_hostname_time
                    ON scans(hostname, scanned_at DESC);
                CREATE TABLE IF NOT EXISTS baselines (
                    hostname TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    change_json TEXT NOT NULL
                );
                """
            )


def register_asset(
    asset_type: str,
    asset_value: str,
    is_authorized: bool = True,
    db_path: str | Path = DB_PATH,
) -> int:
    """Insert or update an explicitly configured domain or host."""
    if asset_type not in _ASSET_TYPES:
        raise ValueError(f"asset_type must be one of {sorted(_ASSET_TYPES)}")
    if not isinstance(asset_value, str) or not asset_value.strip():
        raise ValueError("asset_value must be a non-empty string")
    if not isinstance(is_authorized, bool):
        raise ValueError("is_authorized must be a boolean")

    with _transaction(db_path) as connection:
        connection.execute(
            """
            INSERT INTO assets (asset_type, asset_value, is_authorized, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(asset_type, asset_value)
            DO UPDATE SET is_authorized = excluded.is_authorized
            """,
            (asset_type, asset_value.strip(), int(is_authorized), _utc_timestamp()),
        )
        row = connection.execute(
            "SELECT id FROM assets WHERE asset_type = ? AND asset_value = ?",
            (asset_type, asset_value.strip()),
        ).fetchone()
    if row is None:
        raise RuntimeError("Asset registration did not return a database row")
    return int(row["id"])


def sync_authorized_assets(
    domains: list[str],
    hosts: list[str],
    db_path: str | Path = DB_PATH,
) -> None:
    """Mark exactly the current config scope as authorized without deleting history."""
    with _transaction(db_path) as connection:
        connection.execute("UPDATE assets SET is_authorized = 0")
        for asset_type, values in (("domain", domains), ("host", hosts)):
            for value in values:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("Configured assets must be non-empty strings")
                connection.execute(
                    """
                    INSERT INTO assets (asset_type, asset_value, is_authorized, created_at)
                    VALUES (?, ?, 1, ?)
                    ON CONFLICT(asset_type, asset_value)
                    DO UPDATE SET is_authorized = 1
                    """,
                    (asset_type, value.strip(), _utc_timestamp()),
                )


def create_scan(
    scan_status: str = "running",
    db_path: str | Path = DB_PATH,
    *,
    scan_source: str = "manual",
) -> int:
    """Create a scan record and return its database ID."""
    if scan_status not in _SCAN_STATUSES:
        raise ValueError(f"scan_status must be one of {sorted(_SCAN_STATUSES)}")
    if scan_source not in _SCAN_SOURCES:
        raise ValueError(f"scan_source must be one of {sorted(_SCAN_SOURCES)}")
    timestamp = _utc_timestamp()
    completed_at = None if scan_status == "running" else timestamp
    with _transaction(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans
                (scan_timestamp, scan_status, started_at, completed_at,
                 error_message, scan_source)
            VALUES (?, ?, ?, ?, NULL, ?)
            """,
            (timestamp, scan_status, timestamp, completed_at, scan_source),
        )
        return int(cursor.lastrowid)


def update_scan_status(
    scan_id: int,
    scan_status: str,
    error_message: str | None = None,
    db_path: str | Path = DB_PATH,
) -> None:
    """Update a scan's lifecycle status, completion timestamp, and error."""
    if scan_status not in _SCAN_STATUSES:
        raise ValueError(f"scan_status must be one of {sorted(_SCAN_STATUSES)}")
    completed_at = None if scan_status == "running" else _utc_timestamp()
    if scan_status == "completed":
        error_message = None
    with _transaction(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE scans
            SET scan_status = ?, completed_at = ?, error_message = ?
            WHERE id = ?
            """,
            (scan_status, completed_at, error_message, scan_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"Scan {scan_id} does not exist")


def save_scanner_status(
    scan_id: int,
    scanner_type: str,
    asset_value: str,
    status: str,
    message: str | None = None,
    db_path: str | Path = DB_PATH,
) -> None:
    """Persist the outcome of one scanner for one authorized asset."""
    if scanner_type not in _SCANNER_TYPES:
        raise ValueError(f"scanner_type must be one of {sorted(_SCANNER_TYPES)}")
    if status not in _SCANNER_STATUSES:
        raise ValueError(f"status must be one of {sorted(_SCANNER_STATUSES)}")
    with _transaction(db_path) as connection:
        connection.execute(
            """
            INSERT INTO scanner_statuses
                (scan_id, scanner_type, asset_value, status, message, completed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, scanner_type, asset_value)
            DO UPDATE SET status = excluded.status, message = excluded.message,
                completed_at = excluded.completed_at
            """,
            (scan_id, scanner_type, asset_value, status, message, _utc_timestamp()),
        )


def get_scanner_statuses(
    scan_id: int,
    db_path: str | Path = DB_PATH,
) -> list[dict[str, Any]]:
    with _transaction(db_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM scanner_statuses
            WHERE scan_id = ?
            ORDER BY scanner_type, asset_value
            """,
            (scan_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_observation(
    scan_id: int,
    asset_id: int,
    scanner_type: str,
    observation_type: str,
    observation_value: str,
    details: dict[str, Any] | str | None = None,
    observed_at: str | None = None,
    db_path: str | Path = DB_PATH,
) -> int:
    """Save one scanner result and return the observation ID."""
    if scanner_type not in _SCANNER_TYPES:
        raise ValueError(f"scanner_type must be one of {sorted(_SCANNER_TYPES)}")
    if not observation_type:
        raise ValueError("observation_type must be a non-empty string")
    if not isinstance(observation_value, str):
        raise ValueError("observation_value must be a string")
    if details is None:
        details_json = "{}"
    elif isinstance(details, str):
        json.loads(details)
        details_json = details
    else:
        details_json = json.dumps(details, sort_keys=True)

    with _transaction(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO observations
                (scan_id, asset_id, scanner_type, observation_type,
                 observation_value, details, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                asset_id,
                scanner_type,
                observation_type,
                observation_value,
                details_json,
                observed_at or _utc_timestamp(),
            ),
        )
        return int(cursor.lastrowid)


def get_scan_history(
    limit: int = 100,
    db_path: str | Path = DB_PATH,
) -> list[dict[str, Any]]:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    with _transaction(db_path) as connection:
        rows = connection.execute(
            """
            SELECT s.*,
                (SELECT COUNT(DISTINCT o.asset_id) FROM observations AS o
                 WHERE o.scan_id = s.id) AS assets_scanned,
                (SELECT COUNT(*) FROM findings AS f
                 WHERE f.last_seen_scan_id = s.id AND f.is_active = 1)
                    AS findings_count
            FROM scans AS s
            ORDER BY s.scan_timestamp DESC, s.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_observations_by_scan(
    scan_id: int,
    db_path: str | Path = DB_PATH,
) -> list[dict[str, Any]]:
    with _transaction(db_path) as connection:
        rows = connection.execute(
            """
            SELECT o.*, a.asset_type, a.asset_value
            FROM observations AS o
            JOIN assets AS a ON a.id = o.asset_id
            WHERE o.scan_id = ?
            ORDER BY o.id
            """,
            (scan_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_latest_scan(db_path: str | Path = DB_PATH) -> dict[str, Any] | None:
    with _transaction(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM scans ORDER BY scan_timestamp DESC, id DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row is not None else None


def list_assets(db_path: str | Path = DB_PATH) -> list[dict[str, Any]]:
    with _transaction(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM assets ORDER BY asset_type, asset_value"
        ).fetchall()
    return [dict(row) for row in rows]


def save_finding(
    *,
    fingerprint: str,
    scan_id: int,
    asset_id: int,
    category: str,
    previous_value: str | None,
    new_value: str | None,
    severity: str,
    evidence: str,
    description: str,
    recommended_action: str,
    review_status: str = "NEW",
    db_path: str | Path = DB_PATH,
) -> int:
    """Insert a finding or refresh the last-seen data for an existing finding."""
    allowed_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    allowed_statuses = {
        "NEW", "RESOLVED", "REVIEW_REQUIRED", "CONFIRMED", "FALSE_POSITIVE"
    }
    if not fingerprint.strip() or not category.strip():
        raise ValueError("Finding fingerprint and category must be non-empty")
    if severity not in allowed_severities or review_status not in allowed_statuses:
        raise ValueError("Finding severity or review status is not supported")
    now = _utc_timestamp()
    with _transaction(db_path) as connection:
        existing = connection.execute(
            "SELECT id, review_status FROM findings WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if existing is None:
            cursor = connection.execute(
                """
                INSERT INTO findings
                    (fingerprint, scan_id, last_seen_scan_id, asset_id, category,
                     previous_value, new_value, detected_at, last_seen_at,
                     severity, evidence, description, recommended_action,
                     review_status, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    fingerprint, scan_id, scan_id, asset_id, category,
                    previous_value, new_value, now, now, severity, evidence,
                    description, recommended_action, review_status,
                ),
            )
            finding_id = int(cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO finding_reviews
                    (finding_id, review_status, review_note, reviewed_at)
                VALUES (?, ?, '', ?)
                """,
                (finding_id, review_status, now),
            )
            return finding_id
        connection.execute(
            """
            UPDATE findings
            SET last_seen_scan_id = ?, last_seen_at = ?, is_active = 1,
                previous_value = ?, new_value = ?, severity = ?, evidence = ?,
                description = ?, recommended_action = ?
            WHERE id = ?
            """,
            (
                scan_id, now, previous_value, new_value, severity, evidence,
                description, recommended_action, existing["id"],
            ),
        )
        return int(existing["id"])


def resolve_missing_findings(
    active_fingerprints: set[str],
    scan_id: int,
    db_path: str | Path = DB_PATH,
) -> None:
    """Mark findings absent from a successful baseline comparison as inactive."""
    now = _utc_timestamp()
    with _transaction(db_path) as connection:
        rows = connection.execute(
            "SELECT id, fingerprint, review_status FROM findings WHERE is_active = 1"
        ).fetchall()
        for row in rows:
            if row["fingerprint"] in active_fingerprints:
                continue
            status = row["review_status"]
            if status not in {"FALSE_POSITIVE", "CONFIRMED"}:
                status = "RESOLVED"
            connection.execute(
                """
                UPDATE findings SET is_active = 0, review_status = ?,
                    last_seen_scan_id = ?, last_seen_at = ?
                WHERE id = ?
                """,
                (status, scan_id, now, row["id"]),
            )
            if status == "RESOLVED":
                connection.execute(
                    """
                    INSERT INTO finding_reviews
                        (finding_id, review_status, review_note, reviewed_at)
                    VALUES (?, 'RESOLVED', 'No longer present in the latest successful comparison', ?)
                    """,
                    (row["id"], now),
                )


def get_findings(
    active_only: bool = False,
    db_path: str | Path = DB_PATH,
) -> list[dict[str, Any]]:
    query = """
        SELECT f.*, a.asset_type, a.asset_value
        FROM findings AS f
        JOIN assets AS a ON a.id = f.asset_id
    """
    if active_only:
        query += " WHERE f.is_active = 1"
    query += " ORDER BY f.detected_at DESC, f.id DESC"
    with _transaction(db_path) as connection:
        rows = connection.execute(query).fetchall()
    return [dict(row) for row in rows]


def get_finding_review_history(
    finding_id: int,
    db_path: str | Path = DB_PATH,
) -> list[dict[str, Any]]:
    with _transaction(db_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM finding_reviews
            WHERE finding_id = ? ORDER BY id DESC
            """,
            (finding_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def review_finding(
    finding_id: int,
    review_status: str,
    review_note: str = "",
    db_path: str | Path = DB_PATH,
) -> None:
    allowed_statuses = {"CONFIRMED", "FALSE_POSITIVE", "RESOLVED"}
    if review_status not in allowed_statuses:
        raise ValueError(f"review_status must be one of {sorted(allowed_statuses)}")
    if not isinstance(review_note, str):
        raise ValueError("review_note must be a string")
    now = _utc_timestamp()
    with _transaction(db_path) as connection:
        cursor = connection.execute(
            """
            UPDATE findings SET review_status = ?, is_active = ?
            WHERE id = ?
            """,
            (review_status, int(review_status != "RESOLVED"), finding_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"Finding {finding_id} does not exist")
        connection.execute(
            """
            INSERT INTO finding_reviews
                (finding_id, review_status, review_note, reviewed_at)
            VALUES (?, ?, ?, ?)
            """,
            (finding_id, review_status, review_note.strip(), now),
        )


def _insert_baseline(
    connection: sqlite3.Connection,
    scan_id: int,
    baseline_name: str,
) -> int:
    scan = connection.execute(
        "SELECT scan_status, completed_at FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    if scan is None:
        raise ValueError(f"Scan {scan_id} does not exist")
    if scan["scan_status"] != "completed" or scan["completed_at"] is None:
        raise ValueError("Only a completed scan can be saved as a baseline")
    cursor = connection.execute(
        """
        INSERT INTO baselines (scan_id, baseline_name, created_at, is_active)
        VALUES (?, ?, ?, 1)
        """,
        (scan_id, baseline_name, _utc_timestamp()),
    )
    return int(cursor.lastrowid)


def save_baseline(
    scan_id: int,
    baseline_name: str = "initial",
    db_path: str | Path = DB_PATH,
) -> int:
    """Save a completed scan as the single active baseline."""
    if not baseline_name.strip():
        raise ValueError("baseline_name must be a non-empty string")
    with _transaction(db_path) as connection:
        active = connection.execute(
            "SELECT id FROM baselines WHERE is_active = 1"
        ).fetchone()
        if active is not None:
            raise ValueError("An active baseline already exists")
        return _insert_baseline(connection, scan_id, baseline_name)


def get_baseline(
    hostname: str | None = None,
    db_path: str | Path = DB_PATH,
) -> dict[str, Any] | None:
    """Return the active normalized baseline, or a legacy host baseline by name."""
    if hostname is not None:
        with _transaction(LEGACY_DB_PATH) as connection:
            row = connection.execute(
                "SELECT result_json FROM baselines WHERE hostname = ?", (hostname,)
            ).fetchone()
        return json.loads(row["result_json"]) if row is not None else None

    with _transaction(db_path) as connection:
        row = connection.execute(
            """
            SELECT b.*, s.scan_status, s.scan_timestamp
            FROM baselines AS b
            JOIN scans AS s ON s.id = b.scan_id
            WHERE b.is_active = 1
            ORDER BY b.id DESC
            LIMIT 1
            """
        ).fetchone()
    return dict(row) if row is not None else None


def _replace_active_baseline(
    scan_id: int,
    baseline_name: str,
    db_path: str | Path,
) -> int:
    with _transaction(db_path) as connection:
        connection.execute("UPDATE baselines SET is_active = 0 WHERE is_active = 1")
        return _insert_baseline(connection, scan_id, baseline_name)


def replace_baseline_record(
    scan_id: int,
    baseline_name: str = "replacement",
    db_path: str | Path = DB_PATH,
) -> int:
    """Explicitly replace the active baseline with a completed scan."""
    if not baseline_name.strip():
        raise ValueError("baseline_name must be a non-empty string")
    return _replace_active_baseline(scan_id, baseline_name, db_path)


# Legacy persistence remains available for the existing dashboard.
def _connect() -> sqlite3.Connection:
    return get_connection(LEGACY_DB_PATH)


def save_scan(result: dict[str, Any]) -> None:
    with _transaction(LEGACY_DB_PATH) as connection:
        connection.execute(
            "INSERT INTO scans (hostname, scanned_at, result_json) VALUES (?, ?, ?)",
            (result["hostname"], result["scanned_at"], json.dumps(result)),
        )


def set_baseline(hostname: str, result: dict[str, Any]) -> None:
    with _transaction(LEGACY_DB_PATH) as connection:
        connection.execute(
            """
            INSERT INTO baselines (hostname, result_json) VALUES (?, ?)
            ON CONFLICT(hostname) DO UPDATE SET result_json = excluded.result_json
            """,
            (hostname, json.dumps(result)),
        )


def save_changes(hostname: str, detected_at: str, changes: list[dict[str, Any]]) -> None:
    with _transaction(LEGACY_DB_PATH) as connection:
        connection.executemany(
            "INSERT INTO changes (hostname, detected_at, change_json) VALUES (?, ?, ?)",
            [
                (hostname, detected_at, json.dumps(change))
                for change in changes
            ],
        )


def list_latest_scans(limit: int = 100) -> list[dict[str, Any]]:
    with _transaction(LEGACY_DB_PATH) as connection:
        rows = connection.execute(
            """
            SELECT result_json FROM scans
            WHERE id IN (SELECT MAX(id) FROM scans GROUP BY hostname)
            ORDER BY hostname LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [json.loads(row["result_json"]) for row in rows]


def list_recent_changes(limit: int = 100) -> list[dict[str, Any]]:
    with _transaction(LEGACY_DB_PATH) as connection:
        rows = connection.execute(
            """
            SELECT hostname, detected_at, change_json FROM changes
            ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "hostname": row["hostname"],
            "detected_at": row["detected_at"],
            **json.loads(row["change_json"]),
        }
        for row in rows
    ]
