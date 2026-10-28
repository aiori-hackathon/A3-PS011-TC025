"""Small SQLite storage layer for monitor results."""

import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("monitor.db")


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with _connect() as connection:
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


def save_scan(result: dict) -> None:
    with _connect() as connection:
        connection.execute(
            "INSERT INTO scans (hostname, scanned_at, result_json) VALUES (?, ?, ?)",
            (result["hostname"], result["scanned_at"], json.dumps(result)),
        )


def get_baseline(hostname: str) -> dict | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT result_json FROM baselines WHERE hostname = ?", (hostname,)
        ).fetchone()
    return json.loads(row["result_json"]) if row else None


def set_baseline(hostname: str, result: dict) -> None:
    with _connect() as connection:
        connection.execute(
            """INSERT INTO baselines (hostname, result_json) VALUES (?, ?)
               ON CONFLICT(hostname) DO UPDATE SET result_json = excluded.result_json""",
            (hostname, json.dumps(result)),
        )


def save_changes(hostname: str, detected_at: str, changes: list[dict]) -> None:
    with _connect() as connection:
        connection.executemany(
            "INSERT INTO changes (hostname, detected_at, change_json) VALUES (?, ?, ?)",
            [(hostname, detected_at, json.dumps(change)) for change in changes],
        )


def list_latest_scans(limit: int = 100) -> list[dict]:
    with _connect() as connection:
        rows = connection.execute(
            """SELECT result_json FROM scans
               WHERE id IN (SELECT MAX(id) FROM scans GROUP BY hostname)
               ORDER BY hostname LIMIT ?""",
            (limit,),
        ).fetchall()
    return [json.loads(row["result_json"]) for row in rows]


def list_recent_changes(limit: int = 100) -> list[dict]:
    with _connect() as connection:
        rows = connection.execute(
            """SELECT hostname, detected_at, change_json FROM changes
               ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [
        {"hostname": row["hostname"], "detected_at": row["detected_at"], **json.loads(row["change_json"])}
        for row in rows
    ]