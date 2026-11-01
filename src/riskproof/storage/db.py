"""SQLite persistence: connection management and schema."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    payload TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS investigations (
    finding_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_cache (
    cache_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT,
    outcome TEXT NOT NULL,
    rationale TEXT,
    details TEXT
);
CREATE TABLE IF NOT EXISTS pending_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_log(subject);
CREATE INDEX IF NOT EXISTS idx_pending_finding ON pending_actions(finding_id);
"""


class Database:
    """Thin sqlite3 wrapper. Single-process, WAL mode, explicit transactions."""

    def __init__(self, path: Path) -> None:
        path = path.expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) ON CONFLICT(key) DO NOTHING",
            (str(SCHEMA_VERSION),),
        )
        self._conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        cur = self._conn.execute(sql, params)
        self._conn.commit()
        return cur

    def executemany(self, sql: str, rows: list[tuple]) -> None:
        """Run one statement for many rows in a single transaction."""
        with self._conn:
            self._conn.executemany(sql, rows)

    def query_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self._conn.execute(sql, params).fetchone()

    def query_all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return list(self._conn.execute(sql, params).fetchall())

    def close(self) -> None:
        self._conn.close()
