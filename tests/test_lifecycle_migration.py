"""Schema v2 (finding lifecycle) migration: additive, idempotent, reversible."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from riskproof.storage.db import ROLLBACK_V2_SQL, Database

NEW_COLUMNS = {"status", "status_changed_at", "last_seen_at", "resolution_source"}

_V1_DDL = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    payload TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);
CREATE TABLE investigations (
    finding_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT,
    outcome TEXT NOT NULL,
    rationale TEXT,
    details TEXT
);
INSERT INTO meta(key, value) VALUES('schema_version', '1');
INSERT INTO findings VALUES('f1', 'tenable', 'high', '{}', '2026-01-01T00:00:00+00:00');
INSERT INTO findings VALUES('f2', 'nessus', 'low', '{}', '2026-02-01T00:00:00+00:00');
INSERT INTO investigations VALUES('f1', '{}', '2026-01-02T00:00:00+00:00');
INSERT INTO audit_log(ts, actor, action, subject, outcome)
    VALUES('2026-01-02T00:00:00+00:00', 'a', 'investigate', 'f1', 'ok');
"""


def _columns(path: Path) -> set[str]:
    conn = sqlite3.connect(str(path))
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    finally:
        conn.close()


def _make_v1(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.executescript(_V1_DDL)
    conn.commit()
    conn.close()


def _version(db: Database) -> str:
    row = db.query_one("SELECT value FROM meta WHERE key='schema_version'")
    return row["value"]


def test_new_db_has_v2_columns_and_version(tmp_path: Path) -> None:
    path = tmp_path / "a.db"
    db = Database(path)
    assert _columns(path) >= NEW_COLUMNS
    assert _version(db) == "2"
    db.close()


def test_v1_db_migrates_in_place_without_data_loss(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    _make_v1(path)
    db = Database(path)
    rows = db.query_all("SELECT * FROM findings ORDER BY finding_id")
    assert len(rows) == 2
    for row in rows:
        assert row["status"] == "open"
        assert row["last_seen_at"] == row["ingested_at"]
    assert db.query_one("SELECT COUNT(*) AS n FROM investigations")["n"] == 1
    assert db.query_one("SELECT COUNT(*) AS n FROM audit_log")["n"] == 1
    assert _version(db) == "2"
    db.close()


def test_migration_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    _make_v1(path)
    Database(path).close()
    first = _columns(path)
    db = Database(path)
    assert _columns(path) == first
    assert db.query_one("SELECT COUNT(*) AS n FROM findings")["n"] == 2
    db.close()


def test_rollback_restores_v1_shape(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    _make_v1(path)
    Database(path).close()
    conn = sqlite3.connect(str(path))
    conn.executescript(ROLLBACK_V2_SQL)
    assert not NEW_COLUMNS & {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    indexes = {r[1] for r in conn.execute("PRAGMA index_list(findings)")}
    assert "idx_findings_status" not in indexes
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1
    conn.execute("SELECT finding_id, source, severity, payload, ingested_at FROM findings")
    version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
    assert version == "1"
    conn.close()
