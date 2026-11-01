"""Repositories over the SQLite schema: findings, investigations, intel cache,
audit log, and pending actions."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from pydantic import BaseModel, ValidationError

from riskproof.errors import NotFoundError
from riskproof.models.evidence import InvestigationRecord
from riskproof.models.findings import Finding
from riskproof.storage.db import Database


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.isoformat()


class FindingRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, finding: Finding) -> None:
        now = iso(utcnow())
        self._db.execute(
            "INSERT INTO findings(finding_id, source, severity, payload, ingested_at) "
            "VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(finding_id) DO UPDATE SET payload=excluded.payload, "
            "source=excluded.source, severity=excluded.severity",
            (
                finding.finding_id,
                finding.source,
                finding.severity.value,
                finding.model_dump_json(),
                now,
            ),
        )

    def save_many(self, findings: list[Finding]) -> None:
        """Upsert many findings in one transaction (bulk imports)."""
        now = iso(utcnow())
        self._db.executemany(
            "INSERT INTO findings(finding_id, source, severity, payload, ingested_at) "
            "VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(finding_id) DO UPDATE SET payload=excluded.payload, "
            "source=excluded.source, severity=excluded.severity",
            [
                (f.finding_id, f.source, f.severity.value, f.model_dump_json(), now)
                for f in findings
            ],
        )

    def get(self, finding_id: str) -> Finding:
        row = self._db.query_one("SELECT payload FROM findings WHERE finding_id = ?", (finding_id,))
        if row is None:
            raise NotFoundError(f"Finding {finding_id!r} has not been ingested.")
        try:
            return Finding.model_validate_json(row["payload"])
        except ValidationError as exc:  # pragma: no cover - corrupted row
            raise NotFoundError(f"Stored finding {finding_id!r} failed validation.") from exc

    def list_ids(self, limit: int = 200) -> list[str]:
        rows = self._db.query_all(
            "SELECT finding_id FROM findings ORDER BY ingested_at LIMIT ?", (limit,)
        )
        return [r["finding_id"] for r in rows]

    def count(self) -> int:
        row = self._db.query_one("SELECT COUNT(*) AS n FROM findings")
        return int(row["n"]) if row else 0


class InvestigationRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, record: InvestigationRecord) -> None:
        self._db.execute(
            "INSERT INTO investigations(finding_id, payload, updated_at) VALUES(?, ?, ?) "
            "ON CONFLICT(finding_id) DO UPDATE SET payload=excluded.payload, "
            "updated_at=excluded.updated_at",
            (record.finding_id, record.model_dump_json(), iso(record.updated_at)),
        )

    def get(self, finding_id: str) -> InvestigationRecord:
        record = self.find(finding_id)
        if record is None:
            raise NotFoundError(
                f"No investigation record exists for {finding_id!r}. Run investigate_finding first."
            )
        return record

    def find(self, finding_id: str) -> InvestigationRecord | None:
        """The stored record, or None if the finding was never investigated."""
        row = self._db.query_one(
            "SELECT payload FROM investigations WHERE finding_id = ?", (finding_id,)
        )
        if row is None:
            return None
        return InvestigationRecord.model_validate_json(row["payload"])


class IntelCacheRepository:
    """Generic TTL cache for external intel payloads (e.g. the KEV catalog)."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get_fresh(self, key: str, now: datetime | None = None) -> tuple[dict, datetime] | None:
        now = now or utcnow()
        row = self._db.query_one(
            "SELECT payload, expires_at FROM intel_cache WHERE cache_key = ?", (key,)
        )
        if row is None:
            return None
        expires = datetime.fromisoformat(row["expires_at"])
        if expires <= now:
            return None
        return json.loads(row["payload"]), expires

    def put(
        self, key: str, kind: str, payload: dict, fetched_at: datetime, expires_at: datetime
    ) -> None:
        self._db.execute(
            "INSERT INTO intel_cache(cache_key, kind, payload, fetched_at, expires_at) "
            "VALUES(?, ?, ?, ?, ?) ON CONFLICT(cache_key) DO UPDATE SET "
            "payload=excluded.payload, fetched_at=excluded.fetched_at, "
            "expires_at=excluded.expires_at, kind=excluded.kind",
            (key, kind, json.dumps(payload), iso(fetched_at), iso(expires_at)),
        )


class AuditLog:
    """Append-only audit trail. Never stores credentials; stores evidence refs."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def append(
        self,
        actor: str,
        action: str,
        subject: str | None,
        outcome: str,
        rationale: str | None = None,
        details: dict | None = None,
    ) -> int:
        cur = self._db.execute(
            "INSERT INTO audit_log(ts, actor, action, subject, outcome, rationale, details) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            (
                iso(utcnow()),
                actor,
                action,
                subject,
                outcome,
                rationale,
                json.dumps(details) if details else None,
            ),
        )
        return int(cur.lastrowid or 0)

    def recent(self, limit: int = 50) -> list[dict]:
        rows = self._db.query_all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        out = []
        for row in rows:
            entry = dict(row)
            if entry.get("details"):
                entry["details"] = json.loads(entry["details"])
            out.append(entry)
        return out


class PendingActionRepository:
    """Actions authorized by policy but awaiting human execution/approval."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def add(self, finding_id: str, action: str, status: str, payload: dict) -> int:
        cur = self._db.execute(
            "INSERT INTO pending_actions(created_at, finding_id, action, status, payload) "
            "VALUES(?, ?, ?, ?, ?)",
            (iso(utcnow()), finding_id, action, status, json.dumps(payload)),
        )
        return int(cur.lastrowid or 0)

    def find_open(self, finding_id: str, action: str, status: str) -> int | None:
        """Id of an existing action with this exact finding/action/status, if any.

        Lets repeated policy runs reuse an outstanding action instead of
        recording a duplicate.
        """
        row = self._db.query_one(
            "SELECT id FROM pending_actions WHERE finding_id = ? AND action = ? AND status = ? "
            "ORDER BY id LIMIT 1",
            (finding_id, action, status),
        )
        return int(row["id"]) if row is not None else None

    def list_open(self, finding_id: str | None = None, limit: int = 100) -> list[dict]:
        if finding_id is None:
            rows = self._db.query_all(
                "SELECT * FROM pending_actions ORDER BY id DESC LIMIT ?", (limit,)
            )
        else:
            rows = self._db.query_all(
                "SELECT * FROM pending_actions WHERE finding_id = ? ORDER BY id DESC LIMIT ?",
                (finding_id, limit),
            )
        out = []
        for row in rows:
            entry = dict(row)
            if entry.get("payload"):
                entry["payload"] = json.loads(entry["payload"])
            out.append(entry)
        return out


def make_record(finding_id: str) -> InvestigationRecord:
    """Create a fresh investigation record for a finding."""
    now = utcnow()
    return InvestigationRecord(finding_id=finding_id, created_at=now, updated_at=now)


def assert_model(model: type[BaseModel], payload: str) -> BaseModel:  # pragma: no cover
    return model.model_validate_json(payload)
