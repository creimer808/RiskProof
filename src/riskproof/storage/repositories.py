"""Repositories over the SQLite schema: findings, investigations, intel cache,
audit log, and pending actions."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import BaseModel, ValidationError

from riskproof.errors import NotFoundError
from riskproof.models.evidence import InvestigationRecord
from riskproof.models.findings import Finding, FindingStatus
from riskproof.storage.db import Database


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass(frozen=True)
class SaveStats:
    """What a batch of saved findings changed (see FindingRepository.save_many)."""

    new: int
    updated: int
    reopened: int
    resolved: int


@dataclass(frozen=True)
class ReconcileResult:
    """Outcome (or preview) of marking findings absent from a complete export."""

    candidates: int
    in_scope_open: int
    applied: bool
    skipped_reason: str | None
    sample_ids: list[str]


_SQLITE_ID_CHUNK = 500
_RECONCILE_SAMPLE = 10

_INSERT_FINDING = (
    "INSERT INTO findings(finding_id, source, severity, payload, ingested_at, "
    "status, status_changed_at, last_seen_at, resolution_source) "
    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) "
)
_UPSERT_SIGHTING = (
    _INSERT_FINDING + "ON CONFLICT(finding_id) DO UPDATE SET payload=excluded.payload, "
    "source=excluded.source, severity=excluded.severity, "
    "last_seen_at=excluded.last_seen_at, "
    "status_changed_at=CASE WHEN findings.status != excluded.status "
    "THEN excluded.status_changed_at ELSE findings.status_changed_at END, "
    "resolution_source=excluded.resolution_source, status=excluded.status"
)
_UPSERT_PAYLOAD_ONLY = (
    _INSERT_FINDING + "ON CONFLICT(finding_id) DO UPDATE SET payload=excluded.payload, "
    "source=excluded.source, severity=excluded.severity"
)


def _incoming_status(finding: Finding) -> tuple[FindingStatus, str | None]:
    """Tenable's ``fixed`` state is authoritative; anything else is open."""
    if str((finding.raw or {}).get("state") or "").lower() == "fixed":
        return FindingStatus.RESOLVED, "tenable_fixed"
    return FindingStatus.OPEN, None


class FindingRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, finding: Finding) -> None:
        """Store a finding without recording a sighting.

        New rows start open (or resolved if Tenable reported them fixed).
        Existing rows keep their status and ``last_seen_at``: re-saving a
        stored finding, e.g. to investigate it, is not evidence the scanner
        still sees it.
        """
        self._write([finding], utcnow(), sighting=False)

    def save_many(self, findings: list[Finding], now: datetime | None = None) -> SaveStats:
        """Upsert findings seen in an import and record the sighting.

        Sets ``last_seen_at``; a finding reported ``fixed`` becomes resolved, any
        other becomes open again (counted as reopened if it was inactive).
        A first-seen finding that is already fixed counts as both new and resolved.
        """
        return self._write(findings, now or utcnow(), sighting=True)

    def _write(self, findings: list[Finding], now: datetime, *, sighting: bool) -> SaveStats:
        unique = list({f.finding_id: f for f in findings}.values())
        ids = list(dict.fromkeys(f.finding_id for f in unique))
        existing: dict[str, str] = {}
        stored_tags: dict[str, str] = {}
        for i in range(0, len(ids), _SQLITE_ID_CHUNK):
            chunk = ids[i : i + _SQLITE_ID_CHUNK]
            marks = ",".join("?" * len(chunk))
            for r in self._db.query_all(
                "SELECT finding_id, status, json_extract(payload, '$.asset.tags') AS tags "
                f"FROM findings WHERE finding_id IN ({marks})",
                tuple(chunk),
            ):
                existing[r["finding_id"]] = r["status"]
                if r["tags"] and r["tags"] != "{}":
                    stored_tags[r["finding_id"]] = r["tags"]

        ts = iso(now)
        new = updated = reopened = resolved = 0
        rows: list[tuple] = []
        for f in unique:
            if not f.asset.tags and f.finding_id in stored_tags:
                # An import whose records carry no tags must not erase tags recorded earlier.
                kept = json.loads(stored_tags[f.finding_id])
                f = f.model_copy(update={"asset": f.asset.model_copy(update={"tags": kept})})
            status, source = _incoming_status(f)
            old = existing.get(f.finding_id)
            if old is None:
                new += 1
            else:
                updated += 1
                if status == FindingStatus.OPEN and old != FindingStatus.OPEN:
                    reopened += 1
            if status == FindingStatus.RESOLVED and old != FindingStatus.RESOLVED:
                resolved += 1
            rows.append(
                (
                    f.finding_id,
                    f.source,
                    f.severity.value,
                    f.model_dump_json(),
                    ts,
                    status.value,
                    ts,
                    ts,
                    source,
                )
            )
        self._db.executemany(_UPSERT_SIGHTING if sighting else _UPSERT_PAYLOAD_ONLY, rows)
        if not sighting:
            return SaveStats(new=new, updated=updated, reopened=0, resolved=0)
        return SaveStats(new=new, updated=updated, reopened=reopened, resolved=resolved)

    def affected_asset_counts(
        self, cves: Sequence[str], plugin_ids: Sequence[str]
    ) -> dict[str, int]:
        """Distinct assets with an open finding, per CVE and per CVE-less plugin.

        CVE keys are the CVE id; plugin keys are ``plugin:<id>`` and count only
        findings that carry no CVE. Resolved and not-seen findings never count.
        Keys with no matching finding are omitted.
        """
        counts: dict[str, int] = {}
        open_status = FindingStatus.OPEN.value
        asset = "json_extract(f.payload, '$.asset.asset_id')"
        unique_cves = list(dict.fromkeys(cves))
        for i in range(0, len(unique_cves), _SQLITE_ID_CHUNK):
            chunk = unique_cves[i : i + _SQLITE_ID_CHUNK]
            marks = ",".join("?" * len(chunk))
            for r in self._db.query_all(
                f"SELECT je.value AS key, COUNT(DISTINCT {asset}) AS n "
                "FROM findings f, json_each(f.payload, '$.cve_ids') je "
                f"WHERE f.status = ? AND je.value IN ({marks}) GROUP BY je.value",
                (open_status, *chunk),
            ):
                counts[r["key"]] = int(r["n"])
        unique_plugins = list(dict.fromkeys(plugin_ids))
        for i in range(0, len(unique_plugins), _SQLITE_ID_CHUNK):
            chunk = unique_plugins[i : i + _SQLITE_ID_CHUNK]
            marks = ",".join("?" * len(chunk))
            for r in self._db.query_all(
                f"SELECT json_extract(f.payload, '$.plugin_id') AS key, "
                f"COUNT(DISTINCT {asset}) AS n FROM findings f "
                "WHERE f.status = ? AND json_array_length(f.payload, '$.cve_ids') = 0 "
                f"AND json_extract(f.payload, '$.plugin_id') IN ({marks}) GROUP BY key",
                (open_status, *chunk),
            ):
                counts[f"plugin:{r['key']}"] = int(r["n"])
        return counts

    def inactive_ids(self) -> set[str]:
        """Ids of findings that are resolved or not seen (anything but open)."""
        rows = self._db.query_all(
            "SELECT finding_id FROM findings WHERE status != ?", (FindingStatus.OPEN.value,)
        )
        return {r["finding_id"] for r in rows}

    def reconcile_unseen(
        self,
        *,
        source: str,
        severities: list[str],
        seen_before: datetime,
        apply: bool,
        max_fraction: float,
    ) -> ReconcileResult:
        """Mark open findings not seen since ``seen_before`` as ``not_seen``.

        The caller must only invoke this after a complete, in-scope export.
        Candidates are open findings of ``source`` and one of ``severities``
        with ``last_seen_at < seen_before``. Nothing is changed unless
        ``apply`` is true and the mass-vanish guard passes. Rows are never
        deleted.
        """
        if not severities:
            return ReconcileResult(0, 0, False, "no severities in scope", [])
        marks = ",".join("?" * len(severities))
        scope = f"status = ? AND source = ? AND severity IN ({marks})"
        scope_params = (FindingStatus.OPEN.value, source, *severities)
        stale = f"{scope} AND last_seen_at < ?"
        stale_params = (*scope_params, iso(seen_before))

        in_scope = self._db.query_one(
            f"SELECT COUNT(*) AS n FROM findings WHERE {scope}", scope_params
        )
        in_scope_open = int(in_scope["n"]) if in_scope else 0
        cand = self._db.query_one(f"SELECT COUNT(*) AS n FROM findings WHERE {stale}", stale_params)
        candidates = int(cand["n"]) if cand else 0
        samples = [
            r["finding_id"]
            for r in self._db.query_all(
                f"SELECT finding_id FROM findings WHERE {stale} ORDER BY finding_id LIMIT ?",
                (*stale_params, _RECONCILE_SAMPLE),
            )
        ]

        reason: str | None = None
        if in_scope_open == 0:
            reason = "no open findings in scope to reconcile"
        elif candidates / in_scope_open > max_fraction:
            reason = (
                f"mass-vanish guard: {candidates} of {in_scope_open} in-scope open findings "
                f"are missing (> {max_fraction:.0%}); the export may be incomplete"
            )
        applied = apply and reason is None and candidates > 0
        if applied:
            self._db.execute(
                "UPDATE findings SET status = ?, resolution_source = ?, status_changed_at = ? "
                f"WHERE {stale}",
                (
                    FindingStatus.NOT_SEEN.value,
                    "absent_from_export",
                    iso(utcnow()),
                    *stale_params,
                ),
            )
        return ReconcileResult(candidates, in_scope_open, applied, reason, samples)

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

    def open_ids(self) -> list[str]:
        """Ids of findings whose lifecycle status is open."""
        rows = self._db.query_all(
            "SELECT finding_id FROM findings WHERE status = ?", (FindingStatus.OPEN.value,)
        )
        return [r["finding_id"] for r in rows]

    def uninvestigated_ids(self) -> list[str]:
        """Ids of open findings that have no investigation record yet."""
        rows = self._db.query_all(
            "SELECT f.finding_id AS id FROM findings f "
            "LEFT JOIN investigations i ON i.finding_id = f.finding_id "
            "WHERE i.finding_id IS NULL AND f.status = 'open' ORDER BY f.finding_id"
        )
        return [r["id"] for r in rows]

    def uninvestigated_rollup(self, top_assets: int = 10) -> dict:
        """Counts of open findings with no investigation record, aggregated in SQL.

        Returns ``total``, ``by_severity``, ``asset_count`` and the
        ``top_assets`` (asset id, count) pairs, without loading any payloads
        into Python.
        """
        base = (
            "FROM findings f LEFT JOIN investigations i ON i.finding_id = f.finding_id "
            "WHERE i.finding_id IS NULL AND f.status = 'open'"
        )
        by_severity = {
            r["severity"]: int(r["n"])
            for r in self._db.query_all(
                f"SELECT f.severity AS severity, COUNT(*) AS n {base} GROUP BY f.severity"
            )
        }
        asset = "COALESCE(json_extract(f.payload, '$.asset.asset_id'), '(unknown)')"
        assets = self._db.query_all(
            f"SELECT {asset} AS asset, COUNT(*) AS n {base} "
            "GROUP BY asset ORDER BY n DESC, asset LIMIT ?",
            (top_assets,),
        )
        count_row = self._db.query_one(f"SELECT COUNT(DISTINCT {asset}) AS n {base}")
        return {
            "total": sum(by_severity.values()),
            "by_severity": by_severity,
            "asset_count": int(count_row["n"]) if count_row else 0,
            "top_assets": [(r["asset"], int(r["n"])) for r in assets],
        }


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

    def ids_without_greynoise(self) -> list[str]:
        """Investigated findings with CVEs whose intel has no live GreyNoise reading.

        Findings without CVEs are not listed: GreyNoise is keyed by CVE, so there is
        nothing for it to look up (their record may still carry a batch's bundle).
        """
        rows = self._db.query_all(
            "SELECT i.finding_id AS id FROM investigations i "
            "JOIN findings f ON f.finding_id = i.finding_id "
            "WHERE json_extract(i.payload, '$.intel') IS NOT NULL "
            "AND COALESCE(json_extract(i.payload, '$.intel.greynoise_source'), '') != 'greynoise' "
            "AND json_array_length(f.payload, '$.cve_ids') > 0 ORDER BY i.finding_id"
        )
        return [r["id"] for r in rows]

    def list_ids(self, limit: int = 10000) -> list[str]:
        """Finding ids that have an investigation record (oldest update first)."""
        rows = self._db.query_all(
            "SELECT finding_id FROM investigations ORDER BY updated_at LIMIT ?", (limit,)
        )
        return [r["finding_id"] for r in rows]


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

    def recent(self, limit: int = 50, finding_id: str | None = None) -> list[dict]:
        """Newest entries first; optionally only those about one finding.

        An entry is about a finding when it is the subject (investigation,
        applicability, policy) or named in details (validation checks, whose
        subject is the host:port).
        """
        if finding_id is None:
            rows = self._db.query_all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        else:
            rows = self._db.query_all(
                "SELECT * FROM audit_log WHERE subject = ? "
                "OR (details IS NOT NULL AND json_extract(details, '$.finding_id') = ?) "
                "ORDER BY id DESC LIMIT ?",
                (finding_id, finding_id, limit),
            )
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
