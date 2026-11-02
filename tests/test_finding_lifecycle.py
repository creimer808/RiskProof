"""Finding lifecycle: sightings, resolved state, reconcile of unseen findings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from riskproof.models.findings import Asset, Finding, Severity
from riskproof.services import Services

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
T1 = T0 + timedelta(days=7)


def make_finding(
    fid: str, severity: str = "high", source: str = "tenable", state: str | None = None
) -> Finding:
    return Finding(
        finding_id=fid,
        source=source,
        name=f"Finding {fid}",
        severity=Severity(severity),
        asset=Asset(asset_id=f"asset-{fid}"),
        raw={"state": state},
    )


def row(services: Services, fid: str):
    return services.db.query_one("SELECT * FROM findings WHERE finding_id = ?", (fid,))


def test_first_save_is_new_and_open(services: Services) -> None:
    stats = services.findings.save_many([make_finding("f1")], now=T0)
    assert (stats.new, stats.updated, stats.reopened, stats.resolved) == (1, 0, 0, 0)
    r = row(services, "f1")
    assert r["status"] == "open"
    assert r["last_seen_at"] == T0.isoformat()


def test_resave_updates_last_seen_and_counts_updated(services: Services) -> None:
    services.findings.save_many([make_finding("f1")], now=T0)
    stats = services.findings.save_many([make_finding("f1")], now=T1)
    assert (stats.new, stats.updated) == (0, 1)
    r = row(services, "f1")
    assert r["last_seen_at"] == T1.isoformat()
    assert r["ingested_at"] != r["last_seen_at"]
    assert r["status_changed_at"] == T0.isoformat()


def test_fixed_state_marks_resolved_with_source(services: Services) -> None:
    services.findings.save_many([make_finding("f1")], now=T0)
    stats = services.findings.save_many([make_finding("f1", state="fixed")], now=T1)
    assert stats.resolved == 1
    r = row(services, "f1")
    assert r["status"] == "resolved"
    assert r["resolution_source"] == "tenable_fixed"
    assert r["status_changed_at"] == T1.isoformat()


def test_reappearing_open_finding_is_reopened(services: Services) -> None:
    services.findings.save_many([make_finding("f1", state="fixed")], now=T0)
    stats = services.findings.save_many([make_finding("f1", state="open")], now=T1)
    assert stats.reopened == 1
    r = row(services, "f1")
    assert r["status"] == "open"
    assert r["resolution_source"] is None


def test_save_does_not_refresh_sighting_or_reopen(services: Services) -> None:
    services.findings.save_many([make_finding("f1")], now=T0)
    services.findings.reconcile_unseen(
        source="tenable", severities=["high"], seen_before=T1, apply=True, max_fraction=1.0
    )
    assert row(services, "f1")["status"] == "not_seen"
    services.findings.save(make_finding("f1"))
    r = row(services, "f1")
    assert r["status"] == "not_seen"
    assert r["last_seen_at"] == T0.isoformat()
    services.findings.save(make_finding("f2"))
    assert row(services, "f2")["status"] == "open"


def _seed_stale(services: Services, n: int = 4) -> None:
    services.findings.save_many([make_finding(f"old{i}") for i in range(n)], now=T0)
    services.findings.save_many([make_finding("fresh")], now=T1)


def _reconcile(services: Services, **kw):
    args = {
        "source": "tenable",
        "severities": ["high", "critical"],
        "seen_before": T1,
        "apply": False,
        "max_fraction": 1.0,
    }
    args.update(kw)
    return services.findings.reconcile_unseen(**args)


def test_reconcile_preview_changes_nothing(services: Services) -> None:
    _seed_stale(services)
    result = _reconcile(services)
    assert result.candidates == 4
    assert result.in_scope_open == 5
    assert result.applied is False
    assert result.skipped_reason is None
    assert len(result.sample_ids) == 4
    assert services.findings.inactive_ids() == set()


def test_reconcile_apply_marks_not_seen_and_keeps_rows(services: Services) -> None:
    _seed_stale(services)
    before = services.findings.count()
    result = _reconcile(services, apply=True)
    assert result.applied is True
    assert services.findings.inactive_ids() == {f"old{i}" for i in range(4)}
    r = row(services, "old0")
    assert r["status"] == "not_seen"
    assert r["resolution_source"] == "absent_from_export"
    assert r["status_changed_at"] is not None
    assert row(services, "fresh")["status"] == "open"
    assert services.findings.count() == before


def test_reconcile_only_touches_source_and_severity_in_scope(services: Services) -> None:
    services.findings.save_many(
        [
            make_finding("nes", source="nessus"),
            make_finding("med", severity="medium"),
            make_finding("hi"),
        ],
        now=T0,
    )
    result = _reconcile(services, apply=True)
    assert result.candidates == 1
    assert row(services, "nes")["status"] == "open"
    assert row(services, "med")["status"] == "open"
    assert row(services, "hi")["status"] == "not_seen"


def test_reconcile_mass_vanish_guard_skips(services: Services) -> None:
    services.findings.save_many([make_finding(f"f{i}") for i in range(10)], now=T0)
    result = _reconcile(services, apply=True, max_fraction=0.5)
    assert result.skipped_reason
    assert result.applied is False
    assert result.candidates == 10
    assert services.findings.inactive_ids() == set()


def test_reconcile_with_nothing_in_scope_is_skipped(services: Services) -> None:
    result = _reconcile(services, apply=True)
    assert result.skipped_reason
    assert result.candidates == 0


def test_reconcile_sample_ids_capped_at_ten(services: Services) -> None:
    services.findings.save_many([make_finding(f"f{i:02d}") for i in range(15)], now=T0)
    services.findings.save_many([make_finding(f"n{i:02d}") for i in range(30)], now=T1)
    result = _reconcile(services, max_fraction=1.0)
    assert result.candidates == 15
    assert len(result.sample_ids) == 10


def test_uninvestigated_rollup_ignores_inactive(services: Services) -> None:
    services.findings.save_many(
        [make_finding("a"), make_finding("b", state="fixed"), make_finding("c")], now=T0
    )
    assert services.findings.uninvestigated_rollup()["total"] == 2
    _reconcile(services, seen_before=T1, apply=True)  # a and c go not_seen
    assert services.findings.uninvestigated_rollup()["total"] == 0


def test_inactive_ids(services: Services) -> None:
    services.findings.save_many([make_finding("a"), make_finding("b", state="fixed")], now=T0)
    assert services.findings.inactive_ids() == {"b"}


def test_save_many_handles_more_ids_than_sqlite_variable_limit(services: Services) -> None:
    batch = [make_finding(f"f{i}") for i in range(1200)]
    assert services.findings.save_many(batch, now=T0).new == 1200
    assert services.findings.save_many(batch, now=T1).updated == 1200


def test_settings_default_for_mass_vanish_fraction(services: Services) -> None:
    assert services.settings.reconcile_max_missing_fraction == pytest.approx(0.5)


def test_fixed_state_matches_tenable_uppercase(services: Services) -> None:
    services.findings.save_many([make_finding("f1", state="FIXED")], now=T0)
    assert row(services, "f1")["status"] == "resolved"
