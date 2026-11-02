"""Bulk investigation of imported findings: `riskproof investigate-pending`.

Imports store findings without enriching them, and MCP investigation takes 25
findings per call. The pending sweep walks the open, never-investigated findings
best-candidates-first, in batches, so a whole import can be assessed in one run.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from riskproof.engine import importer
from riskproof.models.findings import Asset, Finding, Severity


def make(fid: str, severity: str, cve: str | None = None, host: str = "h1") -> Finding:
    return Finding(
        finding_id=fid,
        name=f"finding {fid}",
        severity=Severity(severity),
        cve_ids=[cve] if cve else [],
        asset=Asset(asset_id=host),
    )


def seed(services, findings):
    for f in findings:
        services.findings.save(f)


def test_uninvestigated_ids_are_open_findings_without_a_record(services):
    seed(services, [make("a", "high"), make("b", "high"), make("c", "high")])
    asyncio.run(importer.investigate_pending(services, limit=1, batch_size=1))
    pending = services.findings.uninvestigated_ids()
    assert len(pending) == 2
    assert set(pending) <= {"a", "b", "c"}


def test_resolved_findings_are_not_pending(services):
    seed(services, [make("a", "high"), make("b", "high")])
    services.db.execute("UPDATE findings SET status='resolved' WHERE finding_id='b'")
    assert services.findings.uninvestigated_ids() == ["a"]


async def test_sweep_takes_the_best_candidates_first(services):
    seed(
        services,
        [
            make("low", "low"),
            make("crit", "critical", "CVE-2021-44228"),
            make("high", "high"),
            make("medium", "medium"),
        ],
    )
    result = await importer.investigate_pending(services, limit=2)
    assert result["investigated"] == 2
    assert result["remaining"] == 2
    done = set(services.investigations.list_ids())
    assert done == {"crit", "high"}


async def test_sweep_processes_in_batches_and_reports_progress(services):
    seed(services, [make(f"f{i}", "high") for i in range(5)])
    seen: list[tuple[int, int]] = []
    result = await importer.investigate_pending(
        services, batch_size=2, progress=lambda done, total: seen.append((done, total))
    )
    assert result == {"investigated": 5, "remaining": 0, "batches": 3, "pending_before": 5}
    assert seen == [(2, 5), (4, 5), (5, 5)]


async def test_sweep_with_nothing_pending_is_a_no_op(services):
    result = await importer.investigate_pending(services)
    assert result["investigated"] == 0 and result["batches"] == 0


async def test_sweep_is_resumable_after_a_failure(services, monkeypatch):
    seed(services, [make(f"f{i}", "high") for i in range(4)])
    real = importer.investigate
    calls = {"n": 0}

    async def flaky(svc, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("provider went away")
        return await real(svc, **kwargs)

    monkeypatch.setattr(importer, "investigate", flaky)
    with pytest.raises(RuntimeError):
        await importer.investigate_pending(services, batch_size=2)
    assert len(services.investigations.list_ids()) == 2  # first batch kept
    monkeypatch.setattr(importer, "investigate", real)
    result = await importer.investigate_pending(services, batch_size=2)
    assert result["investigated"] == 2 and result["remaining"] == 0


def test_cli_investigate_pending(tmp_path, monkeypatch, capsys):
    for var in (
        "RISKPROOF_DB_PATH",
        "RISKPROOF_OFFLINE",
        "RISKPROOF_FIXTURES_DIR",
        "RISKPROOF_IMPORT_DIR",
        "RISKPROOF_ASSET_INVENTORY",
    ):
        monkeypatch.delenv(var, raising=False)
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    monkeypatch.setenv("RISKPROOF_DB_PATH", str(tmp_path / "cli.db"))
    monkeypatch.setenv("RISKPROOF_OFFLINE", "true")
    monkeypatch.setenv("RISKPROOF_FIXTURES_DIR", str(fixtures))
    monkeypatch.setenv("RISKPROOF_ASSET_INVENTORY", str(tmp_path / "assets.json"))
    monkeypatch.chdir(tmp_path)

    from riskproof.cli import main
    from riskproof.config import load_settings
    from riskproof.services import build_services

    svc = build_services(load_settings())
    seed(svc, [make(f"f{i}", "high") for i in range(3)])
    svc.db.close()

    assert main(["investigate-pending", "--limit", "2"]) == 0
    out = capsys.readouterr().out
    assert "Investigated 2" in out and "1 still pending" in out


async def test_ids_without_greynoise_lists_records_lacking_a_reading(services):
    seed(services, [make("a", "high", "CVE-2021-44228"), make("b", "high")])
    await importer.investigate_pending(services)
    # fixture-mode intel is SAMPLE, not a live GreyNoise reading; "b" has no CVE and no intel
    assert services.investigations.ids_without_greynoise() == ["a"]


async def test_refresh_greynoise_reinvestigates_records_lacking_a_reading(services):
    seed(services, [make("a", "high", "CVE-2021-44228"), make("b", "high")])
    await importer.investigate_pending(services)
    result = await importer.investigate_pending(services, refresh_greynoise=True)
    assert result["pending_before"] == 1 and result["investigated"] == 1
    plain = await importer.investigate_pending(services)
    assert plain["pending_before"] == 0


def test_cli_warns_when_greynoise_is_not_configured(tmp_path, monkeypatch, capsys):
    for var in ("RISKPROOF_DB_PATH", "RISKPROOF_FIXTURES_DIR", "RISKPROOF_ASSET_INVENTORY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    monkeypatch.setenv("RISKPROOF_DB_PATH", str(tmp_path / "w.db"))
    monkeypatch.setenv("RISKPROOF_OFFLINE", "false")
    monkeypatch.setenv("RISKPROOF_ASSET_INVENTORY", str(tmp_path / "assets.json"))
    monkeypatch.chdir(tmp_path)

    from riskproof.cli import main

    assert main(["investigate-pending"]) == 0  # nothing pending: no network use
    assert "GREYNOISE_API_KEY" in capsys.readouterr().err
