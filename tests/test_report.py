"""HTML report generation: build_report assembly, render_html, file writing.

The report is a read-only aggregation over stored findings, investigation
records, pending actions, and the audit log. Priorities are recomputed with
the same deterministic assessment the tools use — the report can never
disagree with investigate_finding output.
"""

from __future__ import annotations

import asyncio
import html
from datetime import UTC, datetime
from pathlib import Path

import pytest

from riskproof.engine import investigation as inv
from riskproof.engine.report import (
    build_report,
    default_report_path,
    render_html,
    write_report_file,
)
from riskproof.errors import InvalidInputError
from riskproof.models.evidence import ApplicabilityStatus
from riskproof.models.findings import Asset, Finding
from riskproof.models.policy import Priority, RiskPolicy

LOG4SHELL = "prod-web-01.demo.local-155999-8080tcp"


async def _investigate_fixture(services) -> int:
    reports = await inv.investigate(services, fixture="findings_sample.json")
    return len(reports)


async def test_build_report_on_demo_fixtures(services):
    total = await _investigate_fixture(services)

    report = build_report(services)

    assert report.summary.investigated_total == total
    assert report.summary.by_priority.get("P1", 0) >= 1
    assert report.summary.shown == total
    assert report.summary.uninvestigated == 0
    assert report.uninvestigated == []

    entry = next(f for f in report.findings if f.finding_id == LOG4SHELL)
    assert entry.assessment.recommended_priority == Priority.P1
    assert entry.assessment.priority_rationale
    assert entry.evidence
    assert entry.scenario.exploit_prerequisites
    assert entry.simulation.recommended_option_id
    # The per-finding audit excerpt reconstructs the investigation.
    assert any(e["action"] == "investigate_finding" for e in entry.audit_entries)

    # Provenance and caveats are carried, never dropped.
    assert any(
        p.epss_source == "sample-fixture" and p.kev_source == "sample-fixture" and p.degraded
        for p in report.provenance
    )
    assert any("SAMPLE" in n for n in report.notices)
    assert "not a claim about this specific system" in report.caveats["epss"]
    assert "not that this asset was compromised" in report.caveats["kev_listed"]


async def test_findings_are_sorted_p1_first(services):
    await _investigate_fixture(services)

    report = build_report(services)

    ranks = [
        (
            list(Priority).index(f.assessment.recommended_priority)
            if f.assessment.recommended_priority
            else 99
        )
        for f in report.findings
    ]
    assert ranks == sorted(ranks)


async def test_min_priority_filter_excludes_and_discloses(services):
    total = await _investigate_fixture(services)
    # Deterministically push one investigated finding below the P2 cutoff.
    record = services.investigations.get(LOG4SHELL)
    record.applicability = ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
    services.investigations.save(record)

    report = build_report(services, min_priority=Priority.P2)

    ids = [f.finding_id for f in report.findings]
    assert LOG4SHELL not in ids
    assert all(
        f.assessment.recommended_priority in (Priority.P1, Priority.P2) for f in report.findings
    )
    # by_priority counts ALL investigated findings; shown counts the filtered set.
    excluded = sum(report.summary.by_priority.get(k, 0) for k in ("P3", "P4", "unprioritized"))
    assert report.summary.investigated_total == total
    assert report.summary.shown == len(report.findings) == total - excluded
    assert report.min_priority == Priority.P2


async def test_invalid_min_priority_is_rejected(services):
    with pytest.raises(InvalidInputError):
        build_report(services, min_priority="P9")


async def test_uninvestigated_findings_are_listed_not_hidden(services):
    await _investigate_fixture(services)
    extra = Finding(
        finding_id="extra-host-999999-80tcp",
        name="Extra imported finding",
        severity="low",
        source="manual",
        asset=Asset(asset_id="extra-host"),
    )
    services.findings.save(extra)

    report = build_report(services)

    assert report.summary.uninvestigated == 1
    assert [u.finding_id for u in report.uninvestigated] == ["extra-host-999999-80tcp"]
    assert all(f.finding_id != extra.finding_id for f in report.findings)


async def test_pending_actions_and_policy_audit_are_included(services):
    await _investigate_fixture(services)
    inv.execute_risk_policy(services, [LOG4SHELL], RiskPolicy())

    report = build_report(services)

    assert report.summary.open_pending_actions >= 1
    assert report.pending_actions
    entry = next(f for f in report.findings if f.finding_id == LOG4SHELL)
    assert any(e["action"].startswith("policy:") for e in entry.audit_entries)
    assert report.recent_audit
    assert report.dry_run is True


async def test_suspected_false_positive_is_counted(services):
    await _investigate_fixture(services)
    record = services.investigations.get(LOG4SHELL)
    record.applicability = ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
    services.investigations.save(record)

    report = build_report(services)

    assert report.summary.suspected_false_positives == 1
    entry = next(f for f in report.findings if f.finding_id == LOG4SHELL)
    assert entry.record.applicability == ApplicabilityStatus.SUSPECTED_NOT_AFFECTED


async def test_render_html_is_self_contained_and_honest(services):
    await _investigate_fixture(services)
    report = build_report(services)
    finding = services.findings.get(LOG4SHELL)

    page = render_html(report)

    assert page.lower().startswith("<!doctype html")
    # Honesty: SAMPLE provenance and the statistical caveats are in the page.
    assert "SAMPLE" in page
    assert "not a claim about this specific system" in page
    assert "not that this asset was compromised" in page
    # Content: the finding and its priority appear.
    assert html.escape(finding.finding_id) in page
    assert ">P1<" in page
    # Self-contained: no external resources.
    assert 'src="http' not in page and 'href="http' not in page


async def test_render_html_empty_report(services):
    report = build_report(services)

    assert report.summary.investigated_total == 0
    assert "No investigated findings in scope." in render_html(report)


def test_default_report_name(tmp_path):
    path = default_report_path(tmp_path, datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC))
    assert path == tmp_path / "riskproof-report-20260102T030405Z.html"


async def test_write_report_file_is_owner_only(tmp_path, services):
    await _investigate_fixture(services)
    page = render_html(build_report(services))
    out = tmp_path / "nested" / "report.html"

    written = write_report_file(page, out)

    assert written == out and out.exists()
    assert out.read_text(encoding="utf-8") == page
    assert (out.stat().st_mode & 0o777) == 0o600


def test_cli_report_writes_html(tmp_path, monkeypatch):
    """The `riskproof report` CLI reads operator settings and writes 0600 HTML."""
    for var in (
        "RISKPROOF_DB_PATH",
        "RISKPROOF_OFFLINE",
        "RISKPROOF_FIXTURES_DIR",
        "RISKPROOF_IMPORT_DIR",
        "RISKPROOF_ASSET_INVENTORY",
        "RISKPROOF_REPORTS_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    monkeypatch.setenv("RISKPROOF_DB_PATH", str(tmp_path / "cli.db"))
    monkeypatch.setenv("RISKPROOF_OFFLINE", "true")
    monkeypatch.setenv("RISKPROOF_FIXTURES_DIR", str(fixtures))
    monkeypatch.setenv("RISKPROOF_ASSET_INVENTORY", str(tmp_path / "assets.json"))
    monkeypatch.chdir(tmp_path)  # keep any developer .env out of the test

    from riskproof.cli import main
    from riskproof.config import load_settings
    from riskproof.services import build_services

    seed = build_services(load_settings())
    asyncio.run(inv.investigate(seed, fixture="findings_sample.json"))
    seed.db.close()

    out = tmp_path / "custom.html"
    assert main(["report", "--output", str(out)]) == 0
    assert out.exists()
    assert (out.stat().st_mode & 0o777) == 0o600
    assert "SAMPLE" in out.read_text(encoding="utf-8")

    # Default output lands in the working directory with a timestamped name.
    monkeypatch.chdir(tmp_path)
    assert main(["report"]) == 0
    default_files = list(tmp_path.glob("riskproof-report-*.html"))
    assert default_files, "expected a timestamped default report file"
