"""investigate_finding summaries stay small for patch bundles with dozens of CVEs.

A single Windows cumulative-update finding can carry 90+ CVEs, and every CVE
used to contribute its own EPSS/KEV/GreyNoise evidence statements, so one
summary could run to hundreds of kilobytes. The summary now keeps the evidence
for the scored CVE and rolls the rest up as counts; detail="full" is unchanged.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from riskproof.engine import investigation as inv
from riskproof.models.findings import Asset, Finding
from riskproof.models.intel import KEVStatus

BUNDLE_SIZE = 90


def bundle(n: int = BUNDLE_SIZE) -> Finding:
    return Finding(
        finding_id="bundle-1",
        name="KB0000000: cumulative update",
        severity="critical",
        cve_ids=[f"CVE-2020-{1000 + i}" for i in range(n)],
        asset=Asset(asset_id="a1"),
    )


@pytest.fixture()
def live(services, monkeypatch):
    async def no_epss(cves):
        return {}

    async def one_kev(cves):
        now = datetime.now(UTC)
        return [
            KEVStatus(
                cve=c,
                in_kev=c in {"CVE-2020-1003", "CVE-2020-1004"},
                catalog="cisa-live",
                checked_at=now,
            )
            for c in cves
        ]

    monkeypatch.setattr(services.epss, "fetch", no_epss)
    monkeypatch.setattr(services.kev, "status_for", one_kev)
    return services


def threat_intel(summary: dict) -> list[dict]:
    return [e for e in summary["evidence"] if e["kind"] == "threat_intel"]


async def test_bundle_summary_keeps_only_the_scored_cves_intel(live):
    (report,) = await inv.investigate(live, finding=bundle(), intel_source="live")
    summary = report.summary()
    scored = report.risk_score.vulnerability
    kept = threat_intel(summary)
    assert kept, "the scored CVE's intel must stay in the summary"
    assert all(scored in e["statement"] for e in kept)
    assert len(kept) <= 3


async def test_bundle_summary_rolls_up_what_it_omitted(live):
    (report,) = await inv.investigate(live, finding=bundle(), intel_source="live")
    rollup = report.summary()["intel_rollup"]
    assert rollup["cves_total"] == BUNDLE_SIZE
    assert rollup["kev_listed"] == 2
    assert rollup["greynoise_observed"] == 0
    assert rollup["statements_omitted"] > 0
    assert rollup["scored_cve"] == report.risk_score.vulnerability
    assert "detail='full'" in rollup["note"]


async def test_bundle_summary_is_small(live):
    (report,) = await inv.investigate(live, finding=bundle(), intel_source="live")
    assert len(json.dumps(report.summary())) < 20_000


async def test_non_intel_evidence_is_never_dropped(live):
    (report,) = await inv.investigate(live, finding=bundle(), intel_source="live")
    kinds = {e["kind"] for e in report.summary()["evidence"]}
    assert {"scanner_finding", "asset_context"} <= kinds


async def test_single_cve_finding_summary_is_unchanged(live):
    one = bundle(1)
    (report,) = await inv.investigate(live, finding=one, intel_source="live")
    summary = report.summary()
    assert "intel_rollup" not in summary
    assert len(threat_intel(summary)) == len(
        [e for e in report.record.evidence if e.kind.value == "threat_intel"]
    )


async def test_confidence_counts_still_cover_all_evidence(live):
    (report,) = await inv.investigate(live, finding=bundle(), intel_source="live")
    counts = report.summary()["evidence_by_confidence"]
    assert sum(counts.values()) == len(report.record.evidence)
