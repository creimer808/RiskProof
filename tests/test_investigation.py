"""Tests for investigation orchestration (ingest -> enrich -> assess)."""

from __future__ import annotations

import pytest

from riskproof.engine import investigation as inv
from riskproof.errors import InvalidInputError, NotFoundError


async def test_investigate_fixture_dataset(services):
    reports = await inv.investigate(services, fixture="findings_sample.json")
    assert len(reports) == 5
    log4shell = next(r for r in reports if r.finding_id.endswith("155999-8080tcp"))
    assert log4shell.finding.source == "fixture"
    assert log4shell.record.intel is not None
    assert log4shell.record.intel.epss_source == "sample-fixture"
    assert log4shell.record.intel.degraded is True  # fixture intel is flagged
    assert log4shell.assessment.recommended_priority is not None
    assert log4shell.assessment.recommended_priority.value == "P1"
    # Findings and records are persisted.
    assert services.findings.count() == 5


async def test_intel_is_per_cve_filtered(services):
    reports = await inv.investigate(services, fixture="findings_sample.json")
    terrapin = next(r for r in reports if r.finding_id.endswith("215400-22tcp"))
    basis = " ".join(terrapin.assessment.likelihood_basis)
    assert "48795" in basis
    assert "44228" not in basis  # must not leak other CVEs' intel into this record


async def test_investigate_inline_finding(services):
    from riskproof.models.findings import Asset, Finding

    finding = Finding(
        finding_id="inline-1",
        name="Inline finding",
        severity="high",
        cve_ids=["CVE-2024-6387"],
        asset=Asset(asset_id="host-x"),
    )
    reports = await inv.investigate(services, finding=finding)
    assert reports[0].finding.source == "manual"
    assert reports[0].record.intel is not None


async def test_selector_exactly_one(services):
    with pytest.raises(InvalidInputError):
        await inv.investigate(services)


async def test_path_traversal_in_fixture_name_refused(services):
    with pytest.raises(InvalidInputError):
        await inv.investigate(services, fixture="../secrets.json")


async def test_unknown_finding_id_raises_not_found(services):
    with pytest.raises(NotFoundError):
        await inv.investigate(services, finding_id="nope")


async def test_verify_applicability_updates_record(services):
    reports = await inv.investigate(services, fixture="findings_sample.json")
    target = next(r for r in reports if r.finding_id.endswith("155999-8080tcp"))
    record = inv.verify_applicability(
        services,
        target.finding_id,
        observed_service=None,
    )
    assert record.applicability.value in {"likely_affected", "affected_evidenced"}


async def test_enrich_live_source_without_network_reports_unavailable(services):
    """source='live' must NOT silently fall back to fixtures."""
    from riskproof.providers.epss import EPSSProvider
    from riskproof.providers.kev import KEVProvider

    # Point both providers at an unroutable address with a tiny timeout.
    services.epss = EPSSProvider(base_url="http://127.0.0.1:1/epss", timeout=0.2)
    services.kev = KEVProvider(feed_url="http://127.0.0.1:1/kev.json", timeout=0.2, cache=None)
    bundle = await inv.enrich_threat_intel(services, ["CVE-2021-44228"], source="live")
    assert bundle.epss["CVE-2021-44228"].kind == "unavailable"
    assert bundle.degraded is True
    assert bundle.epss_source == "unavailable"


LOG4SHELL = "prod-web-01.demo.local-155999-8080tcp"


async def test_reinvestigation_preserves_validation_and_verified_applicability(services):
    """Re-running investigate_finding must not erase work done after the first run."""
    from riskproof.models.evidence import ApplicabilityStatus, EvidenceKind
    from riskproof.models.findings import ServiceObservation

    await inv.investigate(services, fixture="findings_sample.json")
    created_at = services.investigations.get(LOG4SHELL).created_at
    await inv.validate_exposure(
        services, host="127.0.0.1", port=9, method="tcp_connect", finding_id=LOG4SHELL
    )
    inv.verify_applicability(services, LOG4SHELL, ServiceObservation(port=8080, version="2.15.0"))

    report = (await inv.investigate(services, finding_id=LOG4SHELL))[0]
    record = report.record
    kinds = [e.kind for e in record.evidence]
    assert kinds.count(EvidenceKind.NETWORK_VALIDATION) == 1
    assert kinds.count(EvidenceKind.SCANNER_FINDING) == 1  # regenerated, not duplicated
    assert record.applicability == ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
    assert record.created_at == created_at
    assert report.assessment.applicability == ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
    # The verdict is marked as carried forward exactly once, however often we re-run.
    await inv.investigate(services, finding_id=LOG4SHELL)
    rationale = services.investigations.get(LOG4SHELL).applicability_rationale
    assert sum("carried forward" in line for line in rationale) == 1


async def test_reinvestigation_without_intel_keeps_existing_intel(services):
    await inv.investigate(services, fixture="findings_sample.json")
    report = (await inv.investigate(services, finding_id=LOG4SHELL, include_intel=False))[0]
    assert report.record.intel is not None
    assert report.assessment.recommended_priority is not None
    assert report.assessment.recommended_priority.value == "P1"
