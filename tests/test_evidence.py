"""Tests for evidence building and honest confidence classification."""

from __future__ import annotations

from datetime import UTC, datetime

from riskproof.engine.evidence import (
    apply_applicability_observation,
    build_investigation_record,
    build_validation_evidence,
)
from riskproof.models.evidence import (
    ApplicabilityStatus,
    Confidence,
    EvidenceKind,
    InvestigationStatus,
)
from riskproof.models.findings import (
    Asset,
    CVSSV3Observation,
    Finding,
    ServiceObservation,
    Severity,
)
from riskproof.models.intel import EPSSUnavailable, ThreatIntelBundle
from riskproof.validation.checks import ValidationResult


def make_finding() -> Finding:
    return Finding(
        finding_id="ev-finding",
        name="Test",
        severity=Severity.HIGH,
        cve_ids=["CVE-2021-44228"],
        cvss_v3=CVSSV3Observation(
            base_score=9.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
        plugin_output="Installed version : 2.14.1",
        asset=Asset(asset_id="a1", criticality="high", internet_facing=True),
    )


def make_bundle() -> ThreatIntelBundle:
    now = datetime.now(UTC)
    return ThreatIntelBundle(
        cve_ids=["CVE-2021-44228"],
        epss={"CVE-2021-44228": EPSSUnavailable(cve="CVE-2021-44228", reason="test gap")},
        kev_status=[],
        collected_at=now,
        epss_source="first.org",
        kev_source="cisa-live",
    )


def test_record_contains_expected_evidence_kinds():
    finding = make_finding()
    record = build_investigation_record(finding, make_bundle())
    kinds = {e.kind for e in record.evidence}
    assert EvidenceKind.SCANNER_FINDING in kinds
    assert EvidenceKind.THREAT_INTEL in kinds
    assert EvidenceKind.ASSET_CONTEXT in kinds
    assert record.status == InvestigationStatus.ENRICHED
    assert record.applicability == ApplicabilityStatus.LIKELY_AFFECTED


def test_epss_unavailable_recorded_as_missing_not_fabricated():
    finding = make_finding()
    record = build_investigation_record(finding, make_bundle())
    epss_evidence = [
        e for e in record.evidence if e.kind == EvidenceKind.THREAT_INTEL and "EPSS" in e.statement
    ]
    assert len(epss_evidence) == 1
    assert epss_evidence[0].confidence == Confidence.MISSING
    assert "No EPSS observation available" in record.open_questions[0]


def test_no_cves_produces_open_question():
    finding = make_finding().model_copy(update={"cve_ids": []})
    record = build_investigation_record(finding, None)
    assert any("no CVE identifiers" in q for q in record.open_questions)
    assert record.applicability == ApplicabilityStatus.UNKNOWN


def test_negative_validation_does_not_suppress_finding():
    """An inconclusive validation result is recorded as evidence; applicability
    stays scanner-reported and no evidence claims 'not vulnerable'."""
    finding = make_finding()
    record = build_investigation_record(finding, make_bundle())
    result = ValidationResult(
        method="tcp_connect",
        target="10.20.0.99",
        port=8443,
        status="inconclusive",
        notes=["connection timed out (possibly filtered)"],
        checked_at=datetime.now(UTC),
    )
    record.evidence.append(build_validation_evidence(result, finding.finding_id))
    val = [e for e in record.evidence if e.kind == EvidenceKind.NETWORK_VALIDATION]
    assert len(val) == 1
    assert val[0].confidence == Confidence.INCONCLUSIVE
    assert record.applicability in (
        ApplicabilityStatus.LIKELY_AFFECTED,
        ApplicabilityStatus.UNKNOWN,
    )


def test_version_match_and_mismatch_applicability():
    finding = make_finding()
    record = build_investigation_record(finding, make_bundle())

    match = apply_applicability_observation(
        record.model_copy(deep=True),
        finding,
        ServiceObservation(port=8080, product="log4j-core", version="2.14.1"),
    )
    assert match.applicability == ApplicabilityStatus.AFFECTED_EVIDENCED

    mismatch = apply_applicability_observation(
        record.model_copy(deep=True),
        finding,
        ServiceObservation(port=8080, product="log4j-core", version="2.17.1"),
    )
    assert mismatch.applicability == ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
    assert any("not suppressed" in r for r in mismatch.applicability_rationale)
