"""Tests for the risk engine: dimension separation and the decision table."""

from __future__ import annotations

from datetime import UTC, datetime

from riskproof.engine.evidence import build_investigation_record
from riskproof.engine.risk import assess, parse_cvss_metrics
from riskproof.models.analysis import BusinessImpact, ExploitationLikelihood
from riskproof.models.evidence import ApplicabilityStatus
from riskproof.models.findings import Asset, CVSSV3Observation, Finding, Severity
from riskproof.models.intel import (
    EPSSObservation,
    KEVEntry,
    KEVStatus,
    ThreatIntelBundle,
)


def make_finding(**overrides) -> Finding:
    base = {
        "finding_id": "test-finding",
        "name": "Test finding",
        "severity": Severity.HIGH,
        "cve_ids": ["CVE-2021-44228"],
        "cvss_v3": CVSSV3Observation(
            base_score=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        ),
        "asset": Asset(asset_id="test-asset", criticality="high", internet_facing=False),
    }
    base.update(overrides)
    return Finding(**base)


def make_intel(
    epss_score: float | None = 0.9,
    in_kev: bool = True,
    catalog: str = "cisa-live",
) -> ThreatIntelBundle:
    now = datetime.now(UTC)
    epss = {}
    if epss_score is not None:
        epss["CVE-2021-44228"] = EPSSObservation(
            cve="CVE-2021-44228",
            score=epss_score,
            percentile=0.99,
            collected_at=now,
            source="first.org",
        )
    kev = [
        KEVStatus(
            cve="CVE-2021-44228",
            in_kev=in_kev,
            catalog=catalog,
            entry=KEVEntry(cve="CVE-2021-44228", known_ransomware_campaign_use="Known"),
            checked_at=now,
        )
    ]
    return ThreatIntelBundle(
        cve_ids=["CVE-2021-44228"],
        epss=epss,
        kev_status=kev,
        collected_at=now,
        epss_source="first.org",
        kev_source="cisa-live" if catalog == "cisa-live" else "sample-fixture",
    )


def test_kev_and_internet_facing_is_p1():
    finding = make_finding()
    finding = finding.model_copy(
        update={"asset": finding.asset.model_copy(update={"internet_facing": True})}
    )
    record = build_investigation_record(finding, make_intel())
    assessment = assess(finding, record)
    assert assessment.exploitation_likelihood == ExploitationLikelihood.OBSERVED_IN_THE_WILD
    assert assessment.recommended_priority is not None
    assert assessment.recommended_priority.value == "P1"


def test_kev_internal_critical_asset_is_p1():
    finding = make_finding()
    finding = finding.model_copy(
        update={
            "asset": finding.asset.model_copy(
                update={"internet_facing": False, "criticality": "critical"}
            )
        }
    )
    record = build_investigation_record(finding, make_intel())
    assessment = assess(finding, record)
    assert assessment.business_impact == BusinessImpact.SEVERE
    assert assessment.recommended_priority is not None
    assert assessment.recommended_priority.value == "P1"


def test_kev_internal_noncritical_is_p2():
    finding = make_finding()  # criticality high, internal
    record = build_investigation_record(finding, make_intel())
    assessment = assess(finding, record)
    assert assessment.recommended_priority is not None
    assert assessment.recommended_priority.value == "P2"


def test_no_kev_low_epss_high_severity_internal_is_p2():
    finding = make_finding()
    record = build_investigation_record(finding, make_intel(epss_score=0.001, in_kev=False))
    assessment = assess(finding, record)
    assert assessment.exploitation_likelihood == ExploitationLikelihood.LOW
    assert assessment.recommended_priority is not None
    assert assessment.recommended_priority.value == "P2"


def test_medium_severity_without_intel_is_p3():
    finding = make_finding(severity=Severity.MEDIUM, cvss_v3=None, cve_ids=[])
    record = build_investigation_record(finding, None)
    assessment = assess(finding, record)
    assert assessment.exploitation_likelihood == ExploitationLikelihood.UNKNOWN
    assert assessment.evidence_confidence.value == "missing"
    assert assessment.recommended_priority is not None
    assert assessment.recommended_priority.value == "P3"


def test_suspected_not_affected_caps_priority_at_p3():
    finding = make_finding()
    finding = finding.model_copy(
        update={"asset": finding.asset.model_copy(update={"internet_facing": True})}
    )
    record = build_investigation_record(finding, make_intel())
    record.applicability = ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
    assessment = assess(finding, record)
    assert assessment.recommended_priority is not None
    assert assessment.recommended_priority.value == "P3"  # capped, not zeroed
    assert any("NOT suppressed" in r for r in assessment.priority_rationale)


def test_vpr_bump_lifts_p3_to_p2():
    from riskproof.models.findings import VPRObservation

    finding = make_finding(
        severity=Severity.MEDIUM,
        cvss_v3=None,
        cve_ids=[],
        vpr=VPRObservation(score=7.5, source="test"),
    )
    record = build_investigation_record(finding, None)
    assessment = assess(finding, record)
    assert assessment.recommended_priority is not None
    assert assessment.recommended_priority.value == "P2"
    assert any("VPR" in r for r in assessment.priority_rationale)


def test_fixture_intel_is_flagged_inconclusive():
    finding = make_finding()
    record = build_investigation_record(finding, make_intel(catalog="sample"))
    assessment = assess(finding, record)
    assert assessment.evidence_confidence.value == "inconclusive"


def test_parse_cvss_metrics():
    metrics = parse_cvss_metrics("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert metrics == {
        "AV": "N",
        "AC": "L",
        "PR": "N",
        "UI": "N",
        "S": "C",
        "C": "H",
        "I": "H",
        "A": "H",
    }
    assert parse_cvss_metrics(None) == {}
