"""Tests for exploit scenarios and remediation simulation."""

from __future__ import annotations

from datetime import UTC, datetime

from riskproof.engine.evidence import build_investigation_record
from riskproof.engine.remediation import simulate_remediation
from riskproof.engine.risk import assess
from riskproof.engine.scenario import build_exploit_scenario
from riskproof.models.analysis import RemediationActionType
from riskproof.models.findings import Asset, CVSSV3Observation, Finding, Severity
from riskproof.models.intel import (
    EPSSObservation,
    KEVEntry,
    KEVStatus,
    ThreatIntelBundle,
)


def make_setup(internet_facing: bool = True, solution: str | None = "Upgrade Log4j to 2.17.1+"):

    now = datetime.now(UTC)
    bundle = ThreatIntelBundle(
        cve_ids=["CVE-2021-44228"],
        epss={
            "CVE-2021-44228": EPSSObservation(
                cve="CVE-2021-44228", score=0.94, percentile=0.99, collected_at=now
            )
        },
        kev_status=[
            KEVStatus(
                cve="CVE-2021-44228",
                in_kev=True,
                catalog="cisa-live",
                entry=KEVEntry(
                    cve="CVE-2021-44228",
                    date_added="2021-12-10",
                    known_ransomware_campaign_use="Known",
                ),
                checked_at=now,
            )
        ],
        collected_at=now,
        epss_source="first.org",
        kev_source="cisa-live",
    )
    finding = Finding(
        finding_id="scen-finding",
        name="Log4Shell (test)",
        severity=Severity.CRITICAL,
        cve_ids=["CVE-2021-44228"],
        cvss_v3=CVSSV3Observation(
            base_score=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        ),
        solution=solution,
        plugin_output="Installed version : 2.14.1",
        asset=Asset(
            asset_id="asset-x",
            criticality="critical",
            internet_facing=internet_facing,
        ),
    )
    record = build_investigation_record(finding, bundle)
    assessment = assess(finding, record)
    return finding, record, assessment


def test_prerequisites_derived_from_cvss_vector():
    finding, record, assessment = make_setup()
    scenario = build_exploit_scenario(finding, record, assessment)
    assert any("network access" in p for p in scenario.exploit_prerequisites)
    assert any("No authentication" in p for p in scenario.exploit_prerequisites)
    assert any(
        "Scope change" in p or "beyond the vulnerable component" in p
        for p in scenario.exploit_prerequisites
    )


def test_kev_ransomware_consequence_is_intel_not_compromise_claim():
    finding, record, assessment = make_setup()
    scenario = build_exploit_scenario(finding, record, assessment)
    ransomware_lines = [c for c in scenario.potential_consequences if "ransomware" in c.lower()]
    assert ransomware_lines, "KEV ransomware intel should surface as a consequence note"
    assert "no evidence this asset was compromised" in ransomware_lines[0]


def test_no_exploitation_claim_is_made():
    finding, record, assessment = make_setup()
    scenario = build_exploit_scenario(finding, record, assessment)
    assert any("No claim of successful exploitation" in c.statement for c in scenario.conclusions)


def test_epss_caveat_always_present_in_uncertainties():
    finding, record, assessment = make_setup()
    scenario = build_exploit_scenario(finding, record, assessment)
    assert any("EPSS" in u and "statistical" in u for u in scenario.uncertainties)


def test_remediation_options_and_recommendation():
    finding, record, assessment = make_setup()
    simulation = simulate_remediation(finding, record, assessment)
    types = {o.action_type for o in simulation.options}
    assert RemediationActionType.APPLY_PATCH in types
    assert RemediationActionType.REQUEST_RESCAN in types
    assert RemediationActionType.COMPENSATING_CONTROL in types  # internet-facing
    assert simulation.recommended_option_id == "opt-vendor-fix"
    assert "re-scan" in " ".join(simulation.rationale).lower()


def test_remediation_without_solution_still_offers_upgrade_and_rescan():
    finding, record, assessment = make_setup(solution=None)
    simulation = simulate_remediation(finding, record, assessment)
    types = {o.action_type for o in simulation.options}
    assert RemediationActionType.UPGRADE in types
    assert RemediationActionType.REQUEST_RESCAN in types
    assert simulation.disclaimer
