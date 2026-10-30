"""Tests for the policy engine: dry-run, approvals, and audit records."""

from __future__ import annotations

from datetime import UTC, datetime

from riskproof.engine.evidence import build_investigation_record
from riskproof.engine.policy_engine import evaluate_policy
from riskproof.engine.risk import assess
from riskproof.models.evidence import ApplicabilityStatus
from riskproof.models.findings import Asset, CVSSV3Observation, Finding, Severity
from riskproof.models.intel import (
    EPSSObservation,
    KEVEntry,
    KEVStatus,
    ThreatIntelBundle,
)
from riskproof.models.policy import PolicyAction, RiskPolicy


def make_kev_internet_finding() -> tuple[Finding, ThreatIntelBundle]:
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
                entry=KEVEntry(cve="CVE-2021-44228"),
                checked_at=now,
            )
        ],
        collected_at=now,
        epss_source="first.org",
        kev_source="cisa-live",
    )
    finding = Finding(
        finding_id="policy-finding",
        name="Log4Shell (test)",
        severity=Severity.CRITICAL,
        cve_ids=["CVE-2021-44228"],
        cvss_v3=CVSSV3Observation(
            base_score=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        ),
        asset=Asset(asset_id="asset-1", criticality="critical", internet_facing=True),
    )
    return finding, bundle


def test_p1_actions_require_approval_and_are_dry_run(services):
    finding, bundle = make_kev_internet_finding()
    record = build_investigation_record(finding, bundle)
    assessment = assess(finding, record)
    assert assessment.recommended_priority is not None
    assert assessment.recommended_priority.value == "P1"

    decision = evaluate_policy(
        finding,
        record,
        assessment,
        RiskPolicy(),
        services.settings,
        services.audit,
        services.pending,
    )
    assert PolicyAction.CREATE_REMEDIATION_TICKET in decision.recommended_actions
    assert decision.approved_actions == []  # default policy: everything needs a human
    assert PolicyAction.CREATE_REMEDIATION_TICKET in decision.pending_human_approval
    assert decision.dry_run is True
    actionable = [a for a in decision.recommended_actions if a != PolicyAction.NO_ACTION]
    assert len(decision.recorded_action_ids) == len(actionable)
    assert len(services.audit.recent(limit=10)) >= len(actionable)
    open_actions = services.pending.list_open(finding.finding_id)
    assert all(a["status"] == "pending_approval" for a in open_actions)


def test_allow_ticket_creation_queues_without_approval(services):
    finding, bundle = make_kev_internet_finding()
    record = build_investigation_record(finding, bundle)
    assessment = assess(finding, record)
    policy = RiskPolicy(require_approval=False, allow_ticket_creation=True)
    decision = evaluate_policy(
        finding,
        record,
        assessment,
        policy,
        services.settings,
        services.audit,
        services.pending,
    )
    assert PolicyAction.CREATE_REMEDIATION_TICKET in decision.approved_actions
    assert decision.dry_run is True  # settings-level dry run still applies


def test_suspected_fp_adds_escalation_and_keeps_finding(services):
    finding, bundle = make_kev_internet_finding()
    record = build_investigation_record(finding, bundle)
    record.applicability = ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
    assessment = assess(finding, record)
    decision = evaluate_policy(
        finding,
        record,
        assessment,
        RiskPolicy(),
        services.settings,
        services.audit,
        services.pending,
    )
    assert PolicyAction.ESCALATE_TO_OWNER in decision.recommended_actions
    assert any("not suppressed" in r for r in decision.priority_rationale)
