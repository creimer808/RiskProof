"""Remediation simulation: compare proposed fixes and their expected effects.

Options and effects are deterministic heuristics over recorded evidence, clearly
labeled as a simulation. Nothing is executed.
"""

from __future__ import annotations

from datetime import UTC, datetime

from riskproof.engine.risk import RiskAssessment
from riskproof.models.analysis import (
    RemediationActionType,
    RemediationOption,
    RemediationSimulation,
)
from riskproof.models.evidence import Confidence, InvestigationRecord
from riskproof.models.findings import Finding


def simulate_remediation(
    finding: Finding, record: InvestigationRecord, assessment: RiskAssessment
) -> RemediationSimulation:
    now = datetime.now(UTC)
    evidence_ids = [e.id for e in record.evidence]
    options: list[RemediationOption] = []

    if finding.solution:
        options.append(
            RemediationOption(
                id="opt-vendor-fix",
                action_type=RemediationActionType.APPLY_PATCH,
                title="Apply vendor fix",
                description=finding.solution[:1000],
                expected_effect={
                    "applicability": "vulnerability removed once fix applied",
                    "severity": "unchanged until re-scan confirms resolution",
                },
                residual_risk_notes=[
                    "Requires change window and testing on the affected service.",
                    "Resolution must be confirmed by an authenticated re-scan.",
                ],
                dependencies=["vendor fix available", "change approval"],
                evidence_ids=evidence_ids,
                confidence=Confidence.INFERRED,
            )
        )
    elif finding.cve_ids:
        options.append(
            RemediationOption(
                id="opt-vendor-fix",
                action_type=RemediationActionType.UPGRADE,
                title="Upgrade affected software to a fixed version",
                description=(
                    "Identify the fixed version from the upstream advisory for "
                    f"{', '.join(finding.cve_ids)} and upgrade the affected component."
                ),
                expected_effect={
                    "applicability": "vulnerability removed once upgrade applied",
                },
                residual_risk_notes=[
                    "Confirm the fixed version applies to this product edition.",
                    "Resolution must be confirmed by an authenticated re-scan.",
                ],
                dependencies=["upstream advisory", "change approval"],
                evidence_ids=evidence_ids,
                confidence=Confidence.INFERRED,
            )
        )

    if assessment.environmental_exposure.name in ("INTERNET_FACING", "VERIFIED_REACHABLE"):
        options.append(
            RemediationOption(
                id="opt-restrict-exposure",
                action_type=RemediationActionType.COMPENSATING_CONTROL,
                title="Restrict network exposure of the affected service",
                description=(
                    "Limit reachability of the service (firewall/ACL/WAF) to the "
                    "minimum required population while the permanent fix is staged."
                ),
                expected_effect={
                    "environmental_exposure": "reduced (reachable population limited)",
                    "recommended_priority": "may drop one level on reassessment",
                },
                residual_risk_notes=[
                    "The vulnerability itself remains present on the asset.",
                    "Compensating controls require monitoring to stay effective.",
                ],
                dependencies=["network team engagement"],
                evidence_ids=evidence_ids,
                confidence=Confidence.INFERRED,
            )
        )

    options.append(
        RemediationOption(
            id="opt-request-rescan",
            action_type=RemediationActionType.REQUEST_RESCAN,
            title="Request an authenticated re-scan after changes",
            description=(
                "After any remediation or control change, request a credentialed "
                "re-scan of the asset to verify the expected state."
            ),
            expected_effect={
                "evidence_confidence": "confirmed via fresh scanner evidence",
            },
            residual_risk_notes=["Verification only — changes nothing by itself."],
            dependencies=["scanner scheduling"],
            evidence_ids=evidence_ids,
            confidence=Confidence.CONFIRMED,
        )
    )

    recommended = None
    rationale: list[str] = []
    fix_types = (RemediationActionType.APPLY_PATCH, RemediationActionType.UPGRADE)
    if any(o.action_type in fix_types for o in options):
        recommended = "opt-vendor-fix"
        rationale.append("Removing the vulnerability (vendor fix/upgrade) is recommended first.")
        if assessment.exploitation_likelihood.name == "OBSERVED_IN_THE_WILD":
            rationale.append(
                "The CVE is KEV-listed; exploit availability makes removal urgent "
                "(P1/P2 per the decision table)."
            )
    elif options:
        recommended = options[0].id
        rationale.append(
            "No vendor fix recorded on the finding; lead with the first available option."
        )
    if assessment.environmental_exposure.name in ("INTERNET_FACING", "VERIFIED_REACHABLE"):
        rationale.append("Combine the fix with exposure restriction while the change is pending.")
    rationale.append("Always finish with a verification re-scan (opt-request-rescan).")

    return RemediationSimulation(
        finding_id=finding.finding_id,
        generated_at=now,
        options=options,
        recommended_option_id=recommended,
        rationale=rationale,
    )
