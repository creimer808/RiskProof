"""Policy evaluation: thresholds in, authorized actions out — with an audit trail.

The policy engine is the ONLY component that may propose actions, and every
action is recorded. Dry-run and approval requirements come from server
settings; tool input can never relax them.
"""

from __future__ import annotations

from datetime import UTC, datetime

from riskproof.config import Settings
from riskproof.engine.risk import RiskAssessment
from riskproof.models.evidence import ApplicabilityStatus
from riskproof.models.findings import Finding
from riskproof.models.policy import PolicyAction, PolicyDecision, Priority, RiskPolicy
from riskproof.storage.repositories import AuditLog, PendingActionRepository

_PRIORITY_ACTIONS: dict[Priority, list[PolicyAction]] = {
    Priority.P1: [PolicyAction.CREATE_REMEDIATION_TICKET, PolicyAction.REQUEST_RESCAN],
    Priority.P2: [PolicyAction.CREATE_REMEDIATION_TICKET, PolicyAction.REQUEST_RESCAN],
    Priority.P3: [PolicyAction.ESCALATE_TO_OWNER],
    Priority.P4: [PolicyAction.NO_ACTION],
}


def _actions_for(
    priority: Priority | None, applicability: ApplicabilityStatus
) -> list[PolicyAction]:
    actions = list(_PRIORITY_ACTIONS.get(priority, [PolicyAction.NO_ACTION]))
    if (
        applicability == ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
        and PolicyAction.ESCALATE_TO_OWNER not in actions
    ):
        actions.append(PolicyAction.ESCALATE_TO_OWNER)
    if actions != [PolicyAction.NO_ACTION]:
        actions = [a for a in actions if a != PolicyAction.NO_ACTION]
    return actions or [PolicyAction.NO_ACTION]


def evaluate_policy(
    finding: Finding,
    record_unused: object,
    assessment: RiskAssessment,
    policy: RiskPolicy,
    settings: Settings,
    audit: AuditLog,
    pending: PendingActionRepository,
) -> PolicyDecision:
    now = datetime.now(UTC)
    priority = assessment.recommended_priority
    recommended = _actions_for(priority, assessment.applicability)

    approved: list[PolicyAction] = []
    requires_approval: list[PolicyAction] = []
    recorded_ids: list[str] = []
    existing_ids: list[str] = []

    priority_label = priority.value if priority else None
    for action in recommended:
        if action == PolicyAction.NO_ACTION:
            continue
        needs_approval = policy.require_approval or (
            action == PolicyAction.CREATE_REMEDIATION_TICKET and not policy.allow_ticket_creation
        )
        if needs_approval:
            requires_approval.append(action)
            status = "pending_approval"
            payload = {
                "priority": priority_label,
                "policy": policy.name,
                "dry_run": settings.dry_run,
            }
            outcome = "pending_human_approval"
            reason = f"Priority {priority_label or 'n/a'} under policy {policy.name}."
        else:
            approved.append(action)
            status = "queued_dry_run" if settings.dry_run else "queued"
            payload = {"priority": priority_label}
            outcome = "dry_run_recorded" if settings.dry_run else "queued"
            reason = f"Policy {policy.name} permits this action without approval."

        # Idempotent: re-evaluating a finding reuses an identical outstanding
        # action rather than queueing a duplicate. The re-evaluation itself is
        # still audited so the decision chain stays complete.
        existing_id = pending.find_open(finding.finding_id, action.value, status)
        if existing_id is not None:
            recorded_ids.append(str(existing_id))
            existing_ids.append(str(existing_id))
            audit.append(
                actor=settings.audit_actor,
                action=f"policy:{action.value}",
                subject=finding.finding_id,
                outcome="already_recorded",
                rationale=f"{reason} Reusing outstanding action {existing_id} ({status}).",
                details={"dry_run": settings.dry_run, "existing_action_id": existing_id},
            )
            continue

        action_id = pending.add(
            finding_id=finding.finding_id, action=action.value, status=status, payload=payload
        )
        recorded_ids.append(str(action_id))
        audit.append(
            actor=settings.audit_actor,
            action=f"policy:{action.value}",
            subject=finding.finding_id,
            outcome=outcome,
            rationale=reason,
            details={"dry_run": settings.dry_run},
        )

    rationale = list(assessment.priority_rationale)
    if assessment.applicability == ApplicabilityStatus.SUSPECTED_NOT_AFFECTED:
        rationale.append(
            "Applicability flagged for human review; finding retained, not suppressed."
        )
    if requires_approval and settings.dry_run:
        rationale.append("Dry-run mode: all actions were recorded for human execution only.")

    return PolicyDecision(
        finding_id=finding.finding_id,
        evaluated_at=now,
        policy_name=policy.name,
        priority=priority,
        priority_rationale=rationale,
        recommended_actions=recommended,
        approved_actions=approved,
        pending_human_approval=requires_approval,
        dry_run=settings.dry_run,
        applicability=assessment.applicability,
        recorded_action_ids=recorded_ids,
        existing_action_ids=existing_ids,
    )
