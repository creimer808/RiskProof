"""Risk policy models: transparent priorities and authorized actions."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from riskproof.models.evidence import ApplicabilityStatus


class Priority(StrEnum):
    """Recommended remediation priority derived from the decision table.

    This is NOT a black-box score: every assignment carries its rationale.
    """

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class PolicyAction(StrEnum):
    CREATE_REMEDIATION_TICKET = "create_remediation_ticket"
    REQUEST_RESCAN = "request_rescan"
    ESCALATE_TO_OWNER = "escalate_to_owner"
    NO_ACTION = "no_action"


class RiskPolicy(BaseModel):
    """Organization policy thresholds and action authorization.

    ``allow_ticket_creation`` is False by default: milestone 0 records actions
    for human execution instead of creating tickets in external systems.
    """

    name: str = "default"
    epss_elevated_threshold: float = 0.1
    epss_very_high_threshold: float = 0.5
    allow_ticket_creation: bool = False
    require_approval: bool = True


class PolicyDecision(BaseModel):
    """The outcome of evaluating one finding against a policy."""

    finding_id: str
    evaluated_at: datetime
    policy_name: str
    priority: Priority | None = None
    priority_rationale: list[str] = Field(default_factory=list)
    recommended_actions: list[PolicyAction] = Field(default_factory=list)
    approved_actions: list[PolicyAction] = Field(default_factory=list)
    pending_human_approval: list[PolicyAction] = Field(default_factory=list)
    dry_run: bool = True
    applicability: ApplicabilityStatus = ApplicabilityStatus.UNKNOWN
    recorded_action_ids: list[str] = Field(default_factory=list)
