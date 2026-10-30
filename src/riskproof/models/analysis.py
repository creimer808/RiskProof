"""Analysis models: exploit scenarios and remediation simulations."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from riskproof.models.evidence import Confidence


class ExploitationLikelihood(StrEnum):
    """Likelihood that this CVE is exploited, from independent intelligence.

    ``OBSERVED_IN_THE_WILD`` (KEV listing) is a claim about the vulnerability
    worldwide — never proof that this asset was compromised.
    """

    OBSERVED_IN_THE_WILD = "observed_in_the_wild"
    ELEVATED = "elevated"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


class EnvironmentalExposure(StrEnum):
    INTERNET_FACING = "internet_facing"
    VERIFIED_REACHABLE = "verified_reachable"
    INTERNAL = "internal"
    VERIFIED_UNREACHABLE = "verified_unreachable"
    UNKNOWN = "unknown"


class BusinessImpact(StrEnum):
    SEVERE = "severe"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


class ScenarioConclusion(BaseModel):
    """One stated conclusion with its confidence and supporting evidence."""

    statement: str
    confidence: Confidence
    basis_evidence_ids: list[str] = Field(default_factory=list)


class ExploitScenario(BaseModel):
    """Structured, evidence-linked exploitation scenario analysis."""

    finding_id: str
    generated_at: datetime
    exploit_prerequisites: list[str] = Field(default_factory=list)
    exposure_analysis: list[str] = Field(default_factory=list)
    potential_consequences: list[str] = Field(default_factory=list)
    exploitation_likelihood: ExploitationLikelihood = ExploitationLikelihood.UNKNOWN
    likelihood_basis: list[str] = Field(default_factory=list)
    conclusions: list[ScenarioConclusion] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class RemediationActionType(StrEnum):
    APPLY_PATCH = "apply_patch"
    UPGRADE = "upgrade"
    CONFIG_CHANGE = "config_change"
    COMPENSATING_CONTROL = "compensating_control"
    REQUEST_RESCAN = "request_rescan"


class RemediationOption(BaseModel):
    """One candidate remediation with its expected effect on risk."""

    id: str
    action_type: RemediationActionType
    title: str
    description: str
    #: Dimension -> expected qualitative effect, e.g. {"severity": "resolved"}
    expected_effect: dict[str, str] = Field(default_factory=dict)
    residual_risk_notes: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.INFERRED


class RemediationSimulation(BaseModel):
    """What-if comparison of remediation options (a simulation, not a promise)."""

    finding_id: str
    generated_at: datetime
    options: list[RemediationOption] = Field(default_factory=list)
    recommended_option_id: str | None = None
    rationale: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "Simulation only: expected effects are deterministic heuristics over the "
        "recorded evidence, not guarantees. Re-scan after any change to verify."
    )
