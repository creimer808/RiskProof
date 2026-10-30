"""Evidence models: what we know, how we know it, and how much to trust it.

RiskProof distinguishes four confidence states (plus one mixed state):

* CONFIRMED             — direct evidence (a scanner report, a live feed value,
                          an authorized check result on the record)
* INFERRED              — a conclusion derived from evidence, not directly
                          observed
* MISSING               — information we do not have
* INCONCLUSIVE          — mixed or partial evidence (e.g. fixture-backed intel)
* VERIFICATION_FAILED   — an authorized verification ran and could not confirm
                          the expected state

Negative or inconclusive validation results never automatically suppress a
finding; they are recorded as evidence with the corresponding confidence.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from riskproof.models.intel import ThreatIntelBundle


class EvidenceKind(StrEnum):
    SCANNER_FINDING = "scanner_finding"
    THREAT_INTEL = "threat_intel"
    ASSET_CONTEXT = "asset_context"
    NETWORK_VALIDATION = "network_validation"
    CONFIG_OBSERVATION = "config_observation"
    EXTERNAL_ADVISORY = "external_advisory"
    DERIVED_ANALYSIS = "derived_analysis"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    MISSING = "missing"
    INCONCLUSIVE = "inconclusive"
    VERIFICATION_FAILED = "verification_failed"


class ApplicabilityStatus(StrEnum):
    """Whether the vulnerability appears to affect the target system.

    ``SUSPECTED_NOT_AFFECTED`` is a lead for a human, never an automatic
    suppression: findings keep their priority (capped, not zeroed).
    """

    AFFECTED_EVIDENCED = "affected_evidenced"
    LIKELY_AFFECTED = "likely_affected"
    SUSPECTED_NOT_AFFECTED = "suspected_not_affected"
    UNKNOWN = "unknown"
    VERIFICATION_FAILED = "verification_failed"


class InvestigationStatus(StrEnum):
    OPEN = "open"
    ENRICHED = "enriched"
    AWAITING_VALIDATION = "awaiting_validation"
    VERIFIED_APPLICABLE = "verified_applicable"
    VERIFICATION_FAILED = "verification_failed"


class Evidence(BaseModel):
    """A single piece of evidence with provenance and confidence."""

    id: str = Field(min_length=1, max_length=128)
    finding_id: str = Field(min_length=1, max_length=256)
    kind: EvidenceKind
    statement: str = Field(min_length=1, max_length=2_000)
    confidence: Confidence
    source: str = Field(max_length=256)
    collected_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)


class InvestigationRecord(BaseModel):
    """The evolving evidence file for one finding."""

    finding_id: str
    created_at: datetime
    updated_at: datetime
    status: InvestigationStatus = InvestigationStatus.OPEN
    evidence: list[Evidence] = Field(default_factory=list)
    applicability: ApplicabilityStatus = ApplicabilityStatus.UNKNOWN
    applicability_rationale: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    intel: ThreatIntelBundle | None = None
