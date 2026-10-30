"""Risk assessment: separate, explainable dimensions — never a black-box score.

Each dimension is derived from independent intelligence and carries its own
rationale. The final remediation priority comes from a documented decision
table (see docs/risk-methodology.md), not from an opaque weighted score.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from riskproof.models.analysis import (
    BusinessImpact,
    EnvironmentalExposure,
    ExploitationLikelihood,
)
from riskproof.models.evidence import (
    ApplicabilityStatus,
    Confidence,
    EvidenceKind,
    InvestigationRecord,
)
from riskproof.models.findings import Finding, Severity, criticality_value
from riskproof.models.policy import Priority

_CVSS_METRIC_RE = re.compile(r"(AV|AC|PR|UI|S|C|I|A):([NALHRUC])")


def parse_cvss_metrics(vector: str | None) -> dict[str, str]:
    """Parse qualitative metrics out of a CVSS v3 vector string."""
    if not vector:
        return {}
    return dict(_CVSS_METRIC_RE.findall(vector))


_IMPACT_FROM_CRITICALITY = {
    "critical": BusinessImpact.SEVERE,
    "high": BusinessImpact.HIGH,
    "medium": BusinessImpact.MODERATE,
    "low": BusinessImpact.LOW,
    "unspecified": BusinessImpact.UNKNOWN,
}


class RiskAssessment(BaseModel):
    """All risk dimensions for one finding, each with its own rationale."""

    finding_id: str
    # Vulnerability severity (what the vendor/scanner says about the bug)
    severity_label: Severity = Severity.UNKNOWN
    cvss_base_score: float | None = None
    vpr_score: float | None = None
    severity_basis: list[str] = Field(default_factory=list)
    # Exploitation likelihood (how likely this CVE is exploited in the wild)
    exploitation_likelihood: ExploitationLikelihood = ExploitationLikelihood.UNKNOWN
    likelihood_basis: list[str] = Field(default_factory=list)
    # Environmental exposure (how reachable this asset is)
    environmental_exposure: EnvironmentalExposure = EnvironmentalExposure.UNKNOWN
    exposure_basis: list[str] = Field(default_factory=list)
    # Verified applicability (does the bug actually affect this system?)
    applicability: ApplicabilityStatus = ApplicabilityStatus.UNKNOWN
    applicability_basis: list[str] = Field(default_factory=list)
    # Business impact (what compromise of this asset would mean)
    business_impact: BusinessImpact = BusinessImpact.UNKNOWN
    business_impact_basis: list[str] = Field(default_factory=list)
    # Evidence confidence (how much we trust the picture above)
    evidence_confidence: Confidence = Confidence.MISSING
    confidence_basis: list[str] = Field(default_factory=list)
    # Recommended remediation priority (decision table, fully explained)
    recommended_priority: Priority | None = None
    priority_rationale: list[str] = Field(default_factory=list)


def _likelihood(
    finding: Finding, record: InvestigationRecord
) -> tuple[ExploitationLikelihood, list[str]]:
    intel = record.intel
    basis: list[str] = []
    if intel is None:
        return ExploitationLikelihood.UNKNOWN, ["No threat intelligence collected."]
    finding_cves = set(finding.cve_ids)
    kev_listed = [s for s in intel.kev_status if s.in_kev and s.cve in finding_cves]
    if kev_listed:
        for status in kev_listed:
            entry = status.entry
            detail = ""
            if entry and entry.known_ransomware_campaign_use:
                detail = f" (ransomware campaign use: {entry.known_ransomware_campaign_use})"
            basis.append(f"{status.cve} is listed in CISA KEV{detail}: exploited in the wild.")
        likelihood = ExploitationLikelihood.OBSERVED_IN_THE_WILD
    else:
        likelihood = ExploitationLikelihood.UNKNOWN
    for cve in finding.cve_ids:
        entry = (intel.epss or {}).get(cve)
        if entry is None:
            continue
        if entry.kind == "observation":
            caveat = (
                "EPSS is a statistical prediction that the CVE is exploited "
                "somewhere in the wild within 30 days — not a claim about this system."
            )
            if entry.score >= 0.5:
                basis.append(f"EPSS {entry.score:.3f} for {cve} is very high. {caveat}")
                if likelihood is ExploitationLikelihood.UNKNOWN:
                    likelihood = ExploitationLikelihood.ELEVATED
            elif entry.score >= 0.1:
                basis.append(f"EPSS {entry.score:.3f} for {cve} is elevated. {caveat}")
                if likelihood is ExploitationLikelihood.UNKNOWN:
                    likelihood = ExploitationLikelihood.ELEVATED
            elif entry.score >= 0.01:
                basis.append(f"EPSS {entry.score:.3f} for {cve} is moderate. {caveat}")
                if likelihood is ExploitationLikelihood.UNKNOWN:
                    likelihood = ExploitationLikelihood.MODERATE
            else:
                basis.append(f"EPSS {entry.score:.3f} for {cve} is low. {caveat}")
                if likelihood is ExploitationLikelihood.UNKNOWN:
                    likelihood = ExploitationLikelihood.LOW
        else:
            basis.append(f"EPSS unavailable for {cve}: {entry.reason}")
    if likelihood is ExploitationLikelihood.UNKNOWN and not basis:
        if finding.cve_ids:
            basis.append("No EPSS or KEV data available for this CVE set.")
        else:
            basis.append(
                "Finding has no CVE identifiers; exploitation likelihood "
                "cannot be derived from CVE-level intelligence."
            )
    return likelihood, basis


def _exposure(
    finding: Finding, record: InvestigationRecord
) -> tuple[EnvironmentalExposure, list[str]]:
    basis: list[str] = []
    exposure = EnvironmentalExposure.UNKNOWN
    validation = [e for e in record.evidence if e.kind == EvidenceKind.NETWORK_VALIDATION]
    if finding.asset.internet_facing is True:
        exposure = EnvironmentalExposure.INTERNET_FACING
        basis.append("Asset context marks this asset internet-facing.")
    elif finding.asset.internet_facing is False:
        exposure = EnvironmentalExposure.INTERNAL
        basis.append("Asset context marks this asset internal (not internet-facing).")
    for item in validation:
        if item.confidence == Confidence.CONFIRMED:
            exposure = (
                EnvironmentalExposure.INTERNET_FACING
                if finding.asset.internet_facing
                else EnvironmentalExposure.VERIFIED_REACHABLE
            )
            basis.append(item.statement)
        elif item.confidence == Confidence.INCONCLUSIVE:
            basis.append(
                item.statement + " Inconclusive result does NOT rule out exposure and does not "
                "suppress the finding."
            )
    if not basis:
        basis.append("Exposure unknown: no asset context or validation evidence.")
    return exposure, basis


def _evidence_confidence(
    record: InvestigationRecord,
) -> tuple[Confidence, list[str]]:
    if any(
        e.kind == EvidenceKind.NETWORK_VALIDATION and e.confidence == Confidence.VERIFICATION_FAILED
        for e in record.evidence
    ):
        return Confidence.VERIFICATION_FAILED, [
            "An authorized verification attempt failed to complete."
        ]
    intel = record.intel
    if intel is None:
        return Confidence.MISSING, ["No threat intel collected yet."]
    if intel.epss_source == "sample-fixture" or intel.kev_source == "sample-fixture":
        return Confidence.INCONCLUSIVE, [
            "Intelligence is SAMPLE fixture data (offline mode); conclusions are indicative only."
        ]
    if intel.epss_source == "unavailable" and intel.kev_source == "unavailable":
        return Confidence.MISSING, ["Live intel unreachable and no fixtures available."]
    return Confidence.CONFIRMED, ["Direct evidence from scanner and live intel feeds."]


def _priority(assessment_partial: dict) -> tuple[Priority, list[str]]:
    """Documented decision table. Order matters; first match wins."""
    rationale: list[str] = []
    kev = assessment_partial["likelihood"] == ExploitationLikelihood.OBSERVED_IN_THE_WILD
    exposure = assessment_partial["exposure"]
    impact = assessment_partial["impact"]
    likelihood = assessment_partial["likelihood"]
    severity = assessment_partial["severity"]
    vpr = assessment_partial["vpr"]
    elevated = likelihood == ExploitationLikelihood.ELEVATED

    priority: Priority | None = None
    if kev and exposure == EnvironmentalExposure.INTERNET_FACING:
        priority = Priority.P1
        rationale.append("KEV-listed (exploited in the wild) AND internet-facing.")
    elif kev and impact == BusinessImpact.SEVERE:
        priority = Priority.P1
        rationale.append("KEV-listed on a business-critical asset.")
    elif elevated and exposure in (
        EnvironmentalExposure.INTERNET_FACING,
        EnvironmentalExposure.VERIFIED_REACHABLE,
    ):
        priority = Priority.P1
        rationale.append("Elevated exploitation likelihood with confirmed reachability.")
    elif elevated and impact == BusinessImpact.SEVERE:
        priority = Priority.P1
        rationale.append("Elevated exploitation likelihood on a business-critical asset.")
    elif kev:
        priority = Priority.P2
        rationale.append("KEV-listed; exposure and criticality do not force P1.")
    elif elevated:
        priority = Priority.P2
        rationale.append("Elevated exploitation likelihood (EPSS).")
    elif severity in (Severity.CRITICAL, Severity.HIGH):
        priority = Priority.P2
        rationale.append(f"High scanner severity ({severity.value}) without exploitation intel.")
    elif severity == Severity.MEDIUM:
        priority = Priority.P3
        rationale.append("Medium scanner severity.")
    elif severity in (Severity.LOW, Severity.INFO):
        priority = Priority.P4
        rationale.append(f"Low-impact finding ({severity.value}); track only.")
    else:
        priority = Priority.P3
        rationale.append(
            "Insufficient evidence for automated prioritization; human review recommended."
        )

    if vpr is not None and vpr >= 7.0 and priority == Priority.P3:
        priority = Priority.P2
        rationale.append(f"Tenable VPR {vpr} supports elevated priority.")
    elif vpr is not None and vpr >= 9.0 and priority == Priority.P4:
        priority = Priority.P3
        rationale.append(f"Tenable VPR {vpr} lifts priority above track-only.")

    # A questioned applicability CAPS priority at P3 — it never zeroes it.
    if assessment_partial[
        "applicability"
    ] == ApplicabilityStatus.SUSPECTED_NOT_AFFECTED and priority in (Priority.P1, Priority.P2):
        priority = Priority.P3
        rationale.append(
            "Applicability is questioned (possible false positive); priority is "
            "capped at P3 pending human review — the finding is NOT suppressed."
        )
    return priority, rationale


def assess(finding: Finding, record: InvestigationRecord) -> RiskAssessment:
    """Assess one finding against its investigation record."""
    severity_basis: list[str] = [f"{finding.source} reported severity {finding.severity.value}."]
    if finding.cvss_v3:
        severity_basis.append(f"CVSS v3 base score {finding.cvss_v3.base_score}.")
    if finding.vpr:
        severity_basis.append(f"Tenable VPR {finding.vpr.score}.")

    likelihood, likelihood_basis = _likelihood(finding, record)
    exposure, exposure_basis = _exposure(finding, record)
    impact = _IMPACT_FROM_CRITICALITY[criticality_value(finding.asset)]
    impact_basis = (
        [f"Asset criticality recorded as {criticality_value(finding.asset)}."]
        if criticality_value(finding.asset) != "unspecified"
        else ["Asset criticality is not recorded; business impact unknown."]
    )
    confidence, confidence_basis = _evidence_confidence(record)

    partial = {
        "likelihood": likelihood,
        "exposure": exposure,
        "impact": impact,
        "severity": finding.severity,
        "vpr": finding.vpr.score if finding.vpr else None,
        "applicability": record.applicability,
    }
    priority, priority_rationale = _priority(partial)

    return RiskAssessment(
        finding_id=finding.finding_id,
        severity_label=finding.severity,
        cvss_base_score=finding.cvss_v3.base_score if finding.cvss_v3 else None,
        vpr_score=finding.vpr.score if finding.vpr else None,
        severity_basis=severity_basis,
        exploitation_likelihood=likelihood,
        likelihood_basis=likelihood_basis,
        environmental_exposure=exposure,
        exposure_basis=exposure_basis,
        applicability=record.applicability,
        applicability_basis=list(record.applicability_rationale),
        business_impact=impact,
        business_impact_basis=impact_basis,
        evidence_confidence=confidence,
        confidence_basis=confidence_basis,
        recommended_priority=priority,
        priority_rationale=priority_rationale,
    )
