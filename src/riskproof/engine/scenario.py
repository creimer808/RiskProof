"""Exploit scenario analysis: prerequisites, exposure, consequences, uncertainties.

The scenario states what intelligence supports — and explicitly does NOT claim
successful exploitation or compromise without direct evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime

from riskproof.engine.risk import RiskAssessment, parse_cvss_metrics
from riskproof.models.analysis import (
    ExploitationLikelihood,
    ExploitScenario,
    ScenarioConclusion,
)
from riskproof.models.evidence import Confidence, EvidenceKind, InvestigationRecord
from riskproof.models.findings import Finding

_PREREQ_BY_AV = {
    "N": "Attacker needs network access to the affected service.",
    "A": "Attacker needs adjacent-network access (same LAN/segment).",
    "L": "Attacker needs local access to the system.",
    "P": "Attacker needs physical access to the system.",
}
_PREREQ_BY_AC = {
    "L": "No unusual conditions required (low attack complexity).",
    "H": "Exploitation depends on conditions outside the attacker's control "
    "(high attack complexity) — less reliable in practice.",
}
_PREREQ_BY_PR = {
    "N": "No authentication required.",
    "L": "Requires low-privilege credentials.",
    "H": "Requires high-privilege credentials.",
}
_PREREQ_BY_UI = {
    "N": "No user interaction required.",
    "R": "Requires a user to interact (click/open/approve).",
}
_IMPACT_LABELS = {
    "C": ("Confidentiality", "information disclosure"),
    "I": ("Integrity", "data tampering"),
    "A": ("Availability", "service disruption"),
}


def build_exploit_scenario(
    finding: Finding, record: InvestigationRecord, assessment: RiskAssessment
) -> ExploitScenario:
    """Derive a structured scenario from recorded evidence only."""
    now = datetime.now(UTC)
    prerequisites: list[str] = []
    consequences: list[str] = []
    uncertainties: list[str] = []

    metrics = parse_cvss_metrics(finding.cvss_v3.vector if finding.cvss_v3 else None)
    if not metrics and finding.cvss_v3:
        uncertainties.append(
            "CVSS vector string missing; prerequisites derived from base score only."
        )
    if metrics:
        if label := _PREREQ_BY_AV.get(metrics.get("AV", "")):
            prerequisites.append(label)
        if label := _PREREQ_BY_AC.get(metrics.get("AC", "")):
            prerequisites.append(label)
        if label := _PREREQ_BY_PR.get(metrics.get("PR", "")):
            prerequisites.append(label)
        if label := _PREREQ_BY_UI.get(metrics.get("UI", "")):
            prerequisites.append(label)
        if metrics.get("S") == "C":
            prerequisites.append(
                "Scope change possible: successful exploitation may impact resources "
                "beyond the vulnerable component."
            )
        for code, (label, phrase) in _IMPACT_LABELS.items():
            if metrics.get(code) in ("H", "L"):
                degree = "High" if metrics[code] == "H" else "Limited"
                consequences.append(f"{degree} impact to {label.lower()} ({phrase}).")
    else:
        uncertainties.append(
            "No CVSS vector available; exploit prerequisites are unknown and must "
            "come from the advisory."
        )

    if assessment.environmental_exposure.name == "INTERNET_FACING":
        exposure_note = (
            "Asset is internet-facing per context; the attack prerequisite "
            "(network access) appears satisfied from outside the organization."
        )
    elif assessment.environmental_exposure.name == "VERIFIED_REACHABLE":
        exposure_note = (
            "An authorized connectivity check confirmed the service is reachable "
            "from the validation location."
        )
    elif assessment.environmental_exposure.name == "INTERNAL":
        exposure_note = (
            "Asset is internal per context; exploitation requires a foothold or "
            "adjacent access inside the network."
        )
    else:
        exposure_note = "Environmental exposure is unknown; treat as unconfirmed."
        uncertainties.append("Exposure unverified — request an authorized validation check.")
    exposure_analysis = [exposure_note]
    exposure_analysis.extend(assessment.exposure_basis)

    intel = record.intel
    finding_cves = set(finding.cve_ids)
    if intel is not None:
        for status in intel.kev_status:
            if status.in_kev and status.cve in finding_cves and status.entry:
                if (status.entry.known_ransomware_campaign_use or "").lower() == "known":
                    consequences.append(
                        f"{status.cve} is known to be used in ransomware campaigns "
                        "(CISA KEV). This is threat intelligence about the CVE — "
                        "there is no evidence this asset was compromised."
                    )
                else:
                    consequences.append(
                        f"{status.cve} is listed in CISA KEV as exploited in the wild."
                    )
    if finding.asset.criticality.value == "critical":
        consequences.append(
            "The affected asset is business-critical; compromise scenarios should "
            "assume significant business impact pending owner confirmation."
        )
    if not consequences:
        consequences.append("No specific consequences confirmed by evidence; consult the advisory.")

    uncertainties.append(
        "EPSS values are statistical probabilities for the CVE (30-day horizon), "
        "not evidence about this system."
    )
    if intel is not None and (intel.degraded or intel.epss_source == "sample-fixture"):
        uncertainties.append("Part of the intelligence is SAMPLE fixture data (offline mode).")
    for question in record.open_questions:
        uncertainties.append(question)

    conclusions: list[ScenarioConclusion] = []
    scanner_evidence = [e.id for e in record.evidence if e.kind == EvidenceKind.SCANNER_FINDING]
    conclusions.append(
        ScenarioConclusion(
            statement=(
                "The scanner reports the vulnerability present on this asset."
                if record.applicability.value != "suspected_not_affected"
                else "The scanner reports the vulnerability, but applicability is "
                "questioned by independent observation (human review required)."
            ),
            confidence=(
                Confidence.INFERRED
                if record.applicability.value == "likely_affected"
                else Confidence.CONFIRMED
                if record.applicability.value == "affected_evidenced"
                else Confidence.INCONCLUSIVE
            ),
            basis_evidence_ids=scanner_evidence,
        )
    )
    intel_evidence = [e.id for e in record.evidence if e.kind == EvidenceKind.THREAT_INTEL]
    if assessment.exploitation_likelihood == ExploitationLikelihood.OBSERVED_IN_THE_WILD:
        conclusions.append(
            ScenarioConclusion(
                statement=(
                    "This CVE is exploited in the wild per CISA KEV — raising the "
                    "operating assumption that exploits are available."
                ),
                confidence=Confidence.CONFIRMED,
                basis_evidence_ids=intel_evidence,
            )
        )
    else:
        conclusions.append(
            ScenarioConclusion(
                statement="No confirmed evidence of exploitation of this asset.",
                confidence=Confidence.INFERRED,
                basis_evidence_ids=intel_evidence,
            )
        )
    conclusions.append(
        ScenarioConclusion(
            statement="No claim of successful exploitation is made: none was observed.",
            confidence=Confidence.CONFIRMED,
            basis_evidence_ids=[],
        )
    )

    return ExploitScenario(
        finding_id=finding.finding_id,
        generated_at=now,
        exploit_prerequisites=prerequisites,
        exposure_analysis=exposure_analysis,
        potential_consequences=consequences,
        exploitation_likelihood=assessment.exploitation_likelihood,
        likelihood_basis=list(assessment.likelihood_basis),
        conclusions=conclusions,
        uncertainties=uncertainties,
        evidence_ids=[e.id for e in record.evidence],
    )
