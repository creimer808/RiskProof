"""Evidence assembly: turn findings, intel, and validation into an evidence file.

Every statement distinguishes what was directly observed (CONFIRMED), what is
inferred, what is missing, or what failed verification. EPSS statements always
carry the statistical caveat; KEV sample data is never treated as authoritative.
"""

from __future__ import annotations

from datetime import UTC, datetime

from riskproof.models.evidence import (
    ApplicabilityStatus,
    Confidence,
    Evidence,
    EvidenceKind,
    InvestigationRecord,
    InvestigationStatus,
)
from riskproof.models.findings import Finding, ServiceObservation, criticality_value
from riskproof.models.intel import ThreatIntelBundle
from riskproof.storage.repositories import make_record
from riskproof.validation.checks import ValidationResult

_sequence = 0


def _next_id(prefix: str, now: datetime) -> str:
    global _sequence
    _sequence += 1
    return f"{prefix}-{now.strftime('%Y%m%d%H%M%S')}-{_sequence:04d}"


def _scanner_evidence(finding: Finding, now: datetime) -> Evidence:
    where = finding.asset.hostname or finding.asset.asset_id
    if finding.port:
        where += f":{finding.port}/{finding.protocol or 'tcp'}"
    return Evidence(
        id=_next_id("ev-scan", now),
        finding_id=finding.finding_id,
        kind=EvidenceKind.SCANNER_FINDING,
        statement=(
            f"{finding.source} reported '{finding.name}' "
            f"(severity {finding.severity.value}) on {where}."
        ),
        confidence=Confidence.CONFIRMED,
        source=finding.source,
        collected_at=now,
        details={
            "plugin_id": finding.plugin_id,
            "cvss_v3": finding.cvss_v3.base_score if finding.cvss_v3 else None,
            "vpr": finding.vpr.score if finding.vpr else None,
        },
    )


def _epss_evidence(cve: str, intel: ThreatIntelBundle, finding_id: str, now: datetime) -> Evidence:
    entry = intel.epss.get(cve)
    if entry is None:
        statement, confidence = f"No EPSS data was returned for {cve}.", Confidence.MISSING
    elif entry.kind == "observation":
        percentile = f"{entry.percentile:.5f}" if entry.percentile is not None else "n/a"
        statement = (
            f"FIRST EPSS for {cve}: {entry.score:.3f} (percentile {percentile}). "
            "Statistical 30-day in-the-wild exploitation probability for the CVE — "
            "not a claim about this specific system."
        )
        confidence = Confidence.CONFIRMED
    else:
        statement = f"EPSS unavailable for {cve}: {entry.reason}"
        confidence = Confidence.MISSING
    return Evidence(
        id=_next_id("ev-epss", now),
        finding_id=finding_id,
        kind=EvidenceKind.THREAT_INTEL,
        statement=statement,
        confidence=confidence,
        source=intel.epss_source,
        collected_at=now,
    )


def _kev_evidence(cve: str, intel: ThreatIntelBundle, finding_id: str, now: datetime) -> Evidence:
    status = next((s for s in intel.kev_status if s.cve == cve), None)
    if status is None:
        return Evidence(
            id=_next_id("ev-kev", now),
            finding_id=finding_id,
            kind=EvidenceKind.THREAT_INTEL,
            statement=f"KEV status unknown for {cve}.",
            confidence=Confidence.MISSING,
            source=intel.kev_source or "none",
            collected_at=now,
        )
    if status.in_kev:
        entry = status.entry
        added = entry.date_added if entry else "unknown"
        ransomware = entry.known_ransomware_campaign_use if entry else "unknown"
        statement = (
            f"{cve} is in the CISA KEV catalog ({status.catalog}; added {added}; "
            f"ransomware campaign use: {ransomware}). This means the vulnerability "
            "is exploited in the wild — not that this asset was compromised."
        )
        confidence = Confidence.CONFIRMED
    else:
        note = (
            ""
            if status.catalog == "cisa-live"
            else " (SAMPLE catalog: absence is NOT evidence of absence)"
        )
        statement = f"{cve} was not found in the checked KEV catalog{note}."
        confidence = (
            Confidence.CONFIRMED if status.catalog == "cisa-live" else Confidence.INCONCLUSIVE
        )
    return Evidence(
        id=_next_id("ev-kev", now),
        finding_id=finding_id,
        kind=EvidenceKind.THREAT_INTEL,
        statement=statement,
        confidence=confidence,
        source=status.catalog,
        collected_at=now,
    )


def _asset_evidence(finding: Finding, now: datetime) -> Evidence:
    asset = finding.asset
    crit = criticality_value(asset)
    if crit == "unspecified":
        return Evidence(
            id=_next_id("ev-asset", now),
            finding_id=finding.finding_id,
            kind=EvidenceKind.ASSET_CONTEXT,
            statement="Asset context present but criticality/environment are not recorded.",
            confidence=Confidence.MISSING,
            source="asset-catalog",
            collected_at=now,
        )
    if asset.internet_facing is True:
        exposure = "internet-facing"
    elif asset.internet_facing is False:
        exposure = "internal"
    else:
        exposure = "exposure unknown"
    return Evidence(
        id=_next_id("ev-asset", now),
        finding_id=finding.finding_id,
        kind=EvidenceKind.ASSET_CONTEXT,
        statement=(
            f"Asset {asset.asset_id}: criticality {crit}, "
            f"environment {asset.environment or 'unknown'}, {exposure}."
        ),
        confidence=Confidence.CONFIRMED,
        source="asset-catalog",
        collected_at=now,
    )


def _open_questions(finding: Finding, intel: ThreatIntelBundle | None) -> list[str]:
    questions: list[str] = []
    if not finding.cve_ids:
        questions.append("Finding has no CVE identifiers; external intelligence is limited.")
    if intel is not None:
        for cve in finding.cve_ids:
            entry = intel.epss.get(cve)
            if entry is None or entry.kind != "observation":
                questions.append(f"No EPSS observation available for {cve}.")
    if finding.asset.internet_facing is None:
        questions.append("Internet exposure of the asset is unknown.")
    if criticality_value(finding.asset) == "unspecified":
        questions.append("Asset criticality is not recorded.")
    if not finding.plugin_output:
        questions.append("No plugin output captured to verify the affected version.")
    return questions


def _initial_applicability(finding: Finding) -> tuple[ApplicabilityStatus, list[str]]:
    """Baseline applicability from scanner claims only (no independent check yet)."""
    if finding.severity.value == "info":
        return ApplicabilityStatus.UNKNOWN, [
            "Informational finding; applicability is not asserted by the scanner."
        ]
    if finding.cve_ids:
        return ApplicabilityStatus.LIKELY_AFFECTED, [
            "Scanner active check asserts the vulnerability is present "
            "(scanner-reported, not yet independently verified)."
        ]
    return ApplicabilityStatus.UNKNOWN, [
        "No CVEs on this finding; applicability cannot be assessed yet."
    ]


def build_investigation_record(
    finding: Finding, intel: ThreatIntelBundle | None = None
) -> InvestigationRecord:
    """Create the initial evidence file for a finding (with optional intel)."""
    record = make_record(finding.finding_id)
    now = record.created_at
    record.evidence.append(_scanner_evidence(finding, now))
    if intel is not None:
        record.intel = intel
        for cve in finding.cve_ids:
            record.evidence.append(_epss_evidence(cve, intel, finding.finding_id, now))
            record.evidence.append(_kev_evidence(cve, intel, finding.finding_id, now))
    record.evidence.append(_asset_evidence(finding, now))

    record.open_questions = _open_questions(finding, intel)
    record.applicability, record.applicability_rationale = _initial_applicability(finding)
    record.status = InvestigationStatus.ENRICHED if intel is not None else InvestigationStatus.OPEN
    record.updated_at = datetime.now(UTC)
    return record


#: Evidence kinds rebuilt from the finding + intel on every investigation. All
#: other kinds (validation results, config observations, ...) were gathered by
#: later steps and must survive a re-investigation.
REGENERATED_EVIDENCE_KINDS = frozenset(
    {EvidenceKind.SCANNER_FINDING, EvidenceKind.THREAT_INTEL, EvidenceKind.ASSET_CONTEXT}
)

#: Applicability outcomes that only a verification step can produce; the
#: scanner-only baseline must never overwrite them.
VERIFIED_APPLICABILITY = frozenset(
    {
        ApplicabilityStatus.AFFECTED_EVIDENCED,
        ApplicabilityStatus.SUSPECTED_NOT_AFFECTED,
        ApplicabilityStatus.VERIFICATION_FAILED,
    }
)

CARRIED_FORWARD_NOTE = (
    "Applicability verdict carried forward from an earlier verification; re-run "
    "verify_applicability if the scanner evidence has changed."
)


def carry_forward(prior: InvestigationRecord, fresh: InvestigationRecord) -> InvestigationRecord:
    """Merge a re-investigation into the existing record without losing work.

    ``fresh`` supplies regenerated scanner/intel/asset evidence; ``prior``
    supplies everything gathered after the first investigation (validation
    evidence, verified applicability) and the original creation time.
    """
    fresh.created_at = prior.created_at
    fresh.evidence.extend(e for e in prior.evidence if e.kind not in REGENERATED_EVIDENCE_KINDS)
    if prior.applicability in VERIFIED_APPLICABILITY:
        fresh.applicability = prior.applicability
        fresh.applicability_rationale = list(prior.applicability_rationale)
        if CARRIED_FORWARD_NOTE not in fresh.applicability_rationale:
            fresh.applicability_rationale.append(CARRIED_FORWARD_NOTE)
    return fresh


def build_validation_evidence(result: ValidationResult, finding_id: str) -> Evidence:
    """Map a validation result to evidence with honest confidence."""
    confidence = Confidence.CONFIRMED if result.status == "verified" else Confidence.INCONCLUSIVE
    return Evidence(
        id=_next_id("ev-val", result.checked_at),
        finding_id=finding_id,
        kind=EvidenceKind.NETWORK_VALIDATION,
        statement=result.evidence_statement(),
        confidence=confidence,
        source=f"riskproof-validation:{result.method}",
        collected_at=result.checked_at,
        details={"port": result.port, "target": result.target},
    )


def apply_applicability_observation(
    record: InvestigationRecord,
    finding: Finding,
    observed: ServiceObservation | None = None,
) -> InvestigationRecord:
    """Reassess applicability, optionally against a live-observed service.

    A version mismatch produces SUSPECTED_NOT_AFFECTED — a lead for human
    review, never an automatic suppression.
    """
    rationale = list(record.applicability_rationale)
    status = record.applicability

    if observed is not None and observed.version and finding.plugin_output:
        version = observed.version.strip()
        if version and version in finding.plugin_output:
            status = ApplicabilityStatus.AFFECTED_EVIDENCED
            rationale.append(
                f"Observed service version {version} appears in the vulnerability's "
                "affected-version evidence."
            )
        elif version:
            status = ApplicabilityStatus.SUSPECTED_NOT_AFFECTED
            rationale.append(
                f"Observed service version {version} does NOT appear in the scanner's "
                "affected-version evidence. Possible false-positive lead for human "
                "review — the finding is not suppressed."
            )
    record.applicability = status
    record.applicability_rationale = rationale
    record.updated_at = datetime.now(UTC)
    return record
