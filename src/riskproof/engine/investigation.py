"""Investigation orchestration: ingest -> enrich -> evidence -> assessment.

This module is the connective tissue the MCP tools call. It enforces the
"exactly one selector" rule, persists findings and records, and keeps fixture
degradation explicit in every output.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel

from riskproof.engine import policy_engine
from riskproof.engine.evidence import (
    apply_applicability_observation,
    build_investigation_record,
    build_validation_evidence,
    carry_forward,
)
from riskproof.engine.risk import RiskAssessment, assess
from riskproof.errors import (
    AuthorizationDenied,
    InvalidInputError,
    NotFoundError,
    ProviderUnavailable,
)
from riskproof.ingest.fixtures import (
    attach_asset_context,
    load_assets_fixture,
    load_findings_fixture,
)
from riskproof.models.evidence import InvestigationRecord
from riskproof.models.findings import Finding, ServiceObservation
from riskproof.models.intel import (
    EPSSObservation,
    EPSSUnavailable,
    KEVStatus,
    ThreatIntelBundle,
)
from riskproof.models.policy import PolicyDecision, RiskPolicy
from riskproof.providers.base import ProviderError
from riskproof.providers.fixtures_source import SAMPLE_NOTICE
from riskproof.services import Services
from riskproof.validation.checks import ValidationResult

MAX_FIXTURE_FINDINGS = 25

IntelSource = Literal["auto", "live", "fixture"]


class InvestigationReport(BaseModel):
    finding_id: str
    finding: Finding
    record: InvestigationRecord
    assessment: RiskAssessment


def normalize_cve_list(cve_ids: list[str]) -> tuple[list[str], list[str]]:
    """Split raw CVE strings into (valid_normalized, invalid_notices)."""
    import re

    valid: list[str] = []
    notices: list[str] = []
    pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    for raw in cve_ids:
        candidate = raw.strip().upper()
        if not pattern.match(candidate):
            notices.append(f"Ignored invalid CVE identifier {raw!r}.")
        elif candidate not in valid:
            valid.append(candidate)
    return valid, notices


async def enrich_threat_intel(
    services: Services, cve_ids: list[str], source: IntelSource = "auto"
) -> ThreatIntelBundle:
    """Collect EPSS + KEV intelligence with explicit sourcing and degradation."""
    cves, notices = normalize_cve_list(cve_ids)
    now = datetime.now(UTC)
    degraded = False
    epss_data: dict[str, EPSSObservation | EPSSUnavailable] = {}
    kev_data: list[KEVStatus] = []
    epss_source: str = "unavailable"
    kev_source: str = "unavailable"

    # "live" must NEVER substitute fixtures (explicit user intent), even when
    # the server is in offline mode. "auto" uses fixtures in offline mode.
    use_fixture = source == "fixture" or (source == "auto" and services.settings.offline)
    if not use_fixture:
        try:
            epss_data = await services.epss.fetch(cves)
            epss_source = "first.org"
        except ProviderError as exc:
            degraded = True
            notices.append(f"Live EPSS fetch failed: {exc}")
        try:
            kev_data = await services.kev.status_for(cves)
            kev_source = "cisa-live"
        except ProviderError as exc:
            degraded = True
            notices.append(f"Live KEV fetch failed: {exc}")

        if source == "live" and (epss_source == "unavailable" or kev_source == "unavailable"):
            # Explicit live request: report the gap honestly, no fixture fallback.
            for cve in cves:
                if cve not in epss_data:
                    epss_data[cve] = EPSSUnavailable(
                        cve=cve, reason="live EPSS unavailable (see notices)"
                    )
            for cve in cves:
                if cve not in {s.cve for s in kev_data}:
                    kev_data.append(
                        KEVStatus(
                            cve=cve,
                            in_kev=False,
                            catalog="cisa-live",
                            entry=None,
                            checked_at=now,
                        )
                    )
            notices.append(
                "Live intel was explicitly requested but is incomplete; absence "
                "here means 'unavailable', NOT 'not exploitable'."
            )

    if use_fixture or (degraded and source == "auto"):
        if degraded and source == "auto":
            notices.append(
                "Falling back to SAMPLE fixture intelligence (clearly labeled; "
                "values are indicative, not live)."
            )
        fixture = services.fixture_intel
        try:
            fixture_epss = await fixture.fetch_epss(cves)
            for cve in cves:
                if cve in fixture_epss:
                    epss_data[cve] = fixture_epss[cve]
                elif cve not in epss_data:
                    epss_data[cve] = EPSSUnavailable(
                        cve=cve, reason="not present in SAMPLE EPSS fixture"
                    )
            epss_source = "sample-fixture"
            kev_data = await fixture.kev_status_for(cves)
            kev_source = "sample-fixture"
            notices.append(SAMPLE_NOTICE)
            degraded = degraded or source == "fixture"
        except ProviderError as exc:
            raise ProviderUnavailable(str(exc)) from exc

    bundle = ThreatIntelBundle(
        cve_ids=cves,
        epss=epss_data,
        kev_status=kev_data,
        collected_at=now,
        epss_source=epss_source,  # type: ignore[arg-type]
        kev_source=kev_source,  # type: ignore[arg-type]
        degraded=degraded or "sample-fixture" in (epss_source, kev_source),
        notices=notices,
    )
    services.audit.append(
        actor=services.settings.audit_actor,
        action="enrich_threat_intel",
        subject=",".join(cves) or None,
        outcome="ok",
        rationale=f"source={bundle.epss_source}/{bundle.kev_source}; degraded={bundle.degraded}",
    )
    return bundle


def _load_fixture_findings(services: Services, fixture: str) -> list[Finding]:
    if "/" in fixture or ".." in fixture or fixture.startswith("."):
        raise InvalidInputError("Fixture must be a bare file name inside the fixtures directory.")
    path = services.settings.effective_fixtures_dir / fixture
    findings = load_findings_fixture(path)
    try:
        assets_path = services.settings.effective_fixtures_dir / "assets_sample.json"
        assets = load_assets_fixture(assets_path)
    except InvalidInputError:
        assets = {}
    return attach_asset_context(findings, assets)


async def investigate(
    services: Services,
    finding: Finding | None = None,
    fixture: str | None = None,
    finding_id: str | None = None,
    include_intel: bool = True,
    intel_source: IntelSource = "auto",
    include_assets_fixture: bool = True,
    finding_ids: list[str] | None = None,
) -> list[InvestigationReport]:
    selectors = [s for s in (finding, fixture, finding_id, finding_ids) if s is not None]
    if len(selectors) != 1:
        raise InvalidInputError(
            "Provide exactly one of: inline `finding`, `fixture` name, `finding_id`, "
            "or `finding_ids`."
        )
    if fixture is not None:
        findings = _load_fixture_findings(services, fixture)
        if len(findings) > MAX_FIXTURE_FINDINGS:
            notices = findings[MAX_FIXTURE_FINDINGS:]
            findings = findings[:MAX_FIXTURE_FINDINGS]
            services.audit.append(
                actor=services.settings.audit_actor,
                action="investigate_finding",
                subject=fixture,
                outcome="truncated",
                rationale=(
                    f"Fixture had {len(findings) + len(notices)} findings; "
                    f"processed {len(findings)}."
                ),
            )
    elif finding_ids is not None:
        unique_ids = list(dict.fromkeys(finding_ids))
        if not unique_ids or len(unique_ids) > MAX_FIXTURE_FINDINGS:
            raise InvalidInputError(
                f"`finding_ids` must contain 1 to {MAX_FIXTURE_FINDINGS} distinct ids per call."
            )
        findings = [services.findings.get(fid) for fid in unique_ids]
    elif finding_id is not None:
        findings = [services.findings.get(finding_id)]
    else:
        assert finding is not None
        findings = [finding]

    intel: ThreatIntelBundle | None = None
    all_cves = sorted({c for f in findings for c in f.cve_ids})
    if include_intel and all_cves:
        intel = await enrich_threat_intel(services, all_cves, intel_source)
    elif include_intel:
        services.audit.append(
            actor=services.settings.audit_actor,
            action="investigate_finding",
            subject=None,
            outcome="no_cves",
            rationale="No CVEs to enrich; intel skipped.",
        )

    reports: list[InvestigationReport] = []
    for f in findings:
        # Store the finding as reported; operator asset context is applied at
        # assessment time so inventory edits take effect without re-importing.
        services.findings.save(f)
        f, inventory_rules = with_asset_context(services, f)
        prior = services.investigations.find(f.finding_id)
        # Re-investigating without fresh intel keeps the intel already on file.
        record_intel = intel if intel is not None or prior is None else prior.intel
        record = build_investigation_record(f, record_intel, inventory_rules)
        if prior is not None:
            record = carry_forward(prior, record)
        services.investigations.save(record)
        reports.append(
            InvestigationReport(
                finding_id=f.finding_id, finding=f, record=record, assessment=assess(f, record)
            )
        )
    return reports


def verify_applicability(
    services: Services,
    finding_id: str,
    observed_service: ServiceObservation | None = None,
) -> InvestigationRecord:
    finding = services.findings.get(finding_id)
    record = services.investigations.get(finding_id)
    record = apply_applicability_observation(record, finding, observed_service)
    services.investigations.save(record)
    services.audit.append(
        actor=services.settings.audit_actor,
        action="verify_applicability",
        subject=finding_id,
        outcome=record.applicability.value,
        rationale="; ".join(record.applicability_rationale[-2:]),
    )
    return record


async def validate_exposure(
    services: Services,
    host: str,
    port: int,
    method: str,
    finding_id: str | None = None,
    timeout: float = 5.0,
) -> ValidationResult:
    from riskproof.validation.checks import run_authorized_check
    from riskproof.validation.targets import TargetAuthorizer

    authorizer = TargetAuthorizer(services.settings.allowed_targets)
    try:
        result = await run_authorized_check(
            method=method,
            host=host,
            port=port,
            authorizer=authorizer,
            approved_methods=services.settings.approved_validation_methods,
            timeout=timeout,
        )
    except AuthorizationDenied as exc:
        # Refusals are security-relevant: record them before reporting back.
        services.audit.append(
            actor=services.settings.audit_actor,
            action=f"validate_exposure:{method}",
            subject=f"{host}:{port}",
            outcome="refused",
            rationale=exc.message,
            details={"finding_id": finding_id},
        )
        raise
    result.audit_id = services.audit.append(
        actor=services.settings.audit_actor,
        action=f"validate_exposure:{method}",
        subject=f"{host}:{port}",
        outcome=result.status,
        rationale=result.evidence_statement(),
        details={"finding_id": finding_id},
    )
    if finding_id is not None:
        try:
            record = services.investigations.get(finding_id)
        except NotFoundError as exc:
            raise NotFoundError(
                f"Finding {finding_id!r} has no investigation record; run "
                "investigate_finding before validating exposure for it."
            ) from exc
        record.evidence.append(build_validation_evidence(result, finding_id))
        record.updated_at = datetime.now(UTC)
        services.investigations.save(record)
    return result


def with_asset_context(services: Services, finding: Finding) -> tuple[Finding, list[str]]:
    """Apply the operator asset inventory (if any) to a finding."""
    inventory = services.asset_inventory.current()
    if inventory is None:
        return finding, []
    return inventory.apply(finding)


def recompute_assessment(
    services: Services, finding_id: str
) -> tuple[Finding, InvestigationRecord, RiskAssessment]:
    finding, _ = with_asset_context(services, services.findings.get(finding_id))
    record = services.investigations.get(finding_id)
    return finding, record, assess(finding, record)


def execute_risk_policy(
    services: Services, finding_ids: list[str], policy: RiskPolicy
) -> list[PolicyDecision]:
    """Evaluate policy for a batch of findings — all or nothing.

    Every finding is loaded and assessed BEFORE any action or audit entry is
    written, so an unknown id cannot leave a half-recorded batch behind.
    """
    unique_ids = list(dict.fromkeys(finding_ids))
    loaded: list[tuple[Finding, InvestigationRecord, RiskAssessment]] = []
    missing: list[str] = []
    for fid in unique_ids:
        try:
            loaded.append(recompute_assessment(services, fid))
        except NotFoundError:
            missing.append(fid)
    if missing:
        raise NotFoundError(
            f"No investigation record for {missing}; nothing was recorded. Run "
            "investigate_finding on them first, or retry without them."
        )
    return [
        policy_engine.evaluate_policy(
            finding,
            record,
            assessment,
            policy,
            services.settings,
            services.audit,
            services.pending,
        )
        for finding, record, assessment in loaded
    ]


def confidence_summary(record: InvestigationRecord) -> dict[str, int]:
    """Counts of evidence by confidence level, for quick structured output."""
    summary: dict[str, int] = {}
    for evidence in record.evidence:
        summary[evidence.confidence.value] = summary.get(evidence.confidence.value, 0) + 1
    return summary
