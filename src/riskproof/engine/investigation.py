"""Investigation orchestration: ingest -> enrich -> evidence -> assessment.

This module is the connective tissue the MCP tools call. It enforces the
"exactly one selector" rule, persists findings and records, and keeps fixture
degradation explicit in every output.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel

from riskproof.engine import policy_engine
from riskproof.engine.evidence import (
    EPSS_CAVEAT,
    GREYNOISE_CAVEAT,
    KEV_CAVEAT,
    apply_applicability_observation,
    build_investigation_record,
    build_validation_evidence,
    carry_forward,
)
from riskproof.engine.risk import RiskAssessment, assess
from riskproof.engine.riskscore import RiskScore, rank_key, score_batch
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
from riskproof.models.evidence import Evidence, EvidenceKind, InvestigationRecord
from riskproof.models.findings import Finding, ServiceObservation, Severity, criticality_value
from riskproof.models.intel import (
    EPSSObservation,
    EPSSUnavailable,
    GreyNoiseResult,
    KEVStatus,
    ThreatIntelBundle,
)
from riskproof.models.policy import PolicyDecision, RiskPolicy
from riskproof.providers.base import ProviderError
from riskproof.providers.fixtures_source import SAMPLE_NOTICE
from riskproof.services import Services
from riskproof.validation.checks import ValidationResult

#: Most findings one call may investigate / analyze / simulate.
MAX_BATCH_FINDINGS = 25

IntelSource = Literal["auto", "live", "fixture"]

FULL_DETAIL_HINT = (
    "Summary view. detail='full' adds the finding's description, plugin output and "
    "solution, evidence ids/timestamps/details, the raw intel bundle, and the basis "
    "lines behind every risk dimension."
)


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 0,
}

_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}")
#: CVE ids named per list in the compact intel rollup.
ROLLUP_CVE_LIMIT = 10

ROLLUP_NOTE = (
    "Intel statements for the other CVEs on this finding are summarized here, not listed; "
    "detail='full' returns every statement."
)


class InvestigationReport(BaseModel):
    finding_id: str
    finding: Finding
    record: InvestigationRecord
    assessment: RiskAssessment
    risk_score: RiskScore | None = None

    def summary(self) -> dict[str, Any]:
        """Compact, agent-facing view: everything needed to report on the
        finding, without the bulky source text or repeated intel."""
        f, record, a = self.finding, self.record, self.assessment
        asset = f.asset
        scored = {"risk_score": self.risk_score.model_dump(mode="json")} if self.risk_score else {}
        evidence, rollup = self._compact_evidence()
        extra = {"intel_rollup": rollup} if rollup else {}
        return {
            "finding_id": f.finding_id,
            "name": f.name,
            "source": f.source,
            "severity": f.severity.value,
            "cvss_v3": f.cvss_v3.base_score if f.cvss_v3 else None,
            "vpr": f.vpr.score if f.vpr else None,
            "cve_ids": f.cve_ids,
            "asset": {
                "asset_id": asset.asset_id,
                "hostname": asset.hostname,
                "ip": asset.ip_address,
                "port": f.port,
                "criticality": criticality_value(asset),
                "environment": asset.environment,
                "internet_facing": asset.internet_facing,
                "owner": asset.owner,
                **({"tags": asset.tags} if asset.tags else {}),
            },
            "priority": a.recommended_priority.value if a.recommended_priority else None,
            "priority_rationale": a.priority_rationale,
            "dimensions": {
                "exploitation_likelihood": a.exploitation_likelihood.value,
                "environmental_exposure": a.environmental_exposure.value,
                "applicability": a.applicability.value,
                "business_impact": a.business_impact.value,
                "evidence_confidence": a.evidence_confidence.value,
            },
            "evidence": [
                {
                    "kind": e.kind.value,
                    "confidence": e.confidence.value,
                    "source": e.source,
                    # Caveats are stated once per response (see summarize_reports).
                    "statement": strip_caveats(e.statement),
                }
                for e in evidence
            ],
            "evidence_by_confidence": confidence_summary(record),
            "open_questions": record.open_questions,
            **scored,
            **extra,
        }

    def _compact_evidence(self) -> tuple[list[Evidence], dict[str, Any] | None]:
        """Evidence for the summary view: bundle findings keep intel for one CVE.

        A patch bundle can list 90+ CVEs and each one adds EPSS/KEV/GreyNoise
        statements. The summary keeps those for the scored CVE (the one the
        score and ranking cite) and rolls the rest up as counts. Everything
        else, including all non-intel evidence, is kept as is.
        """
        f, record = self.finding, self.record
        anchor = None
        if self.risk_score is not None and self.risk_score.vulnerability_kind == "cve":
            anchor = self.risk_score.vulnerability
        elif self.risk_score is None and f.cve_ids:
            anchor = f.cve_ids[0]
        if anchor is None:
            return list(record.evidence), None
        kept: list[Evidence] = []
        omitted = 0
        for e in record.evidence:
            found = _CVE_IN_TEXT.search(e.statement)
            if e.kind == EvidenceKind.THREAT_INTEL and found and found.group(0) != anchor:
                omitted += 1
            else:
                kept.append(e)
        intel = record.intel
        if omitted == 0 or intel is None:
            return kept, None
        own = set(f.cve_ids)
        kev = sorted(s.cve for s in intel.kev_status if s.in_kev and s.cve in own)
        observed = sorted(c for c in own if (g := intel.greynoise.get(c)) and g.state == "observed")
        return kept, {
            "scored_cve": anchor,
            "cves_total": len(f.cve_ids),
            "kev_listed": len(kev),
            "kev_cves": kev[:ROLLUP_CVE_LIMIT],
            "greynoise_observed": len(observed),
            "greynoise_observed_cves": observed[:ROLLUP_CVE_LIMIT],
            "statements_omitted": omitted,
            "note": ROLLUP_NOTE,
        }


def strip_caveats(statement: str) -> str:
    """Remove the per-statement caveats for compact views that state them once."""
    return (
        statement.replace(f" {EPSS_CAVEAT}", "")
        .replace(f" {KEV_CAVEAT}", "")
        .replace(f" {GREYNOISE_CAVEAT}", "")
    )


def summarize_reports(reports: list[InvestigationReport]) -> dict[str, Any]:
    """Summaries plus intel provenance stated ONCE for the whole batch."""
    notices: list[str] = []
    provenance: set[tuple[str, str, bool]] = set()
    for report in reports:
        intel = report.record.intel
        if intel is None:
            continue
        provenance.add(
            (intel.epss_source, intel.kev_source, intel.greynoise_source, intel.degraded)
        )
        notices.extend(n for n in intel.notices if n not in notices)
    scored = [r for r in reports if r.risk_score is not None]
    by_rank = sorted(scored, key=lambda r: rank_key(r.risk_score), reverse=True)  # type: ignore[arg-type]
    ranking = [
        {
            "finding_id": r.finding_id,
            "rank": position,
            "score": r.risk_score.score,  # type: ignore[union-attr]
            "exploited_now": r.risk_score.exploited_now,  # type: ignore[union-attr]
        }
        for position, r in enumerate(by_rank, start=1)
    ]
    return {
        "investigations": [r.summary() for r in reports],
        "ranking": ranking,
        "intel_provenance": [
            {
                "epss_source": epss,
                "kev_source": kev,
                "greynoise_source": greynoise,
                "degraded": degraded,
            }
            for epss, kev, greynoise, degraded in sorted(provenance)
        ],
        "intel_notices": notices,
        "intel_caveats": {
            "epss": EPSS_CAVEAT,
            "kev_listed": KEV_CAVEAT,
            "greynoise": GREYNOISE_CAVEAT,
        },
        "detail": "summary",
        "note": FULL_DETAIL_HINT,
    }


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


async def _collect_greynoise(
    services: Services, cves: list[str], source: IntelSource, now: datetime, notices: list[str]
) -> tuple[dict[str, GreyNoiseResult], str]:
    """Optional GreyNoise readings. Never degrades the bundle; gaps stay explicit.

    Fixture mode uses the labeled SAMPLE file. Live mode needs a configured key;
    without one GreyNoise is simply absent (and no fixture is substituted).
    """
    if source == "fixture" or (source == "auto" and services.settings.offline):
        try:
            data = await services.fixture_intel.greynoise_for(
                cves, now, services.settings.greynoise_window_days
            )
        except ProviderError as exc:
            notices.append(f"GreyNoise SAMPLE fixture unavailable: {exc}")
            return {}, "unavailable"
        return data, "sample-fixture"
    if not services.greynoise.configured:
        return {}, "unavailable"
    try:
        return await services.greynoise.lookup(cves, now), "greynoise"
    except ProviderError as exc:
        notices.append(f"GreyNoise lookup failed: {exc}")
        gap = "GreyNoise lookup failed (see notices)."
        return (
            {c: GreyNoiseResult(cve=c, state="not_checked", reason=gap) for c in cves},
            "unavailable",
        )


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

    greynoise_data, greynoise_source = await _collect_greynoise(
        services, cves, source, now, notices
    )

    bundle = ThreatIntelBundle(
        cve_ids=cves,
        epss=epss_data,
        kev_status=kev_data,
        greynoise=greynoise_data,
        greynoise_source=greynoise_source,  # type: ignore[arg-type]
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
        rationale=(
            f"source={bundle.epss_source}/{bundle.kev_source}; degraded={bundle.degraded}; "
            f"greynoise={bundle.greynoise_source}"
        ),
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


def _cves_by_severity(findings: list[Finding]) -> list[str]:
    """Distinct CVEs, most severe finding first (ties alphabetical).

    The order decides which CVEs get optional, call-budgeted lookups first.
    """
    worst: dict[str, int] = {}
    for f in findings:
        rank = _SEVERITY_RANK[f.severity]
        for cve in f.cve_ids:
            worst[cve] = max(worst.get(cve, -1), rank)
    return sorted(worst, key=lambda c: (-worst[c], c))


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
        if len(findings) > MAX_BATCH_FINDINGS:
            notices = findings[MAX_BATCH_FINDINGS:]
            findings = findings[:MAX_BATCH_FINDINGS]
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
        if not unique_ids or len(unique_ids) > MAX_BATCH_FINDINGS:
            raise InvalidInputError(
                f"`finding_ids` must contain 1 to {MAX_BATCH_FINDINGS} distinct ids per call."
            )
        findings = [services.findings.get(fid) for fid in unique_ids]
    elif finding_id is not None:
        findings = [services.findings.get(finding_id)]
    else:
        assert finding is not None
        findings = [finding]

    intel: ThreatIntelBundle | None = None
    all_cves = _cves_by_severity(findings)
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
        assessment = assess(f, record)
        reports.append(
            InvestigationReport(
                finding_id=f.finding_id, finding=f, record=record, assessment=assessment
            )
        )
        priority = assessment.recommended_priority
        services.audit.append(
            actor=services.settings.audit_actor,
            action="investigate_finding",
            subject=f.finding_id,
            outcome=priority.value if priority else "unprioritized",
            rationale="; ".join(assessment.priority_rationale) or None,
            details={
                "source": f.source,
                "reinvestigation": prior is not None,
                "intel": (
                    f"{record.intel.epss_source}/{record.intel.kev_source}"
                    if record.intel
                    else None
                ),
                "inventory_rules": inventory_rules or None,
            },
        )
    for report, risk_score in zip(
        reports, score_batch(services, [(r.finding, r.record) for r in reports]), strict=True
    ):
        report.risk_score = risk_score
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


def recompute_assessments(
    services: Services, finding_ids: list[str], max_findings: int | None = None
) -> list[tuple[Finding, InvestigationRecord, RiskAssessment]]:
    """Load and assess a batch — all or nothing, every missing id reported."""
    unique_ids = list(dict.fromkeys(finding_ids))
    if not unique_ids:
        raise InvalidInputError("`finding_ids` must contain at least one id.")
    if max_findings is not None and len(unique_ids) > max_findings:
        raise InvalidInputError(
            f"`finding_ids` must contain at most {max_findings} distinct ids per call."
        )
    loaded: list[tuple[Finding, InvestigationRecord, RiskAssessment]] = []
    missing: list[str] = []
    for fid in unique_ids:
        try:
            loaded.append(recompute_assessment(services, fid))
        except NotFoundError:
            missing.append(fid)
    if missing:
        raise NotFoundError(
            f"No investigation record for {missing}; nothing was processed. Run "
            "investigate_finding on them first, or retry without them."
        )
    return loaded


def execute_risk_policy(
    services: Services, finding_ids: list[str], policy: RiskPolicy
) -> list[PolicyDecision]:
    """Evaluate policy for a batch of findings — all or nothing.

    Every finding is loaded and assessed BEFORE any action or audit entry is
    written, so an unknown id cannot leave a half-recorded batch behind.
    """
    loaded = recompute_assessments(services, finding_ids)
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
