"""Report rollups: per-asset, per-vulnerability, and signal-coverage views.

Pure functions over the investigated findings already loaded for a report. Nothing
here reads storage or makes a judgment: priorities come from the stored assessment,
scores from ``engine.riskscore``, and every count is over the findings in scope.

"GreyNoise-active" means GreyNoise sensors saw malicious scanning or exploitation
attempts for the CVE in the lookback window. It never means this asset was attacked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from riskproof.engine.riskscore import ScoreComponent, rank_key, score_vulnerability
from riskproof.models.findings import criticality_value
from riskproof.models.policy import Priority

if TYPE_CHECKING:
    from riskproof.engine.report import FindingReport

#: Findings listed under each asset's drill-down (the rest are counted).
ASSET_DRILLDOWN = 10
#: Exploited-now CVEs kept in the vulnerability rollup.
VULNERABILITY_LIMIT = 15
#: GreyNoise tag names kept per CVE.
TAG_NAMES_PER_CVE = 2

_PRIORITY_ORDER = [Priority.P1, Priority.P2, Priority.P3, Priority.P4]


def priority_rank(priority: Priority | str | None) -> int:
    """Lower is more urgent; no priority sorts last."""
    try:
        return _PRIORITY_ORDER.index(Priority(priority)) if priority else len(_PRIORITY_ORDER)
    except ValueError:
        return len(_PRIORITY_ORDER)


class FindingBrief(BaseModel):
    """One finding as listed under an asset."""

    finding_id: str
    name: str
    vulnerability: str
    score: int
    exploited_now: bool
    priority: str | None = None
    components: list[ScoreComponent] = Field(default_factory=list)


class AssetRollup(BaseModel):
    """One system and what the investigated findings say about it."""

    asset_id: str
    hostname: str | None = None
    ip: str | None = None
    owner: str | None = None
    environment: str | None = None
    criticality: str = "unspecified"
    internet_facing: bool | None = None
    #: Tenable asset tags (category -> values), merged over the asset's findings.
    tags: dict[str, list[str]] = Field(default_factory=dict)
    findings: int = 0
    cves: int = 0
    #: Distinct CVEs on this asset that GreyNoise saw actively exploited.
    greynoise_active_cves: int = 0
    kev_cves: int = 0
    exploited_now_findings: int = 0
    top_score: int = 0
    top_vulnerability: str = ""
    best_priority: str | None = None
    top_findings: list[FindingBrief] = Field(default_factory=list)
    more_findings: int = 0

    @property
    def label(self) -> str:
        return self.hostname or self.asset_id


class VulnerabilityRollup(BaseModel):
    """One exploited-now CVE: how many assets in scope carry it and why it is flagged."""

    cve: str
    assets: int
    findings: int
    greynoise_observed: bool = False
    peak_ips: int | None = None
    last_day: str | None = None
    tags: list[str] = Field(default_factory=list)
    kev: bool = False
    epss: float | None = None
    score: int = 0


class SignalCoverage(BaseModel):
    """What the threat-intel sources said about the distinct CVEs in scope."""

    cves_total: int = 0
    greynoise_observed: int = 0
    greynoise_quiet: int = 0
    #: GreyNoise has no tag for the CVE. Not evidence that it is safe.
    greynoise_no_data: int = 0
    #: Not checked (no key, budget, rate limit) or no GreyNoise reading at all.
    greynoise_unavailable: int = 0
    kev_listed: int = 0


_GN_PRECEDENCE = {"observed": 0, "quiet": 1, "no_data": 2}


def _best_greynoise(entries: list[FindingReport], cve: str):
    """The strongest GreyNoise reading for a CVE across the investigated findings."""
    best = None
    for e in entries:
        intel = e.record.intel
        result = intel.greynoise.get(cve) if intel else None
        if result is None:
            continue
        if best is None or _GN_PRECEDENCE.get(result.state, 3) < _GN_PRECEDENCE.get(best.state, 3):
            best = result
    return best


def _kev_listed(entries: list[FindingReport], cve: str) -> bool:
    return any(
        s.in_kev and s.cve == cve
        for e in entries
        if e.record.intel
        for s in e.record.intel.kev_status
    )


def build_signal_coverage(entries: list[FindingReport]) -> SignalCoverage:
    by_cve: dict[str, list[FindingReport]] = {}
    for e in entries:
        for cve in e.finding.cve_ids:
            by_cve.setdefault(cve, []).append(e)
    cov = SignalCoverage(cves_total=len(by_cve))
    for cve, group in by_cve.items():
        result = _best_greynoise(group, cve)
        state = result.state if result else "unavailable"
        if state == "observed":
            cov.greynoise_observed += 1
        elif state == "quiet":
            cov.greynoise_quiet += 1
        elif state == "no_data":
            cov.greynoise_no_data += 1
        else:
            cov.greynoise_unavailable += 1
        if _kev_listed(group, cve):
            cov.kev_listed += 1
    return cov


def build_asset_rollups(entries: list[FindingReport]) -> list[AssetRollup]:
    """One rollup per asset, most urgent first.

    Order: most urgent priority on the asset, then its highest risk score, then
    GreyNoise-active CVEs, then KEV-listed CVEs, then name (stable).
    """
    by_asset: dict[str, list[FindingReport]] = {}
    for e in entries:
        by_asset.setdefault(e.finding.asset.asset_id, []).append(e)

    rollups: list[AssetRollup] = []
    for asset_id, group in by_asset.items():
        asset = group[0].finding.asset
        cves = {c for e in group for c in e.finding.cve_ids}
        active = {c for c in cves if (g := _best_greynoise(group, c)) and g.state == "observed"}
        kev = {c for c in cves if _kev_listed(group, c)}
        ranked = sorted(
            (e for e in group if e.risk_score is not None),
            key=lambda e: (rank_key(e.risk_score), e.finding.finding_id),  # type: ignore[arg-type]
            reverse=True,
        )
        tags: dict[str, list[str]] = {}
        for e in group:
            for category, values in e.finding.asset.tags.items():
                merged = tags.setdefault(category, [])
                merged.extend(v for v in values if v not in merged)
        best = min((e.assessment.recommended_priority for e in group), key=priority_rank)
        top = ranked[0] if ranked else None
        rollups.append(
            AssetRollup(
                asset_id=asset_id,
                hostname=asset.hostname,
                ip=asset.ip_address,
                owner=asset.owner,
                environment=asset.environment,
                criticality=criticality_value(asset),
                internet_facing=asset.internet_facing,
                tags=tags,
                findings=len(group),
                cves=len(cves),
                greynoise_active_cves=len(active),
                kev_cves=len(kev),
                exploited_now_findings=sum(
                    bool(e.risk_score and e.risk_score.exploited_now) for e in group
                ),
                top_score=top.risk_score.score if top and top.risk_score else 0,
                top_vulnerability=top.risk_score.vulnerability if top and top.risk_score else "",
                best_priority=best.value if best else None,
                top_findings=[
                    FindingBrief(
                        finding_id=e.finding.finding_id,
                        name=e.finding.name,
                        vulnerability=e.risk_score.vulnerability,  # type: ignore[union-attr]
                        score=e.risk_score.score,  # type: ignore[union-attr]
                        exploited_now=e.risk_score.exploited_now,  # type: ignore[union-attr]
                        priority=(
                            e.assessment.recommended_priority.value
                            if e.assessment.recommended_priority
                            else None
                        ),
                        components=e.risk_score.components,  # type: ignore[union-attr]
                    )
                    for e in ranked[:ASSET_DRILLDOWN]
                ],
                more_findings=max(0, len(group) - ASSET_DRILLDOWN),
            )
        )
    rollups.sort(
        key=lambda a: (
            priority_rank(a.best_priority),
            -a.top_score,
            -a.greynoise_active_cves,
            -a.kev_cves,
            a.asset_id,
        )
    )
    return rollups


def build_vulnerability_rollups(
    entries: list[FindingReport], affected: dict[str, int]
) -> list[VulnerabilityRollup]:
    """Exploited-now CVEs (GreyNoise-observed or KEV-listed), widest first.

    ``affected`` is the open-asset count per CVE the risk score uses, so the score
    shown here equals the one the tools report for the same CVE.
    """
    by_cve: dict[str, list[FindingReport]] = {}
    for e in entries:
        for cve in e.finding.cve_ids:
            by_cve.setdefault(cve, []).append(e)
    rows: list[VulnerabilityRollup] = []
    for cve, group in by_cve.items():
        gn = _best_greynoise(group, cve)
        observed = gn is not None and gn.state == "observed"
        kev = _kev_listed(group, cve)
        if not (observed or kev):
            continue
        intel = next((e.record.intel for e in group if e.record.intel), None)
        epss = intel.epss.get(cve) if intel else None
        rows.append(
            VulnerabilityRollup(
                cve=cve,
                assets=len({e.finding.asset.asset_id for e in group}),
                findings=len(group),
                greynoise_observed=observed,
                peak_ips=gn.peak_malicious_ips if observed and gn else None,
                last_day=gn.last_malicious_day if observed and gn else None,
                tags=[t.name for t in (gn.tags if gn else [])[:TAG_NAMES_PER_CVE]],
                kev=kev,
                epss=epss.score if epss is not None and epss.kind == "observation" else None,
                score=score_vulnerability(cve, "cve", intel, affected.get(cve)).score,
            )
        )
    rows.sort(key=lambda v: (not v.greynoise_observed, -v.assets, not v.kev, v.cve))
    return rows[:VULNERABILITY_LIMIT]
