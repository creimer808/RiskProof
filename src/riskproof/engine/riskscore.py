"""Transparent additive risk score and exploited-now ranking, per vulnerability.

The score is a published table (docs/risk-methodology.md), never a learned or
hidden number: four components, each with points, maximum, availability and a
one-line basis. It orders work; it does not replace the P1-P4 decision table.

| Component         | Points | Rule                                                  |
| ----------------- | ------ | ----------------------------------------------------- |
| GreyNoise         | 0 / 30 | malicious scanning activity observed in the window    |
| CISA KEV          | 0 / 30 | CVE is listed                                         |
| EPSS              | 0-25   | ``round(score * 25)``                                 |
| Affected assets   | 0-15   | distinct assets with an open finding (tiers below)    |

A vulnerability is a CVE, or the scanner plugin when a finding has no CVE.
Unavailable inputs add no points and are listed as unavailable; they are never
presented as zero risk.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from riskproof.models.evidence import InvestigationRecord
from riskproof.models.findings import Finding
from riskproof.models.intel import ThreatIntelBundle

if TYPE_CHECKING:
    from riskproof.services import Services

GREYNOISE_POINTS = 30
KEV_POINTS = 30
EPSS_MAX_POINTS = 25
ASSET_MAX_POINTS = 15
#: (minimum distinct assets, points), largest first.
ASSET_TIERS = ((100, 15), (20, 12), (5, 9), (2, 5), (1, 2))
INPUTS_TOTAL = 4

ComponentName = Literal["greynoise", "kev", "epss", "affected_assets"]


class ScoreComponent(BaseModel):
    name: ComponentName
    points: int
    max_points: int
    available: bool
    basis: str


class RiskScore(BaseModel):
    vulnerability: str
    vulnerability_kind: Literal["cve", "plugin"]
    score: int = Field(ge=0, le=100)
    #: GreyNoise observed malicious activity OR the CVE is KEV-listed.
    exploited_now: bool
    inputs_available: int
    inputs_total: int = INPUTS_TOTAL
    affected_assets: int | None = None
    components: list[ScoreComponent]


def asset_points(assets: int) -> int:
    for minimum, points in ASSET_TIERS:
        if assets >= minimum:
            return points
    return 0


def _greynoise(cve: str | None, intel: ThreatIntelBundle | None) -> tuple[ScoreComponent, bool]:
    def build(points: int, available: bool, basis: str) -> ScoreComponent:
        return ScoreComponent(
            name="greynoise",
            points=points,
            max_points=GREYNOISE_POINTS,
            available=available,
            basis=basis,
        )

    if cve is None:
        return build(0, False, "No CVE on this finding; GreyNoise is keyed by CVE."), False
    result = intel.greynoise.get(cve) if intel else None
    if result is None:
        return build(0, False, "GreyNoise not available (not configured or not collected)."), False
    if result.state == "observed":
        return (
            build(
                GREYNOISE_POINTS,
                True,
                f"GreyNoise sensors saw malicious scanning/exploitation attempts for {cve} in "
                f"the lookback window (peak {result.peak_malicious_ips} distinct IPs/day). "
                "These are attempts against GreyNoise sensors, not against this asset.",
            ),
            True,
        )
    if result.state == "quiet":
        return (
            build(0, True, f"GreyNoise has tags for {cve} but saw no recent malicious activity."),
            False,
        )
    if result.state == "no_data":
        return build(0, False, result.reason or "No GreyNoise tag for this CVE."), False
    return build(0, False, f"GreyNoise not checked: {result.reason or 'no reason recorded'}"), False


def _kev(cve: str | None, intel: ThreatIntelBundle | None) -> tuple[ScoreComponent, bool]:
    def build(points: int, available: bool, basis: str) -> ScoreComponent:
        return ScoreComponent(
            name="kev", points=points, max_points=KEV_POINTS, available=available, basis=basis
        )

    status = next((s for s in intel.kev_status if s.cve == cve), None) if intel else None
    if status is None:
        return build(0, False, "No KEV data for this vulnerability."), False
    if status.in_kev:
        return (
            build(
                KEV_POINTS,
                True,
                f"{cve} is listed in CISA KEV: exploited in the wild "
                "(says nothing about this asset being hit).",
            ),
            True,
        )
    if status.catalog == "cisa-live":
        return build(0, True, f"{cve} is not in the live CISA KEV catalog."), False
    return (
        build(0, False, "KEV check used a SAMPLE catalog; absence there is not evidence."),
        False,
    )


def _epss(cve: str | None, intel: ThreatIntelBundle | None) -> ScoreComponent:
    entry = intel.epss.get(cve) if intel and cve else None
    if entry is not None and entry.kind == "observation":
        return ScoreComponent(
            name="epss",
            points=round(entry.score * EPSS_MAX_POINTS),
            max_points=EPSS_MAX_POINTS,
            available=True,
            basis=(
                f"EPSS {entry.score:.3f}: statistical 30-day exploitation probability "
                "for the CVE, not a claim about this system."
            ),
        )
    reason = entry.reason if entry is not None else "no EPSS data"
    return ScoreComponent(
        name="epss",
        points=0,
        max_points=EPSS_MAX_POINTS,
        available=False,
        basis=f"EPSS unavailable: {reason}.",
    )


def _assets(affected_assets: int | None) -> ScoreComponent:
    if affected_assets is None:
        return ScoreComponent(
            name="affected_assets",
            points=0,
            max_points=ASSET_MAX_POINTS,
            available=False,
            basis="Affected-asset count not available.",
        )
    return ScoreComponent(
        name="affected_assets",
        points=asset_points(affected_assets),
        max_points=ASSET_MAX_POINTS,
        available=True,
        basis=f"{affected_assets} distinct asset(s) have an open finding for this vulnerability.",
    )


def score_vulnerability(
    vulnerability: str,
    kind: Literal["cve", "plugin"],
    intel: ThreatIntelBundle | None,
    affected_assets: int | None,
) -> RiskScore:
    cve = vulnerability if kind == "cve" else None
    greynoise, gn_observed = _greynoise(cve, intel)
    kev, kev_listed = _kev(cve, intel)
    components = [greynoise, kev, _epss(cve, intel), _assets(affected_assets)]
    return RiskScore(
        vulnerability=vulnerability,
        vulnerability_kind=kind,
        score=sum(c.points for c in components),
        exploited_now=gn_observed or kev_listed,
        inputs_available=sum(c.available for c in components),
        affected_assets=affected_assets,
        components=components,
    )


def rank_key(score: RiskScore) -> tuple[int, int, int]:
    """Sort descending: exploited-now first, then score, then affected assets."""
    return (int(score.exploited_now), score.score, score.affected_assets or 0)


def score_finding(
    finding: Finding, record: InvestigationRecord, counts: dict[str, int]
) -> RiskScore:
    """Score the finding's best vulnerability (highest rank), naming it."""
    intel = record.intel
    if finding.cve_ids:
        candidates = [
            score_vulnerability(cve, "cve", intel, counts.get(cve)) for cve in finding.cve_ids
        ]
    elif finding.plugin_id:
        candidates = [
            score_vulnerability(
                finding.plugin_id, "plugin", intel, counts.get(f"plugin:{finding.plugin_id}")
            )
        ]
    else:
        candidates = [score_vulnerability("unknown", "plugin", intel, None)]
    return max(candidates, key=rank_key)


def score_batch(
    services: Services, items: list[tuple[Finding, InvestigationRecord]]
) -> list[RiskScore]:
    """Score many findings with a single affected-asset query."""
    cves = sorted({c for f, _ in items for c in f.cve_ids})
    plugins = sorted({f.plugin_id for f, _ in items if not f.cve_ids and f.plugin_id})
    counts = services.findings.affected_asset_counts(cves, plugins)
    return [score_finding(f, r, counts) for f, r in items]
