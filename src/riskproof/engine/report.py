"""HTML report generation: read-only aggregation of recorded investigations.

The report never computes new judgments: findings, evidence, and audit history
are read from storage, and priorities come from the same deterministic
assessment the MCP tools use (``investigation.recompute_assessment``). What the
report says must never be able to disagree with what the tools said.

Honesty rules carried into the rendered page:
* provenance is shown (live vs SAMPLE fixture, degraded or not);
* the EPSS/KEV/GreyNoise caveats are printed, not assumed;
* risk scores are the tool scores, shown with every component's points and basis;
* asset context from an operator inventory is disclosed (including its label);
* big databases are summarized (top assets, top findings) and the cut is stated;
* a priority filter is disclosed in the header, never silently applied;
* findings that were imported but never investigated are listed as such.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from riskproof import __version__
from riskproof.engine import remediation
from riskproof.engine.evidence import EPSS_CAVEAT, GREYNOISE_CAVEAT, KEV_CAVEAT
from riskproof.engine.investigation import recompute_assessment, strip_caveats
from riskproof.engine.report_charts import (
    asset_score_chart,
    component_label,
    component_legend,
    coverage_chart,
    score_bar_svg,
    vulnerability_chart,
    vulnerability_legend,
)
from riskproof.engine.report_rollups import (
    AssetRollup,
    SignalCoverage,
    VulnerabilityRollup,
    build_asset_rollups,
    build_signal_coverage,
    build_vulnerability_rollups,
)
from riskproof.engine.risk import RiskAssessment
from riskproof.engine.riskscore import RiskScore, rank_key, score_finding
from riskproof.errors import InvalidInputError
from riskproof.models.analysis import RemediationSimulation
from riskproof.models.evidence import ApplicabilityStatus, Evidence, InvestigationRecord
from riskproof.models.findings import Finding
from riskproof.models.policy import Priority
from riskproof.services import Services

#: Global audit entries in the footer section.
RECENT_AUDIT_LIMIT = 10
#: CVEs named inline per finding; the rest are counted.
CVE_PREVIEW = 3
#: Basis lines / non-routine evidence statements shown per finding.
BASIS_PREVIEW = 3
#: Hosts named in the uninvestigated rollup.
UNINVESTIGATED_TOP_HOSTS = 10
#: Open pending actions listed in the report.
PENDING_LIMIT = 200
#: Findings that get a full detail card (highest ranked first); the rest are
#: counted, listed in the ranked table and under their asset, and kept in the DB.
MAX_DETAIL_FINDINGS = 40
#: Rows in the ranked-findings table.
RANKED_TABLE_LIMIT = 100
#: Assets whose drill-down is open to expand; the rest are compact rows.
ASSET_DRILLDOWNS = 25
#: Tag categories shown as badges on an asset line.
MAX_TAG_BADGES = 4
#: Assets listed at all (the rest are counted).
ASSET_LIST_LIMIT = 200

#: Hard ceiling on findings one report may cover. Beyond this, generate a
#: filtered report — a silently truncated report would be dishonest.
MAX_FINDINGS = 10_000

_PRIORITY_ORDER: list[Priority] = [Priority.P1, Priority.P2, Priority.P3, Priority.P4]


class ProvenanceView(BaseModel):
    epss_source: str
    kev_source: str
    degraded: bool
    greynoise_source: str = "unavailable"


class ReportSummary(BaseModel):
    """Rollup over ALL investigated findings; ``shown`` reflects the filter."""

    investigated_total: int
    shown: int
    by_priority: dict[str, int] = Field(default_factory=dict)
    kev_listed: int = 0
    internet_facing: int = 0
    suspected_false_positives: int = 0
    verification_failed: int = 0
    unprioritized: int = 0
    uninvestigated: int = 0
    open_pending_actions: int = 0
    #: Investigated findings left out because they are resolved or not seen.
    resolved_excluded: int = 0
    #: Findings in scope whose CVE GreyNoise saw actively exploited or CISA lists (KEV).
    exploited_now_findings: int = 0
    assets_in_scope: int = 0
    assets_exploited_now: int = 0
    #: Distinct CVEs in scope that GreyNoise saw actively exploited in the window.
    greynoise_active_cves: int = 0


class FindingReport(BaseModel):
    """Everything the report says about one finding, already loaded."""

    finding: Finding
    record: InvestigationRecord
    assessment: RiskAssessment
    simulation: RemediationSimulation
    risk_score: RiskScore | None = None

    @property
    def finding_id(self) -> str:
        return self.finding.finding_id

    @property
    def evidence(self) -> list[Evidence]:
        return self.record.evidence


class UninvestigatedRollup(BaseModel):
    """Imported findings with no investigation, as counts (never row-by-row)."""

    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    asset_count: int = 0
    top_assets: list[tuple[str, int]] = Field(default_factory=list)


class ReportData(BaseModel):
    generated_at: datetime
    riskproof_version: str
    min_priority: Priority | None = None
    summary: ReportSummary
    provenance: list[ProvenanceView] = Field(default_factory=list)
    notices: list[str] = Field(default_factory=list)
    caveats: dict[str, str] = Field(default_factory=dict)
    findings: list[FindingReport] = Field(default_factory=list)
    assets: list[AssetRollup] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityRollup] = Field(default_factory=list)
    signals: SignalCoverage = Field(default_factory=SignalCoverage)
    #: Where the asset context (criticality, exposure, owner) came from, if anywhere.
    asset_context_note: str | None = None
    uninvestigated: UninvestigatedRollup = Field(default_factory=UninvestigatedRollup)
    pending_actions: list[dict[str, Any]] = Field(default_factory=list)
    recent_audit: list[dict[str, Any]] = Field(default_factory=list)
    dry_run: bool = True


def _normalize_priority(value: Priority | str | None) -> Priority | None:
    if value is None or isinstance(value, Priority):
        return value
    try:
        return Priority(str(value))
    except ValueError:
        raise InvalidInputError(
            f"Unknown priority {value!r}; expected one of P1, P2, P3, P4."
        ) from None


def _rank(priority: Priority | None) -> int:
    return _PRIORITY_ORDER.index(priority) if priority in _PRIORITY_ORDER else len(_PRIORITY_ORDER)


def build_report(
    services: Services,
    min_priority: Priority | str | None = None,
    include_resolved: bool = False,
) -> ReportData:
    """Aggregate every recorded investigation into a report model.

    Resolved and not-seen findings are left out (and counted in
    ``summary.resolved_excluded``) unless ``include_resolved`` is true.

    ``min_priority`` keeps findings at that priority or MORE urgent (P2 keeps
    P1 and P2). The filter is recorded on the report either way.
    """
    floor = _normalize_priority(min_priority)

    investigated_ids = services.investigations.list_ids(limit=MAX_FINDINGS + 1)
    if len(investigated_ids) > MAX_FINDINGS:
        raise InvalidInputError(
            f"The database holds more than {MAX_FINDINGS} investigated findings; "
            "narrow the report with min_priority or read the SQLite store directly."
        )
    inactive = set() if include_resolved else services.findings.inactive_ids()
    excluded = inactive.intersection(investigated_ids)
    investigated_ids = [i for i in investigated_ids if i not in excluded]
    entries: list[FindingReport] = []
    provenance: dict[tuple[str, str, str, bool], ProvenanceView] = {}
    notices: list[str] = []
    summary = ReportSummary(
        investigated_total=len(investigated_ids), shown=0, resolved_excluded=len(excluded)
    )

    for finding_id in investigated_ids:
        finding, record, assessment = recompute_assessment(services, finding_id)
        priority = assessment.recommended_priority
        key = priority.value if priority else "unprioritized"
        summary.by_priority[key] = summary.by_priority.get(key, 0) + 1
        if priority is None:
            summary.unprioritized += 1
        if assessment.exploitation_likelihood.value == "observed_in_the_wild":
            summary.kev_listed += 1
        if assessment.environmental_exposure.value == "internet_facing":
            summary.internet_facing += 1
        if record.applicability == ApplicabilityStatus.SUSPECTED_NOT_AFFECTED:
            summary.suspected_false_positives += 1
        if record.applicability == ApplicabilityStatus.VERIFICATION_FAILED:
            summary.verification_failed += 1

        if floor is not None and not (priority is not None and _rank(priority) <= _rank(floor)):
            continue
        if record.intel is not None:
            view = ProvenanceView(
                epss_source=record.intel.epss_source,
                kev_source=record.intel.kev_source,
                greynoise_source=record.intel.greynoise_source,
                degraded=record.intel.degraded,
            )
            provenance[
                (view.epss_source, view.kev_source, view.greynoise_source, view.degraded)
            ] = view
            notices.extend(n for n in record.intel.notices if n not in notices)

        entries.append(
            FindingReport(
                finding=finding,
                record=record,
                assessment=assessment,
                simulation=remediation.simulate_remediation(finding, record, assessment),
            )
        )

    cves = sorted({c for e in entries for c in e.finding.cve_ids})
    plugins = sorted(
        {e.finding.plugin_id for e in entries if not e.finding.cve_ids and e.finding.plugin_id}
    )
    affected = services.findings.affected_asset_counts(cves, plugins)
    for e in entries:
        e.risk_score = score_finding(e.finding, e.record, affected)
    entries.sort(
        key=lambda e: (
            _rank(e.assessment.recommended_priority),
            tuple(-x for x in rank_key(e.risk_score)),  # type: ignore[arg-type]
            e.finding.finding_id,
        )
    )
    summary.shown = len(entries)
    assets = build_asset_rollups(entries)
    signals = build_signal_coverage(entries)
    summary.exploited_now_findings = sum(
        bool(e.risk_score and e.risk_score.exploited_now) for e in entries
    )
    summary.assets_in_scope = len(assets)
    summary.assets_exploited_now = sum(a.exploited_now_findings > 0 for a in assets)
    summary.greynoise_active_cves = signals.greynoise_observed
    inventory = services.asset_inventory.current()
    pending = services.pending.list_open(limit=PENDING_LIMIT)
    summary.open_pending_actions = len(pending)

    rollup = services.findings.uninvestigated_rollup(top_assets=UNINVESTIGATED_TOP_HOSTS)
    uninvestigated = UninvestigatedRollup(**rollup)
    summary.uninvestigated = uninvestigated.total

    return ReportData(
        generated_at=datetime.now(UTC),
        riskproof_version=__version__,
        min_priority=floor,
        summary=summary,
        provenance=sorted(
            provenance.values(), key=lambda v: (v.epss_source, v.kev_source, v.degraded)
        ),
        notices=notices,
        caveats={"epss": EPSS_CAVEAT, "kev_listed": KEV_CAVEAT, "greynoise": GREYNOISE_CAVEAT},
        findings=entries,
        assets=assets,
        vulnerabilities=build_vulnerability_rollups(entries, affected),
        signals=signals,
        asset_context_note=(
            None
            if inventory is None
            else inventory.label
            or "Asset criticality, exposure and owner come from the operator asset inventory."
        ),
        uninvestigated=uninvestigated,
        pending_actions=pending,
        recent_audit=services.audit.recent(limit=RECENT_AUDIT_LIMIT),
        dry_run=services.settings.dry_run,
    )


# --------------------------------------------------------------------------
# HTML rendering (self-contained: inline CSS and SVG, no scripts, no external assets)
# --------------------------------------------------------------------------

_CSS = """
:root { color-scheme: light;
  --bg:#f3f3f0; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --line:#dcdbd5; --soft:#eeeeea;
  --c-gn:#2a78d6; --c-kev:#eb6834; --c-epss:#1baf7a; --c-assets:#eda100;
  --c-quiet:#86b6ef; --c-none:#b9b8b0; --c-na:#dcdbd5;
  --p1:#b3001b; --p2:#c96a00; --p3:#8a6d00; --p4:#4a5568;
  --ok:#1c7c3c; --warn:#a05a00; --bad:#b3001b; --info:#1a5fa8;
  --warn-bg:#fff7ec; --info-bg:#eef5fc; }
@media (prefers-color-scheme: dark) { :root { color-scheme: dark;
  --bg:#121211; --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --line:#34332f; --soft:#242422;
  --c-gn:#3987e5; --c-kev:#d95926; --c-epss:#199e70; --c-assets:#c98500;
  --c-quiet:#1c5cab; --c-none:#55544f; --c-na:#3a3935;
  --ok:#4cc17a; --warn:#e3a14a; --bad:#ff6b6b; --info:#6da7ec;
  --warn-bg:#2b2113; --info-bg:#14212f; } }
* { box-sizing: border-box; }
body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--ink);
       background: var(--bg); margin: 0 auto; max-width: 1100px; padding: 24px 20px 64px; }
h1 { font-size: 22px; margin: 0 0 2px; }
h2 { font-size: 17px; margin: 30px 0 8px; border-bottom: 2px solid var(--line);
     padding-bottom: 4px; }
h3 { font-size: 12px; margin: 16px 0 6px; color: var(--ink2); text-transform: uppercase;
     letter-spacing: .04em; }
.meta { color: var(--ink2); font-size: 13px; }
.banner { border-left: 4px solid var(--warn); background: var(--warn-bg); padding: 10px 14px;
          margin: 12px 0; border-radius: 0 6px 6px 0; }
.banner.assume { border-left-color: var(--info); background: var(--info-bg); }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 10px;
         margin: 12px 0; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
        padding: 10px 14px; }
.card .n { font-size: 24px; font-weight: 650; line-height: 1.2; }
.card .l { color: var(--ink2); font-size: 12px; }
.panel { background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
         padding: 12px 16px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; background: var(--surface); margin: 6px 0;
        border: 1px solid var(--line); }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line);
         vertical-align: top; font-size: 13px; }
th { background: var(--soft); font-weight: 600; }
tr:last-child td { border-bottom: none; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.chip { display: inline-block; padding: 1px 9px; border-radius: 999px; color: #fff;
        font-weight: 650; font-size: 12px; }
.p1 { background: var(--p1); } .p2 { background: var(--p2); }
.p3 { background: var(--p3); } .p4 { background: var(--p4); }
.badge { display: inline-block; padding: 0 7px; border-radius: 4px; font-size: 11px;
         font-weight: 650; border: 1px solid var(--line); color: var(--ink2); margin-right: 4px; }
.badge.gn { border-color: var(--c-gn); color: var(--info); }
.badge.kev { border-color: var(--c-kev); color: var(--warn); }
.badge.net { border-color: var(--bad); color: var(--bad); }
.c-confirmed { color: var(--ok); font-weight: 600; }
.c-inferred { color: var(--info); font-weight: 600; }
.c-missing { color: var(--ink2); font-weight: 600; }
.c-inconclusive { color: var(--warn); font-weight: 600; }
.c-verification_failed { color: var(--bad); font-weight: 600; }
details.sec > summary { cursor: pointer; font-size: 17px; font-weight: 650; margin: 26px 0 8px;
                        border-bottom: 2px solid var(--line); padding-bottom: 4px; }
details.sec > summary .meta { font-weight: 400; font-size: 13px; }
.finding { background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
           margin: 10px 0; }
.finding > details > summary { cursor: pointer; padding: 10px 14px; display: flex; gap: 10px;
                               align-items: center; flex-wrap: wrap; }
.finding .body { padding: 0 16px 14px; }
.finding .id { color: var(--ink2); font-size: 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
        gap: 4px 18px; margin: 10px 0; }
.grid div b { display: inline-block; min-width: 96px; color: var(--ink2); font-weight: 500; }
ul { margin: 4px 0 10px; padding-left: 22px; }
.rec { color: var(--ok); }
.audit li { margin-bottom: 3px; }
.audit .t { color: var(--ink2); }
footer { margin-top: 36px; padding-top: 12px; border-top: 1px solid var(--line);
         color: var(--ink2); font-size: 12px; }
code { background: var(--soft); padding: 0 4px; border-radius: 4px; font-size: 12px;
       white-space: nowrap; }
.legend { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 6px 0; font-size: 12px;
          color: var(--ink2); }
.key { display: inline-flex; align-items: center; gap: 6px; }
.sw { display: inline-block; width: 12px; height: 12px; border-radius: 3px; }
.sw.c-gn { background: var(--c-gn); } .sw.c-kev { background: var(--c-kev); }
.sw.c-epss { background: var(--c-epss); } .sw.c-assets { background: var(--c-assets); }
.sw.c-quiet { background: var(--c-quiet); } .sw.c-none { background: var(--c-none); }
.sw.c-na { background: var(--c-na); }
svg.chart { width: 100%; height: auto; max-width: 720px; display: block; }
svg .seg { stroke: var(--surface); stroke-width: 2; }
svg .seg.c-gn { fill: var(--c-gn); } svg .seg.c-kev { fill: var(--c-kev); }
svg .seg.c-epss { fill: var(--c-epss); } svg .seg.c-assets { fill: var(--c-assets); }
svg .seg.c-quiet { fill: var(--c-quiet); } svg .seg.c-none { fill: var(--c-none); }
svg .seg.c-na { fill: var(--c-na); }
svg .track { fill: var(--soft); }
svg .gridline { stroke: var(--line); stroke-width: 1; }
svg .axis { fill: var(--ink2); font-size: 11px; }
svg .lbl { fill: var(--ink); font-size: 12px; }
svg .val { fill: var(--ink); font-size: 12px; font-weight: 650; }
svg .mono { font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; }
svg.bar { vertical-align: middle; }
.assets { margin: 8px 0; }
.arow { display: grid; align-items: center; gap: 8px; padding: 7px 10px;
        grid-template-columns: 22px minmax(150px, 2.2fr) 52px 66px 52px 92px 56px
                               minmax(150px, 1.4fr); }
.ahead { font-size: 11px; color: var(--ink2); text-transform: uppercase; letter-spacing: .04em;
         border-bottom: 2px solid var(--line); }
.ahead span.r, .arow .r { text-align: right; font-variant-numeric: tabular-nums; }
details.asset { background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
                margin: 4px 0; }
details.asset > summary { cursor: pointer; list-style: none; }
details.asset > summary::-webkit-details-marker { display: none; }
.chev { display: inline-block; color: var(--ink2); transition: transform .1s; }
details[open] > summary .chev { transform: rotate(90deg); }
.hot { font-weight: 700; color: var(--info); }
.asset .body { padding: 2px 14px 12px; }
@media (max-width: 760px) { .arow { grid-template-columns: 22px 1fr 52px 56px; }
  .arow > :nth-child(n+5) { display: none; } }
@media print { body { background: #fff; padding: 0; }
  .finding, details.asset { break-inside: avoid; } }
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _cell(value: object) -> str:
    """Escaped cell text; None renders as an em dash."""
    return "&mdash;" if value is None else _esc(value)


def _yesno(value: bool | None) -> str:
    return "&mdash;" if value is None else ("yes" if value else "no")


def _chip(priority: str | None) -> str:
    if priority is None:
        return "&mdash;"
    return f'<span class="chip p{priority[1]}">{_esc(priority)}</span>'


def _conf(cls: str) -> str:
    return f'<span class="c-{_esc(cls)}">{_esc(cls)}</span>'


def _ulist(items: list[str]) -> str:
    if not items:
        return ""
    return "<ul>" + "".join(f"<li>{_esc(i)}</li>" for i in items) + "</ul>"


def _table(headers: list[str], rows: list[str], num: frozenset[int] = frozenset()) -> str:
    if not rows:
        return ""
    head = "".join(
        f"<th class='num'>{h}</th>" if i in num else f"<th>{h}</th>" for i, h in enumerate(headers)
    )
    body = "".join(f"<tr>{r}</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _section(title: str, body: str, *, count: str = "", open_: bool = False) -> str:
    """A collapsible top-level section."""
    note = f" <span class='meta'>{_esc(count)}</span>" if count else ""
    return (
        f"<details class='sec'{' open' if open_ else ''}><summary>{_esc(title)}{note}</summary>"
        f"{body}</details>"
    )


def _summary_cards(summary: ReportSummary) -> str:
    cards = [
        (summary.assets_in_scope, "assets analysed"),
        (summary.assets_exploited_now, "assets with exploited-now vulnerabilities"),
        (summary.exploited_now_findings, "findings exploited now (GreyNoise or KEV)"),
        (summary.greynoise_active_cves, "CVEs GreyNoise sees actively exploited"),
        (summary.kev_listed, "findings with a CISA KEV CVE"),
        (summary.by_priority.get("P1", 0), "P1 findings"),
        (summary.by_priority.get("P2", 0), "P2 findings"),
        (summary.internet_facing, "findings on internet-facing assets"),
        (summary.open_pending_actions, "open pending actions"),
    ]
    rendered = "".join(
        f'<div class="card"><div class="n">{n}</div><div class="l">{_esc(label)}</div></div>'
        for n, label in cards
    )
    return f'<div class="cards">{rendered}</div>'


def _cve_preview(cve_ids: list[str]) -> str:
    """First few CVEs inline, the rest counted (patch bundles carry dozens)."""
    if not cve_ids:
        return "&mdash;"
    shown = ", ".join(_esc(c) for c in cve_ids[:CVE_PREVIEW])
    extra = len(cve_ids) - CVE_PREVIEW
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _signal_badges(components: list) -> str:  # type: ignore[type-arg]
    points = {c.name: c.points for c in components}
    out = ""
    if points.get("greynoise"):
        out += "<span class='badge gn'>GreyNoise</span>"
    if points.get("kev"):
        out += "<span class='badge kev'>KEV</span>"
    return out or "<span class='meta'>&mdash;</span>"


def _coverage_note(pending: int) -> str:
    if not pending:
        return ""
    noun = "finding is" if pending == 1 else "findings are"
    return (
        f" This view covers investigated findings only: {pending} imported {noun} "
        "not yet investigated, so systems with only those are not ranked here."
    )


def _asset_meta(a: AssetRollup) -> str:
    bits = [b for b in (a.ip, a.environment, a.owner) if b]
    if a.criticality != "unspecified":
        bits.append(f"{a.criticality} criticality")
    meta = _esc(" · ".join(bits)) if bits else "context unknown"
    net = " <span class='badge net'>internet-facing</span>" if a.internet_facing else ""
    tags = "".join(
        f" <span class='badge'>{_esc(category)}: {_esc(', '.join(values))}</span>"
        for category, values in list(a.tags.items())[:MAX_TAG_BADGES]
    )
    return f"<div class='meta'>{meta}{net}{tags}</div>"


def _asset_row(rank: int, a: AssetRollup) -> str:
    """The grid cells shared by an expandable asset summary line."""
    comps = a.top_findings[0].components if a.top_findings else []
    bar = score_bar_svg(comps, a.label, width=96) if comps else ""
    active = (
        f"<span class='hot'>{a.greynoise_active_cves}</span>" if a.greynoise_active_cves else "0"
    )
    return (
        f"<span><span class='chev'>&#9656;</span></span>"
        f"<span><b>{rank}. {_esc(a.label)}</b>{_asset_meta(a)}</span>"
        f"<span>{_chip(a.best_priority)}</span>"
        f"<span class='r'>{a.findings}</span>"
        f"<span class='r'>{a.cves}</span>"
        f"<span class='r'>{active}</span>"
        f"<span class='r'>{a.kev_cves}</span>"
        f"<span>{bar} <b>{a.top_score}</b>"
        f"<div class='meta'>{_esc(a.top_vulnerability)}</div></span>"
    )


def _asset_drilldown(a: AssetRollup) -> str:
    rows = [
        f"<td>{_chip(b.priority)}</td>"
        f"<td>{_esc(b.name)}<div class='meta'>{_esc(b.finding_id)}</div></td>"
        f"<td>{_esc(b.vulnerability)}</td>"
        f"<td class='num'>{score_bar_svg(b.components, b.name, width=80)} <b>{b.score}</b></td>"
        f"<td>{_signal_badges(b.components)}</td>"
        for b in a.top_findings
    ]
    more = (
        f"<p class='meta'>+{a.more_findings} more investigated findings on this asset "
        "are not listed here.</p>"
        if a.more_findings
        else ""
    )
    return (
        "<div class='body'>"
        + _table(
            ["Priority", "Finding", "Vulnerability scored", "Risk score", "Signals"],
            rows,
            frozenset({3}),
        )
        + more
        + "</div>"
    )


_ASSET_HEADERS = (
    "<div class='arow ahead'><span></span><span>System</span><span>Priority</span>"
    "<span class='r'>Findings</span><span class='r'>CVEs</span>"
    "<span class='r'>GreyNoise-active CVEs</span><span class='r'>KEV</span>"
    "<span>Top risk score</span></div>"
)


def _assets_section(assets: list[AssetRollup]) -> str:
    if not assets:
        return ""
    listed = assets[:ASSET_LIST_LIMIT]
    expandable = listed[:ASSET_DRILLDOWNS]
    rest = listed[ASSET_DRILLDOWNS:]
    rows = "".join(
        f"<details class='asset'><summary class='arow'>{_asset_row(i, a)}</summary>"
        f"{_asset_drilldown(a)}</details>"
        for i, a in enumerate(expandable, start=1)
    )
    tail = ""
    if rest:
        compact = [
            f"<td class='num'>{i}</td><td><b>{_esc(a.label)}</b>{_asset_meta(a)}</td>"
            f"<td>{_chip(a.best_priority)}</td><td class='num'>{a.findings}</td>"
            f"<td class='num'>{a.greynoise_active_cves}</td><td class='num'>{a.kev_cves}</td>"
            f"<td class='num'>{a.top_score}</td><td>{_esc(a.top_vulnerability)}</td>"
            for i, a in enumerate(rest, start=ASSET_DRILLDOWNS + 1)
        ]
        tail = _section(
            f"{len(rest)} more assets",
            _table(
                [
                    "#",
                    "System",
                    "Priority",
                    "Findings",
                    "GreyNoise-active CVEs",
                    "KEV",
                    "Top score",
                    "Top vulnerability",
                ],
                compact,
                frozenset({0, 3, 4, 5, 6}),
            ),
        )
    cut = (
        f"<p class='meta'>{len(assets) - len(listed)} further assets are not listed.</p>"
        if len(assets) > len(listed)
        else ""
    )
    return f"<div class='assets'>{_ASSET_HEADERS}{rows}</div>{tail}{cut}"


def _vulnerability_table(vulns: list[VulnerabilityRollup]) -> str:
    rows = []
    for v in vulns:
        signals = ""
        if v.greynoise_observed:
            peak = f" (peak {v.peak_ips} IPs/day)" if v.peak_ips is not None else ""
            signals += f"<span class='badge gn'>GreyNoise{_esc(peak)}</span>"
        if v.kev:
            signals += "<span class='badge kev'>KEV</span>"
        epss = f"{v.epss:.3f}" if v.epss is not None else "&mdash;"
        tags = _esc("; ".join(v.tags)) if v.tags else "&mdash;"
        rows.append(
            f"<td><code>{_esc(v.cve)}</code></td><td class='num'>{v.assets}</td>"
            f"<td>{signals}</td><td class='num'>{epss}</td><td class='num'><b>{v.score}</b></td>"
            f"<td>{tags}</td>"
        )
    return _table(
        ["CVE", "Assets", "Signals", "EPSS", "Score", "GreyNoise tags"], rows, frozenset({1, 3, 4})
    )


def _dimensions(entry: FindingReport) -> str:
    """One row of dimension values; basis lines only for the ones that move priority."""
    a = entry.assessment
    rows = [
        ("Exploitation likelihood", a.exploitation_likelihood.value, a.likelihood_basis),
        ("Environmental exposure", a.environmental_exposure.value, a.exposure_basis),
        ("Applicability", a.applicability.value, a.applicability_basis),
        ("Business impact", a.business_impact.value, a.business_impact_basis),
        ("Evidence confidence", a.evidence_confidence.value, a.confidence_basis),
    ]
    trs = []
    for label, value, basis in rows:
        shown = basis[:BASIS_PREVIEW]
        extra = len(basis) - len(shown)
        basis_html = _ulist(shown) or "&mdash;"
        if extra > 0:
            basis_html += f"<div class='meta'>+{extra} more basis lines omitted</div>"
        trs.append(f"<td><b>{_esc(label)}</b></td><td>{_esc(value)}</td><td>{basis_html}</td>")
    return _table(["Dimension", "Value", "Basis"], trs)


def _unavailable(available: bool) -> str:
    return "" if available else " <span class='meta'>(input unavailable)</span>"


def _score_section(score: RiskScore | None) -> str:
    """The risk score with every component's points and basis (nothing hidden)."""
    if score is None:
        return ""
    rows = [
        f"<td>{_esc(component_label(c.name))}</td><td class='num'>{c.points}/{c.max_points}</td>"
        f"<td>{_esc(c.basis)}{_unavailable(c.available)}</td>"
        for c in score.components
    ]
    flag = (
        " &mdash; <b>exploited now</b> (GreyNoise-observed or KEV-listed)"
        if score.exploited_now
        else ""
    )
    return (
        f"<p><b>Risk score {score.score}/100</b>{flag}. {score.inputs_available} of "
        f"{score.inputs_total} inputs available. Scored vulnerability: "
        f"<code>{_esc(score.vulnerability)}</code>.</p>"
        + score_bar_svg(score.components, score.vulnerability, width=240)
        + _table(["Component", "Points", "Basis"], rows, frozenset({1}))
    )


def _evidence_summary(evidence: list[Evidence]) -> str:
    """Counts by confidence, plus any statement that is not plainly confirmed."""
    counts: dict[str, int] = {}
    for e in evidence:
        counts[e.confidence.value] = counts.get(e.confidence.value, 0) + 1
    line = ", ".join(f"{_conf(k)}: {n}" for k, n in sorted(counts.items()))
    gaps = [e for e in evidence if e.confidence.value != "confirmed"]
    listed = _ulist(
        [f"{e.confidence.value}: {strip_caveats(e.statement)}" for e in gaps[:BASIS_PREVIEW]]
    )
    more = len(gaps) - BASIS_PREVIEW
    tail = f"<div class='meta'>+{more} more not shown</div>" if more > 0 else ""
    return f"<p>{len(evidence)} evidence statements &mdash; {line}</p>{listed}{tail}"


def _remediation_section(entry: FindingReport) -> str:
    """Only the recommended option; the rest stay in the simulate_remediation tool."""
    sim = entry.simulation
    rec = next((o for o in sim.options if o.id == sim.recommended_option_id), None)
    if rec is None:
        return "<p>No remediation recommendation.</p>"
    effects = ", ".join(f"{_esc(k)}: {_esc(v)}" for k, v in rec.expected_effect.items())
    suffix = f" &mdash; {effects}" if effects else ""
    return f"<p><b class='rec'>{_esc(rec.title)}</b> ({_esc(rec.action_type.value)}){suffix}</p>"


def _audit_list(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "<p>No audit entries.</p>"
    items = []
    for e in entries:
        rationale = f" &mdash; {_esc(e['rationale'])}" if e.get("rationale") else ""
        items.append(
            f"<li><span class='t'>{_esc(e.get('ts', ''))}</span> &bull; "
            f"{_esc(e.get('actor', ''))} &bull; <b>{_esc(e.get('action', ''))}</b> &rarr; "
            f"{_esc(e.get('outcome', ''))}{rationale}</li>"
        )
    return f"<ul class='audit'>{''.join(items)}</ul>"


def _finding_section(entry: FindingReport) -> str:
    finding, record, a = entry.finding, entry.record, entry.assessment
    asset = finding.asset
    priority = a.recommended_priority.value if a.recommended_priority else None
    score = entry.risk_score
    score_text = f"<b>{score.score}</b>" if score else ""
    now = " <span class='badge gn'>exploited now</span>" if score and score.exploited_now else ""
    head = (
        f"<summary>{_chip(priority)} <b>{_esc(finding.name)}</b> "
        f"<span class='meta'>{_esc(asset.hostname or asset.asset_id)}</span> "
        f"{score_text}{now}</summary>"
    )
    facts = (
        "<div class='grid'>"
        f"<div><b>Priority</b> {_chip(priority)}</div>"
        f"<div><b>Host</b> {_cell(asset.hostname or asset.asset_id)}</div>"
        f"<div><b>IP</b> {_cell(asset.ip_address)}</div>"
        f"<div><b>Port</b> {_cell(finding.port)}</div>"
        f"<div><b>Criticality</b> {_esc(asset.criticality.value)}</div>"
        f"<div><b>Owner</b> {_cell(asset.owner)}</div>"
        f"<div><b>Internet-facing</b> {_yesno(asset.internet_facing)}</div>"
        f"<div><b>Severity</b> {_esc(finding.severity.value)}</div>"
        f"<div><b>CVSS v3</b> "
        f"{_cell(finding.cvss_v3.base_score if finding.cvss_v3 else None)}</div>"
        f"<div><b>VPR</b> {_cell(finding.vpr.score if finding.vpr else None)}</div>"
        f"<div><b>CVEs</b> {_cve_preview(finding.cve_ids)}</div>"
        "</div>"
    )
    open_q = ""
    if record.open_questions:
        open_q = f"<h3>Open questions</h3>{_ulist(record.open_questions)}"
    why = ""
    if a.priority_rationale:
        reasons = _esc("; ".join(a.priority_rationale))
        why = f"<p><b>Why {_esc(priority or 'unprioritized')}:</b> {reasons}</p>"
    return (
        f"<section class='finding'><details>{head}<div class='body'>"
        f"<div class='id'>{_esc(finding.finding_id)}</div>{why}{facts}"
        f"<h3>Risk score</h3>{_score_section(score)}"
        f"<h3>Risk dimensions</h3>{_dimensions(entry)}"
        f"<h3>Evidence</h3>{_evidence_summary(record.evidence)}"
        f"<h3>Recommended fix</h3>{_remediation_section(entry)}"
        f"{open_q}</div></details></section>"
    )


def _ranked_table(findings: list[FindingReport]) -> str:
    rows = []
    for i, e in enumerate(findings[:RANKED_TABLE_LIMIT], start=1):
        f, a, s = e.finding, e.assessment, e.risk_score
        priority = a.recommended_priority.value if a.recommended_priority else None
        rows.append(
            f"<td class='num'>{i}</td><td>{_chip(priority)}</td>"
            f"<td>{_esc(f.name)}<div class='meta'>{_esc(f.finding_id)}</div></td>"
            f"<td>{_esc(f.asset.hostname or f.asset.asset_id)}</td>"
            f"<td>{_esc(s.vulnerability) if s else '&mdash;'}</td>"
            f"<td class='num'><b>{s.score if s else '&mdash;'}</b></td>"
            f"<td>{_signal_badges(s.components) if s else ''}</td>"
        )
    cut = (
        f"<p class='meta'>Top {RANKED_TABLE_LIMIT} of {len(findings)} shown.</p>"
        if len(findings) > RANKED_TABLE_LIMIT
        else ""
    )
    return (
        _table(
            ["#", "Priority", "Finding", "Asset", "Vulnerability scored", "Score", "Signals"],
            rows,
            frozenset({0, 5}),
        )
        + cut
    )


def _uninvestigated_section(rollup: UninvestigatedRollup) -> str:
    """Counts, not rows: thousands of imported-only findings would bury the report."""
    sev_rows = [f"<td>{_esc(k)}</td><td>{n}</td>" for k, n in sorted(rollup.by_severity.items())]
    host_rows = [f"<td>{_esc(h)}</td><td>{n}</td>" for h, n in rollup.top_assets]
    body = (
        "<p class='meta'>These have no risk assessment yet, so nothing is concluded about "
        "them. Run <code>investigate_finding</code> on them (25 per call); the full list is "
        "in the RiskProof database.</p>"
        + _table(["Severity", "Findings"], sev_rows)
        + f"<h3>Hosts with the most (top {len(rollup.top_assets)} of {rollup.asset_count})</h3>"
        + _table(["Asset", "Findings"], host_rows)
    )
    return _section(f"Imported but not yet investigated ({rollup.total})", body)


def _method_section(report: ReportData) -> str:
    prov = "".join(
        f"<li>EPSS: <code>{_esc(p.epss_source)}</code> &bull; "
        f"KEV: <code>{_esc(p.kev_source)}</code> "
        f"&bull; GreyNoise: <code>{_esc(p.greynoise_source)}</code>"
        f"{' &bull; <b>degraded</b>' if p.degraded else ''}</li>"
        for p in report.provenance
    )
    body = (
        "<p>The risk score (0&ndash;100) is a published additive table, per vulnerability: "
        "GreyNoise observed 30, CISA KEV listed 30, EPSS <code>round(score &times; 25)</code>, "
        "affected assets with an open finding 2&ndash;15 (1&rarr;2, 2&ndash;4&rarr;5, "
        "5&ndash;19&rarr;9, 20&ndash;99&rarr;12, 100+&rarr;15). Unavailable inputs add nothing and "
        "are listed as unavailable, never treated as zero risk. &ldquo;Exploited now&rdquo; means "
        "GreyNoise-observed or KEV-listed, and ranks first. The score orders work; the P1&ndash;P4 "
        "priority still comes from the documented decision table.</p>"
        "<p>Assets are ordered by their most urgent priority, then highest risk score, then "
        "GreyNoise-active CVEs, then KEV-listed CVEs.</p>"
        f"<p class='meta'>{_esc(report.caveats['epss'])}<br>{_esc(report.caveats['kev_listed'])}"
        f"<br>{_esc(report.caveats['greynoise'])}</p>"
        + (f"<h3>Intel sources</h3><ul>{prov}</ul>" if prov else "")
    )
    return _section("How scores and rankings are computed", body)


def render_html(report: ReportData) -> str:
    """Render the report as one self-contained HTML document (no external assets)."""
    scope = (
        f"priorities {report.min_priority.value} and more urgent"
        if report.min_priority
        else "all priorities"
    )
    title = "RiskProof Vulnerability Report"
    dry_run_note = " &bull; <b>dry-run mode</b>" if report.dry_run else ""
    excluded_note = (
        f" &bull; {report.summary.resolved_excluded} resolved / not-seen findings excluded"
        if report.summary.resolved_excluded
        else ""
    )
    sources = "; ".join(
        f"EPSS {p.epss_source}, KEV {p.kev_source}, GreyNoise {p.greynoise_source}"
        for p in report.provenance
    )
    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head><body>",
        f"<h1>{_esc(title)}</h1>",
        f"<p class='meta'>Generated "
        f"{_esc(report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC'))} &bull; "
        f"RiskProof v{_esc(report.riskproof_version)} &bull; scope: {_esc(scope)} &bull; "
        f"showing {report.summary.shown} of {report.summary.investigated_total} "
        f"investigated findings{excluded_note}{dry_run_note}"
        + (f"<br>Intel: {_esc(sources)}" if sources else "")
        + "</p>",
    ]
    if any(p.degraded for p in report.provenance):
        parts.append(
            "<div class='banner'><b>Threat intelligence is degraded or SAMPLE fixture "
            "data.</b> Conclusions are indicative only, not live intelligence.</div>"
        )
    for notice in report.notices:
        parts.append(f"<div class='banner'>{_esc(notice)}</div>")
    if report.asset_context_note:
        parts.append(
            "<div class='banner assume'><b>Asset context:</b> "
            f"{_esc(report.asset_context_note)}</div>"
        )
    parts.append(
        "<div class='banner assume'><b>Reading this report:</b> "
        f"{_esc(report.caveats['epss'])} {_esc(report.caveats['kev_listed'])} "
        f"{_esc(report.caveats['greynoise'])} "
        "A closed port or failed check never suppresses a finding.</div>"
    )
    if not report.findings:
        parts.append("<h2>Dashboard</h2>" + _summary_cards(report.summary))
        parts.append("<p>No investigated findings in scope.</p>")
    else:
        parts.append("<h2>Dashboard</h2>" + _summary_cards(report.summary))
        parts.append(
            "<h2>Asset prioritization</h2>"
            f"<p class='meta'>{len(report.assets)} assets in scope. Each system with the "
            "vulnerabilities GreyNoise sees actively exploited, and its highest risk score. "
            "Expand a system for its findings and score breakdowns."
            f"{_coverage_note(report.uninvestigated.total)}</p>"
            + component_legend()
            + asset_score_chart(report.assets)
            + _assets_section(report.assets)
        )
        parts.append(
            "<h2>Exploited-now vulnerabilities</h2>"
            "<p class='meta'>CVEs that GreyNoise sensors saw attacked in the lookback window "
            "or that CISA lists as exploited, by how many assets in scope carry them.</p>"
            + vulnerability_legend()
            + vulnerability_chart(report.vulnerabilities)
            + _vulnerability_table(report.vulnerabilities)
        )
        parts.append(
            "<h2>Signal coverage</h2>"
            "<p class='meta'>What GreyNoise said about each distinct CVE in scope. GreyNoise "
            "tags only a small share of CVEs: &ldquo;no data&rdquo; is a gap, not a clean "
            "bill of health.</p>" + coverage_chart(report.signals)
        )
        detail = report.findings[:MAX_DETAIL_FINDINGS]
        cut = (
            f"<p class='meta'>Detail cards for the top {len(detail)} of {len(report.findings)} "
            "findings; the ranked table lists more and the rest remain in the database.</p>"
            if len(report.findings) > len(detail)
            else ""
        )
        parts.append(
            _section(
                "Finding detail",
                _section(
                    "Ranked findings",
                    _ranked_table(report.findings),
                    count=f"top {min(len(report.findings), RANKED_TABLE_LIMIT)}",
                )
                + cut
                + "".join(_finding_section(e) for e in detail),
                count=f"{len(report.findings)} findings",
            )
        )
    if report.uninvestigated.total:
        parts.append(_uninvestigated_section(report.uninvestigated))
    if report.pending_actions:
        rows = [
            f"<td>{_esc(p.get('id', ''))}</td><td>{_esc(p.get('finding_id', ''))}</td>"
            f"<td>{_esc(p.get('action', ''))}</td><td>{_esc(p.get('status', ''))}</td>"
            f"<td>{_esc(p.get('created_at', ''))}</td>"
            for p in report.pending_actions
        ]
        parts.append(
            _section(
                f"Open pending actions ({len(report.pending_actions)})",
                "<p class='meta'>Recorded by the risk policy for human execution; nothing "
                "has been executed.</p>"
                + _table(["ID", "Finding", "Action", "Status", "Recorded at"], rows),
            )
        )
    if report.recent_audit:
        parts.append(
            _section(
                f"Recent audit activity (latest {len(report.recent_audit)})",
                _audit_list(report.recent_audit),
            )
        )
    parts.append(_method_section(report))
    parts.append(
        "<footer>Priorities come from RiskProof's documented decision table; the risk score "
        "orders work and shows its arithmetic, and every priority cites its rationale. "
        "Simulations are deterministic heuristics over recorded evidence &mdash; re-scan "
        "after any change to verify. This file contains vulnerability data: keep it "
        "access-restricted.</footer></body></html>"
    )
    return "".join(parts)


def default_report_path(directory: Path, generated_at: datetime) -> Path:
    """Timestamped default file name inside the operator's chosen directory."""
    return Path(directory) / f"riskproof-report-{generated_at:%Y%m%dT%H%M%SZ}.html"


def write_report_file(page: str, path: Path) -> Path:
    """Write the report with owner-only permissions (0600): vulnerability data."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(page, encoding="utf-8")
    path.chmod(0o600)
    return path
