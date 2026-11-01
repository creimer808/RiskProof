"""HTML report generation: read-only aggregation of recorded investigations.

The report never computes new judgments: findings, evidence, and audit history
are read from storage, and priorities come from the same deterministic
assessment the MCP tools use (``investigation.recompute_assessment``). What the
report says must never be able to disagree with what the tools said.

Honesty rules carried into the rendered page:
* provenance is shown (live vs SAMPLE fixture, degraded or not);
* the EPSS/KEV caveats are printed, not assumed;
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
from riskproof.engine import remediation, scenario
from riskproof.engine.evidence import EPSS_CAVEAT, KEV_CAVEAT
from riskproof.engine.investigation import recompute_assessment, strip_caveats
from riskproof.engine.risk import RiskAssessment
from riskproof.errors import InvalidInputError
from riskproof.models.analysis import ExploitScenario, RemediationSimulation
from riskproof.models.evidence import ApplicabilityStatus, Evidence, InvestigationRecord
from riskproof.models.findings import Finding
from riskproof.models.policy import Priority
from riskproof.services import Services

#: Audit entries kept per finding in the report.
PER_FINDING_AUDIT_LIMIT = 25
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

#: Hard ceiling on findings one report may cover. Beyond this, generate a
#: filtered report — a silently truncated report would be dishonest.
MAX_FINDINGS = 10_000

_PRIORITY_ORDER: list[Priority] = [Priority.P1, Priority.P2, Priority.P3, Priority.P4]


class ProvenanceView(BaseModel):
    epss_source: str
    kev_source: str
    degraded: bool


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


class FindingReport(BaseModel):
    """Everything the report says about one finding, already loaded."""

    finding: Finding
    record: InvestigationRecord
    assessment: RiskAssessment
    scenario: ExploitScenario
    simulation: RemediationSimulation
    audit_entries: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def finding_id(self) -> str:
        return self.finding.finding_id

    @property
    def evidence(self) -> list[Evidence]:
        return self.record.evidence


class UninvestigatedFinding(BaseModel):
    finding_id: str
    name: str
    severity: str
    cve_ids: list[str]
    asset_id: str


class ReportData(BaseModel):
    generated_at: datetime
    riskproof_version: str
    min_priority: Priority | None = None
    summary: ReportSummary
    provenance: list[ProvenanceView] = Field(default_factory=list)
    notices: list[str] = Field(default_factory=list)
    caveats: dict[str, str] = Field(default_factory=dict)
    findings: list[FindingReport] = Field(default_factory=list)
    uninvestigated: list[UninvestigatedFinding] = Field(default_factory=list)
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


def build_report(services: Services, min_priority: Priority | str | None = None) -> ReportData:
    """Aggregate every recorded investigation into a report model.

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
    all_ids = services.findings.list_ids(limit=MAX_FINDINGS + 1)
    if len(all_ids) > MAX_FINDINGS:
        raise InvalidInputError(f"The database holds more than {MAX_FINDINGS} findings.")

    entries: list[FindingReport] = []
    provenance: dict[tuple[str, str, bool], ProvenanceView] = {}
    notices: list[str] = []
    summary = ReportSummary(investigated_total=len(investigated_ids), shown=0)

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
                degraded=record.intel.degraded,
            )
            provenance[(view.epss_source, view.kev_source, view.degraded)] = view
            notices.extend(n for n in record.intel.notices if n not in notices)

        entries.append(
            FindingReport(
                finding=finding,
                record=record,
                assessment=assessment,
                scenario=scenario.build_exploit_scenario(finding, record, assessment),
                simulation=remediation.simulate_remediation(finding, record, assessment),
                audit_entries=services.audit.recent(
                    limit=PER_FINDING_AUDIT_LIMIT, finding_id=finding_id
                ),
            )
        )

    entries.sort(key=lambda e: (_rank(e.assessment.recommended_priority), e.finding.finding_id))
    summary.shown = len(entries)
    pending = services.pending.list_open(limit=PENDING_LIMIT)
    summary.open_pending_actions = len(pending)

    uninvestigated = []
    for fid in sorted(set(all_ids) - set(investigated_ids)):
        imported = services.findings.get(fid)
        uninvestigated.append(
            UninvestigatedFinding(
                finding_id=imported.finding_id,
                name=imported.name,
                severity=imported.severity.value,
                cve_ids=imported.cve_ids,
                asset_id=imported.asset.asset_id,
            )
        )
    summary.uninvestigated = len(uninvestigated)

    return ReportData(
        generated_at=datetime.now(UTC),
        riskproof_version=__version__,
        min_priority=floor,
        summary=summary,
        provenance=sorted(
            provenance.values(), key=lambda v: (v.epss_source, v.kev_source, v.degraded)
        ),
        notices=notices,
        caveats={"epss": EPSS_CAVEAT, "kev_listed": KEV_CAVEAT},
        findings=entries,
        uninvestigated=uninvestigated,
        pending_actions=pending,
        recent_audit=services.audit.recent(limit=RECENT_AUDIT_LIMIT),
        dry_run=services.settings.dry_run,
    )


# --------------------------------------------------------------------------
# HTML rendering (self-contained: inline CSS, no scripts, no external assets)
# --------------------------------------------------------------------------

_CSS = """
:root { --p1:#b3001b; --p2:#c96a00; --p3:#8a6d00; --p4:#4a5568;
        --ink:#1a202c; --muted:#5f6b7a; --line:#dde3ea; --bg:#f7f9fb;
        --ok:#1c7c3c; --warn:#a05a00; --bad:#b3001b; --info:#1a5fa8; }
* { box-sizing: border-box; }
body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
       color: var(--ink); background: var(--bg); margin: 0 auto; max-width: 1080px;
       padding: 24px 20px 64px; }
h1 { font-size: 22px; margin: 0 0 2px; }
h2 { font-size: 17px; margin: 28px 0 8px; border-bottom: 2px solid var(--line);
     padding-bottom: 4px; }
h3 { font-size: 13px; margin: 18px 0 6px; color: var(--muted);
     text-transform: uppercase; letter-spacing: .04em; }
.meta { color: var(--muted); font-size: 13px; }
.banner { border-left: 4px solid var(--warn); background: #fff7ec; padding: 10px 14px;
          margin: 14px 0; border-radius: 0 6px 6px 0; }
.banner.assume { border-left-color: var(--info); background: #eef5fc; }
.cards { display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0; }
.card { background: #fff; border: 1px solid var(--line); border-radius: 8px;
        padding: 10px 16px; min-width: 130px; }
.card .n { font-size: 22px; font-weight: 650; }
.card .l { color: var(--muted); font-size: 12px; }
table { border-collapse: collapse; width: 100%; background: #fff; margin: 8px 0;
        border: 1px solid var(--line); }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line);
         vertical-align: top; font-size: 13px; }
th { background: #eef2f6; font-weight: 600; }
tr:last-child td { border-bottom: none; }
.chip { display: inline-block; padding: 1px 9px; border-radius: 999px;
        color: #fff; font-weight: 650; font-size: 12px; }
.p1 { background: var(--p1); } .p2 { background: var(--p2); }
.p3 { background: var(--p3); } .p4 { background: var(--p4); }
.c-confirmed { color: var(--ok); font-weight: 600; }
.c-inferred { color: var(--info); font-weight: 600; }
.c-missing { color: var(--muted); font-weight: 600; }
.c-inconclusive { color: var(--warn); font-weight: 600; }
.c-verification_failed { color: var(--bad); font-weight: 600; }
.finding { background: #fff; border: 1px solid var(--line); border-radius: 10px;
           padding: 16px 18px; margin: 14px 0; }
.finding h2 { margin-top: 0; }
.finding header .id { color: var(--muted); font-size: 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
        gap: 4px 18px; margin: 10px 0; }
.grid div b { display: inline-block; min-width: 96px; color: var(--muted);
              font-weight: 500; }
ul { margin: 4px 0 10px; padding-left: 22px; }
.rec { color: var(--ok); }
.audit li { margin-bottom: 3px; }
.audit .t { color: var(--muted); }
footer { margin-top: 36px; padding-top: 12px; border-top: 1px solid var(--line);
         color: var(--muted); font-size: 12px; }
code { background: #eef2f6; padding: 0 4px; border-radius: 4px; font-size: 12px; }
@media print { body { background: #fff; padding: 0; } .finding { break-inside: avoid; } }
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


def _table(headers: list[str], rows: list[str]) -> str:
    if not rows:
        return ""
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join(f"<tr>{r}</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _summary_cards(summary: ReportSummary) -> str:
    cards = [
        (summary.by_priority.get("P1", 0), "P1 findings"),
        (summary.by_priority.get("P2", 0), "P2 findings"),
        (summary.kev_listed, "exploited in the wild (KEV)"),
        (summary.internet_facing, "internet-facing"),
        (summary.suspected_false_positives, "suspected false positives"),
        (summary.open_pending_actions, "open pending actions"),
    ]
    rendered = "".join(
        f'<div class="card"><div class="n">{n}</div><div class="l">{_esc(label)}</div></div>'
        for n, label in cards
    )
    return f'<div class="cards">{rendered}</div>'


def _queue_table(report: ReportData) -> str:
    rows = []
    for entry in report.findings:
        finding, a = entry.finding, entry.assessment
        cves = _cve_preview(finding.cve_ids)
        why = "; ".join(_esc(r) for r in a.priority_rationale) or "&mdash;"
        rows.append(
            f"<td>{_chip(a.recommended_priority.value if a.recommended_priority else None)}</td>"
            f"<td>{_esc(finding.name)}<div class='meta'>{_esc(finding.finding_id)}</div></td>"
            f"<td>{_esc(finding.asset.asset_id)}</td>"
            f"<td>{cves}</td>"
            f"<td>{_esc(a.exploitation_likelihood.value)}</td>"
            f"<td>{_esc(a.environmental_exposure.value)}</td>"
            f"<td>{why}</td>"
        )
    return _table(
        ["Priority", "Finding", "Asset", "CVEs", "Likelihood", "Exposure", "Why"],
        rows,
    )


def _cve_preview(cve_ids: list[str]) -> str:
    """First few CVEs inline, the rest counted (patch bundles carry dozens)."""
    if not cve_ids:
        return "&mdash;"
    shown = ", ".join(_esc(c) for c in cve_ids[:CVE_PREVIEW])
    extra = len(cve_ids) - CVE_PREVIEW
    return f"{shown} (+{extra} more)" if extra > 0 else shown


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
    head = (
        f"<header><h2>{_esc(finding.name)}</h2>"
        f"<div class='id'>{_esc(finding.finding_id)}</div></header>"
    )
    facts = (
        "<div class='grid'>"
        f"<div><b>Priority</b> {_chip(priority)}</div>"
        f"<div><b>Host</b> {_cell(asset.hostname or asset.asset_id)}</div>"
        f"<div><b>IP</b> {_cell(asset.ip_address)}</div>"
        f"<div><b>Port</b> {_cell(finding.port)}</div>"
        f"<div><b>Criticality</b> {_esc(asset.criticality.value)}</div>"
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
    return (
        f"<section class='finding'>{head}{facts}"
        f"<h3>Risk dimensions</h3>{_dimensions(entry)}"
        f"<h3>Evidence</h3>{_evidence_summary(record.evidence)}"
        f"<h3>Recommended fix</h3>{_remediation_section(entry)}"
        f"{open_q}</section>"
    )


def _uninvestigated_section(items: list[UninvestigatedFinding]) -> str:
    """Counts, not rows: thousands of imported-only findings would bury the report."""
    by_severity: dict[str, int] = {}
    by_host: dict[str, int] = {}
    for u in items:
        by_severity[u.severity] = by_severity.get(u.severity, 0) + 1
        by_host[u.asset_id] = by_host.get(u.asset_id, 0) + 1
    sev_rows = [f"<td>{_esc(k)}</td><td>{n}</td>" for k, n in sorted(by_severity.items())]
    top_hosts = sorted(by_host.items(), key=lambda kv: (-kv[1], kv[0]))
    host_rows = [f"<td>{_esc(h)}</td><td>{n}</td>" for h, n in top_hosts[:UNINVESTIGATED_TOP_HOSTS]]
    return (
        f"<h2>Imported but not yet investigated ({len(items)})</h2>"
        "<p class='meta'>These have no risk assessment yet, so nothing is concluded about "
        "them. Run <code>investigate_finding</code> on them (25 per call); the full list is "
        "in the RiskProof database.</p>"
        + _table(["Severity", "Findings"], sev_rows)
        + f"<h3>Hosts with the most (top {min(len(top_hosts), UNINVESTIGATED_TOP_HOSTS)} "
        f"of {len(top_hosts)})</h3>" + _table(["Asset", "Findings"], host_rows)
    )


def render_html(report: ReportData) -> str:
    """Render the report as one self-contained HTML document (no external assets)."""
    scope = (
        f"priorities {report.min_priority.value} and more urgent"
        if report.min_priority
        else "all priorities"
    )
    title = "RiskProof Vulnerability Report"
    dry_run_note = " &bull; <b>dry-run mode</b>" if report.dry_run else ""
    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head><body>",
        f"<h1>{_esc(title)}</h1>",
        f"<p class='meta'>Generated "
        f"{_esc(report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC'))} &bull; "
        f"RiskProof v{_esc(report.riskproof_version)} &bull; scope: {_esc(scope)} &bull; "
        f"showing {report.summary.shown} of {report.summary.investigated_total} "
        f"investigated findings{dry_run_note}</p>",
    ]
    if any(p.degraded for p in report.provenance):
        parts.append(
            "<div class='banner'><b>Threat intelligence is degraded or SAMPLE fixture "
            "data.</b> Conclusions are indicative only, not live intelligence.</div>"
        )
    for notice in report.notices:
        parts.append(f"<div class='banner'>{_esc(notice)}</div>")
    parts.append(
        "<div class='banner assume'><b>Reading this report:</b> "
        f"{_esc(report.caveats['epss'])} {_esc(report.caveats['kev_listed'])} "
        "A closed port or failed check never suppresses a finding.</div>"
        "<h2>Executive summary</h2>"
        + _summary_cards(report.summary)
        + "<h2>Priority queue</h2>"
        + (_queue_table(report) or "<p>No investigated findings in scope.</p>")
    )
    parts.extend(_finding_section(e) for e in report.findings)
    if report.uninvestigated:
        parts.append(_uninvestigated_section(report.uninvestigated))
    if report.pending_actions:
        rows = [
            f"<td>{_esc(p.get('id', ''))}</td><td>{_esc(p.get('finding_id', ''))}</td>"
            f"<td>{_esc(p.get('action', ''))}</td><td>{_esc(p.get('status', ''))}</td>"
            f"<td>{_esc(p.get('created_at', ''))}</td>"
            for p in report.pending_actions
        ]
        parts.append(
            f"<h2>Open pending actions ({len(report.pending_actions)})</h2>"
            "<p class='meta'>Recorded by the risk policy for human execution; nothing "
            "has been executed.</p>"
            + _table(["ID", "Finding", "Action", "Status", "Recorded at"], rows)
        )
    if report.recent_audit:
        parts.append(
            f"<h2>Recent audit activity (latest {len(report.recent_audit)})</h2>"
            + _audit_list(report.recent_audit)
        )
    parts.append(
        "<footer>Priorities come from RiskProof's documented decision table, not a "
        "weighted score; every assignment cites its rationale above. Simulations are "
        "deterministic heuristics over recorded evidence &mdash; re-scan after any "
        "change to verify. This file contains vulnerability data: keep it "
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
