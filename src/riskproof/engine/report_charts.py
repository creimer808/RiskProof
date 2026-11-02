"""Inline SVG charts for the report: no scripts, no external assets.

Colors are CSS custom properties defined by the report stylesheet (validated with
the dataviz palette checker in light and dark). Each score component keeps one
color everywhere it appears: GreyNoise blue, KEV orange, EPSS aqua, assets yellow.
Hover text is native ``<title>`` tooltips; every chart has a table or list beside it.
"""

from __future__ import annotations

import html

from riskproof.engine.report_rollups import AssetRollup, SignalCoverage, VulnerabilityRollup
from riskproof.engine.riskscore import ScoreComponent

COMPONENT_LABELS = {
    "greynoise": "GreyNoise",
    "kev": "CISA KEV",
    "epss": "EPSS",
    "affected_assets": "Affected assets",
}
_COMPONENT_CLASS = {
    "greynoise": "c-gn",
    "kev": "c-kev",
    "epss": "c-epss",
    "affected_assets": "c-assets",
}
_COMPONENT_ORDER = ("greynoise", "kev", "epss", "affected_assets")

#: Rows drawn in each chart (the tables beside them carry the rest).
ASSET_CHART_ROWS = 12
VULNERABILITY_CHART_ROWS = 10

_WIDTH = 720


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def component_label(name: str) -> str:
    return COMPONENT_LABELS.get(name, name)


def component_legend() -> str:
    """HTML legend for the four score components (identity is never color alone)."""
    items = "".join(
        f"<span class='key'><i class='sw {_COMPONENT_CLASS[n]}'></i>"
        f"{_esc(COMPONENT_LABELS[n])}</span>"
        for n in _COMPONENT_ORDER
    )
    return f"<div class='legend'>{items}</div>"


def _ordered(components: list[ScoreComponent]) -> list[ScoreComponent]:
    by_name = {c.name: c for c in components}
    return [by_name[n] for n in _COMPONENT_ORDER if n in by_name]


def _component_tooltip(label: str, c: ScoreComponent) -> str:
    state = "" if c.available else " (input unavailable)"
    return f"{label}: {component_label(c.name)} {c.points}/{c.max_points}{state}. {c.basis}"


def score_bar_svg(components: list[ScoreComponent], title: str, width: int = 120) -> str:
    """Small stacked bar of a 0-100 score, one segment per component."""
    height = 10
    x = 0.0
    rects = []
    for c in _ordered(components):
        w = c.points / 100 * width
        if w <= 0:
            continue
        rects.append(
            f"<rect class='seg {_COMPONENT_CLASS[c.name]}' x='{x:.1f}' y='0' "
            f"width='{max(w, 1.5):.1f}' height='{height}'>"
            f"<title>{_esc(_component_tooltip(title, c))}</title></rect>"
        )
        x += w
    track = f"<rect class='track' x='0' y='0' width='{width}' height='{height}' rx='2'/>"
    return (
        f"<svg class='bar' viewBox='0 0 {width} {height}' width='{width}' height='{height}' "
        f"role='img' aria-label='{_esc(title)} score breakdown'>{track}{''.join(rects)}</svg>"
    )


def asset_score_chart(assets: list[AssetRollup]) -> str:
    """Top assets by their highest finding score, stacked by score component."""
    rows = [a for a in assets if a.top_findings][:ASSET_CHART_ROWS]
    if not rows:
        return ""
    x0, bar_w, row_h, bar_h, top = 210, 420, 26, 14, 6
    height = top + len(rows) * row_h + 26
    scale = bar_w / 100
    parts = [
        f"<svg class='chart' viewBox='0 0 {_WIDTH} {height}' role='img' "
        "aria-label='Highest risk score per asset, stacked by score component'>"
    ]
    for tick in (0, 25, 50, 75, 100):
        x = x0 + tick * scale
        parts.append(
            f"<line class='gridline' x1='{x:.1f}' y1='{top}' x2='{x:.1f}' "
            f"y2='{top + len(rows) * row_h}'/>"
            f"<text class='axis' x='{x:.1f}' y='{top + len(rows) * row_h + 16}' "
            f"text-anchor='middle'>{tick}</text>"
        )
    for i, a in enumerate(rows):
        y = top + i * row_h
        prefix = f"{a.best_priority} · " if a.best_priority else ""
        parts.append(
            f"<text class='lbl' x='{x0 - 10}' y='{y + bar_h - 2}' text-anchor='end'>"
            f"<title>{_esc(a.label)}</title>{_esc(prefix + _clip(a.label, 24))}</text>"
        )
        x = float(x0)
        for c in _ordered(a.top_findings[0].components):
            w = c.points * scale
            if w <= 0:
                continue
            parts.append(
                f"<rect class='seg {_COMPONENT_CLASS[c.name]}' x='{x:.1f}' y='{y}' "
                f"width='{max(w, 1.5):.1f}' height='{bar_h}'>"
                f"<title>{_esc(_component_tooltip(a.label, c))}</title></rect>"
            )
            x += w
        parts.append(f"<text class='val' x='{x + 8:.1f}' y='{y + bar_h - 2}'>{a.top_score}</text>")
    parts.append("</svg>")
    return "".join(parts)


def vulnerability_chart(vulns: list[VulnerabilityRollup]) -> str:
    """Exploited-now CVEs by how many assets in scope carry them."""
    rows = vulns[:VULNERABILITY_CHART_ROWS]
    if not rows:
        return ""
    x0, bar_w, row_h, bar_h = 140, 280, 26, 14
    peak = max(v.assets for v in rows) or 1
    height = len(rows) * row_h + 8
    parts = [
        f"<svg class='chart' viewBox='0 0 {_WIDTH} {height}' role='img' "
        "aria-label='Exploited-now vulnerabilities by number of affected assets'>"
    ]
    for i, v in enumerate(rows):
        y = 4 + i * row_h
        w = max(v.assets / peak * bar_w, 3)
        cls = "c-gn" if v.greynoise_observed else "c-kev"
        why = "GreyNoise-observed" if v.greynoise_observed else "CISA KEV only"
        detail = f"{v.assets} asset(s) · {why}"
        if v.greynoise_observed and v.peak_ips is not None:
            detail += f" · peak {v.peak_ips} IPs/day"
        tag = f" · {_clip(v.tags[0], 34)}" if v.tags else ""
        parts.append(
            f"<text class='lbl mono' x='{x0 - 10}' y='{y + bar_h - 2}' text-anchor='end'>"
            f"{_esc(v.cve)}</text>"
            f"<rect class='seg {cls}' x='{x0}' y='{y}' width='{w:.1f}' height='{bar_h}'>"
            f"<title>{_esc(v.cve)}: {_esc(detail)}{_esc(tag)}</title></rect>"
            f"<text class='val' x='{x0 + w + 8:.1f}' y='{y + bar_h - 2}'>{v.assets}"
            f"<tspan class='axis'> {_esc(tag.strip(' ·') or why)}</tspan></text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def vulnerability_legend() -> str:
    return (
        "<div class='legend'>"
        "<span class='key'><i class='sw c-gn'></i>GreyNoise-observed</span>"
        "<span class='key'><i class='sw c-kev'></i>CISA KEV only</span></div>"
    )


def coverage_chart(signals: SignalCoverage) -> str:
    """One segmented bar: what GreyNoise said about each distinct CVE in scope."""
    total = signals.cves_total
    if total == 0:
        return "<p class='meta'>No CVEs in scope.</p>"
    segments = [
        ("Observed (malicious activity in window)", signals.greynoise_observed, "c-gn"),
        ("Tagged, quiet in window", signals.greynoise_quiet, "c-quiet"),
        ("No GreyNoise tag (no data, not evidence of safety)", signals.greynoise_no_data, "c-none"),
        ("Not checked / unavailable", signals.greynoise_unavailable, "c-na"),
    ]
    x = 0.0
    rects = []
    for label, n, cls in segments:
        if n <= 0:
            continue
        w = n / total * _WIDTH
        rects.append(
            f"<rect class='seg {cls}' x='{x:.1f}' y='0' width='{max(w, 2):.1f}' height='22'>"
            f"<title>{_esc(label)}: {n} of {total} CVEs</title></rect>"
        )
        x += w
    legend = "".join(
        f"<span class='key'><i class='sw {cls}'></i>{_esc(label)}: <b>{n}</b> "
        f"({n / total:.0%})</span>"
        for label, n, cls in segments
    )
    return (
        f"<svg class='chart' viewBox='0 0 {_WIDTH} 22' role='img' "
        f"aria-label='GreyNoise coverage of {total} distinct CVEs'>{''.join(rects)}</svg>"
        f"<div class='legend'>{legend}</div>"
    )
