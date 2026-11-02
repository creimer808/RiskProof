"""Report dashboard: risk scores, the top-level asset view, charts, collapsible sections.

The page must stay a read-only view over stored investigations. Scores come from
``engine.riskscore`` (the same numbers the MCP tools return), asset rollups are
counts over the investigated findings in scope, and a big database must not turn
into a multi-megabyte page.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

import pytest

from riskproof.engine import investigation as inv
from riskproof.engine import report as report_mod
from riskproof.engine.report import build_report, render_html
from riskproof.models.findings import Asset, Finding
from riskproof.models.intel import GreyNoiseResult, GreyNoiseTag, KEVStatus

LOG4J = "CVE-2021-44228"
ZERO = "CVE-2020-1472"
LOG4SHELL_HOST = "prod-web-01.demo.local"


async def investigated(services):
    await inv.investigate(services, fixture="findings_sample.json")
    return build_report(services)


async def test_every_finding_carries_its_risk_score(services):
    report = await investigated(services)
    assert report.findings
    assert all(e.risk_score is not None for e in report.findings)
    log4shell = next(e for e in report.findings if LOG4J in e.finding.cve_ids)
    assert log4shell.risk_score.exploited_now is True
    assert {c.name for c in log4shell.risk_score.components} == {
        "greynoise",
        "kev",
        "epss",
        "affected_assets",
    }


async def test_findings_with_equal_priority_are_ordered_by_ranking(services):
    report = await investigated(services)
    by_priority: dict[str, list] = {}
    for e in report.findings:
        by_priority.setdefault(str(e.assessment.recommended_priority), []).append(e)
    for group in by_priority.values():
        keys = [(not e.risk_score.exploited_now, -e.risk_score.score) for e in group]
        assert keys == sorted(keys)


async def test_assets_roll_up_investigated_findings(services):
    report = await investigated(services)
    assert sum(a.findings for a in report.assets) == len(report.findings)
    hosts = {a.hostname or a.asset_id for a in report.assets}
    assert LOG4SHELL_HOST in hosts
    web = next(a for a in report.assets if (a.hostname or a.asset_id) == LOG4SHELL_HOST)
    assert web.findings == 2
    assert web.greynoise_active_cves >= 1  # SAMPLE Log4j activity
    assert web.exploited_now_findings >= 1
    assert web.top_score == max(
        e.risk_score.score for e in report.findings if e.finding.asset.asset_id == web.asset_id
    )
    assert web.top_vulnerability


async def test_assets_are_ranked_most_urgent_first(services):
    report = await investigated(services)
    order = ["P1", "P2", "P3", "P4", "None"]
    keys = [(order.index(str(a.best_priority)), -a.top_score) for a in report.assets]
    assert keys == sorted(keys)
    assert report.assets[0].hostname == LOG4SHELL_HOST


async def test_signal_coverage_accounts_for_every_cve(services):
    report = await investigated(services)
    cves = {c for e in report.findings for c in e.finding.cve_ids}
    s = report.signals
    assert s.cves_total == len(cves)
    assert (
        s.greynoise_observed + s.greynoise_quiet + s.greynoise_no_data + s.greynoise_unavailable
        == s.cves_total
    )
    assert s.greynoise_observed >= 1


async def test_summary_counts_exploited_now(services):
    report = await investigated(services)
    summary = report.summary
    assert summary.exploited_now_findings == sum(
        e.risk_score.exploited_now for e in report.findings
    )
    assert summary.assets_in_scope == len(report.assets)
    assert 1 <= summary.assets_exploited_now <= summary.assets_in_scope
    assert summary.greynoise_active_cves == report.signals.greynoise_observed


async def test_vulnerability_rollup_lists_exploited_cves_widest_first(services):
    report = await investigated(services)
    assert report.vulnerabilities
    assert report.vulnerabilities[0].cve in {LOG4J, ZERO}
    assert all(v.greynoise_observed or v.kev for v in report.vulnerabilities)
    widths = [v.assets for v in report.vulnerabilities if v.greynoise_observed]
    assert widths == sorted(widths, reverse=True)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


async def test_page_leads_with_dashboard_then_asset_priorities(services):
    page = render_html(await investigated(services))
    dash = page.index("Dashboard")
    assets = page.index("Asset prioritization")
    detail = page.index("Finding detail")
    assert dash < assets < detail
    assert LOG4SHELL_HOST in page
    assert "GreyNoise-active" in page


async def test_page_has_charts_without_scripts_or_external_assets(services):
    page = render_html(await investigated(services))
    assert page.count("<svg") >= 3
    assert "<script" not in page.lower()
    assert 'src="http' not in page and 'href="http' not in page
    assert "url(http" not in page


async def test_score_breakdown_is_shown_with_basis(services):
    page = render_html(await investigated(services))
    for label in ("GreyNoise", "CISA KEV", "EPSS", "Affected assets"):
        assert label in page
    assert "not against this asset" in page  # the GreyNoise basis keeps its caveat


async def test_sections_are_collapsible(services):
    page = render_html(await investigated(services))
    assert page.count("<details") >= 5
    assert page.count("<details") == page.count("</details>")


async def test_asset_names_are_escaped(services):
    evil = Finding(
        finding_id="x-1",
        name="<img src=x onerror=alert(1)>",
        severity="critical",
        cve_ids=[LOG4J],
        asset=Asset(asset_id="evil", hostname="<script>alert(1)</script>"),
    )
    await inv.investigate(services, finding=evil, intel_source="fixture")
    page = render_html(build_report(services))
    assert "<script>alert(1)</script>" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;" in page


async def test_detail_cards_are_capped_and_disclosed(services, monkeypatch):
    await inv.investigate(services, fixture="findings_sample.json")
    monkeypatch.setattr(report_mod, "MAX_DETAIL_FINDINGS", 2)
    report = build_report(services)
    page = render_html(report)
    assert page.count("<section class='finding'") == 2
    assert f"top 2 of {len(report.findings)}" in page


async def test_empty_report_still_renders_dashboard(services):
    page = render_html(build_report(services))
    assert "No investigated findings in scope." in page
    assert "<script" not in page.lower()


# --------------------------------------------------------------------------
# Asset context disclosure
# --------------------------------------------------------------------------


async def test_inventory_label_is_disclosed(services, settings, tmp_path):
    settings.asset_inventory.write_text(
        json.dumps(
            {
                "label": "DEMO inventory: invented for lab data",
                "rules": [{"match": "nas-01", "criticality": "high", "owner": "storage-team"}],
            }
        )
    )
    f = Finding(
        finding_id="n-1",
        name="x",
        severity="high",
        cve_ids=[LOG4J],
        asset=Asset(asset_id="nas-01", hostname="nas-01"),
        source="tenable",
    )
    await inv.investigate(services, finding=f, intel_source="fixture")
    report = build_report(services)
    assert report.asset_context_note and "DEMO inventory" in report.asset_context_note
    assert "DEMO inventory: invented for lab data" in render_html(report)
    web = report.assets[0]
    assert web.owner == "storage-team" and web.criticality == "high"


async def test_no_inventory_note_when_none_configured(services):
    report = await investigated(services)
    assert report.asset_context_note is None


# --------------------------------------------------------------------------
# Scale: a big database must not produce a huge page
# --------------------------------------------------------------------------


@pytest.fixture()
def big(services, monkeypatch):
    async def no_epss(cves):
        return {}

    async def kev(cves):
        now = datetime.now(UTC)
        return [
            KEVStatus(cve=c, in_kev=int(c[-1]) % 3 == 0, catalog="cisa-live", checked_at=now)
            for c in cves
        ]

    async def gn(cves, now=None):
        return {
            c: GreyNoiseResult(
                cve=c,
                state="observed",
                tags=[GreyNoiseTag(id="t", slug="s", name="Tag", intention="malicious")],
                malicious_ips_by_day={"2026-11-02": 5},
                peak_malicious_ips=5,
                last_malicious_day="2026-11-02",
            )
            for c in cves
            if int(c[-1]) % 2 == 0
        }

    class FakeGN:
        configured = True
        lookup = staticmethod(gn)

    monkeypatch.setattr(services.epss, "fetch", no_epss)
    monkeypatch.setattr(services.kev, "status_for", kev)
    services.greynoise = FakeGN()
    return services


async def test_large_database_renders_a_bounded_page(big):
    findings = [
        Finding(
            finding_id=f"f-{i}",
            name=f"Vuln {i}",
            severity="critical",
            cve_ids=[f"CVE-2020-{1000 + (i * 7 + k) % 300}" for k in range(3)],
            asset=Asset(asset_id=f"host-{i % 60:02d}"),
        )
        for i in range(300)
    ]
    for start in range(0, len(findings), inv.MAX_BATCH_FINDINGS):
        batch = findings[start : start + inv.MAX_BATCH_FINDINGS]
        await inv.investigate(
            big, finding_ids=[b.finding_id for b in _saved(big, batch)], intel_source="live"
        )
    report = build_report(big)
    page = render_html(report)
    assert len(report.assets) == 60
    assert page.count("<section class='finding'") <= report_mod.MAX_DETAIL_FINDINGS
    assert len(page) < 700_000
    assert re.search(r"\b60 assets\b", page)


def _saved(services, findings):
    for f in findings:
        services.findings.save(f)
    return findings


async def test_chart_rows_carry_the_assets_priority(services):
    page = render_html(await investigated(services))
    assert re.search(r"<text class='lbl'[^>]*>(?:<title>[^<]*</title>)?P1 · ", page)


async def test_internet_facing_card_says_what_it_counts(services):
    page = render_html(await investigated(services))
    assert "findings on internet-facing assets" in page


async def test_asset_section_states_how_much_is_not_investigated(services):
    await inv.investigate(services, fixture="findings_sample.json")
    extra = Finding(
        finding_id="pending-1", name="pending", severity="high", asset=Asset(asset_id="other")
    )
    services.findings.save(extra)
    page = render_html(build_report(services))
    assert "1 imported finding is not yet investigated" in page
