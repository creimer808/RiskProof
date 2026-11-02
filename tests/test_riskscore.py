"""Transparent additive risk score and exploited-now ranking."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from mcp.server.fastmcp import FastMCP

from riskproof.engine import investigation as inv
from riskproof.engine.evidence import build_investigation_record
from riskproof.engine.riskscore import (
    asset_points,
    rank_key,
    score_batch,
    score_finding,
    score_vulnerability,
)
from riskproof.models.findings import Asset, Finding
from riskproof.models.intel import (
    EPSSObservation,
    EPSSUnavailable,
    GreyNoiseResult,
    KEVEntry,
    KEVStatus,
    ThreatIntelBundle,
)
from riskproof.tools import register_tools

NOW = datetime(2026, 11, 2, tzinfo=UTC)
CVE = "CVE-2021-44228"
OTHER = "CVE-2020-1472"


def bundle(
    cve: str = CVE,
    *,
    gn: str | None = None,
    kev: str | None = None,
    epss: float | None = None,
) -> ThreatIntelBundle:
    """gn: observed|quiet|no_data|not_checked; kev: live|sample + _listed|_absent."""
    greynoise = {}
    if gn:
        greynoise[cve] = GreyNoiseResult(
            cve=cve,
            state=gn,  # type: ignore[arg-type]
            reason="no tag; not evidence of safety" if gn in ("no_data", "not_checked") else None,
            peak_malicious_ips=22 if gn == "observed" else 0,
        )
    statuses = []
    if kev:
        catalog = "cisa-live" if kev.startswith("live") else "sample"
        listed = kev.endswith("listed")
        statuses.append(
            KEVStatus(
                cve=cve,
                in_kev=listed,
                catalog=catalog,  # type: ignore[arg-type]
                entry=KEVEntry(cve=cve) if listed else None,
                checked_at=NOW,
            )
        )
    epss_map = (
        {cve: EPSSObservation(cve=cve, score=epss, collected_at=NOW)} if epss is not None else {}
    )
    return ThreatIntelBundle(
        cve_ids=[cve],
        epss=epss_map,
        kev_status=statuses,
        greynoise=greynoise,
        collected_at=NOW,
        greynoise_source="greynoise" if gn else "unavailable",
    )


def comp(score, name):
    return next(c for c in score.components if c.name == name)


@pytest.mark.parametrize(
    ("assets", "points"),
    [(0, 0), (1, 2), (2, 5), (4, 5), (5, 9), (19, 9), (20, 12), (99, 12), (100, 15), (5000, 15)],
)
def test_asset_points_tiers(assets, points):
    assert asset_points(assets) == points


def test_full_score_is_100():
    s = score_vulnerability(
        CVE, "cve", bundle(gn="observed", kev="live_listed", epss=1.0), affected_assets=100
    )
    assert s.score == 100 and s.exploited_now is True
    assert s.inputs_available == 4 and s.inputs_total == 4
    assert [c.name for c in s.components] == ["greynoise", "kev", "epss", "affected_assets"]
    assert [c.max_points for c in s.components] == [30, 30, 25, 15]


def test_each_component_has_points_max_and_basis():
    s = score_vulnerability(CVE, "cve", bundle(gn="quiet", kev="live_absent", epss=0.1), 3)
    for c in s.components:
        assert c.basis.strip() and 0 <= c.points <= c.max_points


@pytest.mark.parametrize("epss", [0.0, 0.01, 0.5, 0.942, 1.0])
def test_epss_points_round(epss):
    s = score_vulnerability(CVE, "cve", bundle(epss=epss), None)
    assert comp(s, "epss").points == round(epss * 25)


def test_missing_inputs_listed_unavailable_not_zero():
    s = score_vulnerability(CVE, "cve", bundle(gn="no_data", kev="sample_absent"), 1)
    assert s.inputs_available == 1  # only the asset count
    for name in ("greynoise", "kev", "epss"):
        c = comp(s, name)
        assert c.available is False and c.points == 0
    assert "not evidence" in comp(s, "greynoise").basis
    assert s.exploited_now is False


def test_not_checked_and_absent_greynoise_are_unavailable():
    for intel in (bundle(gn="not_checked"), bundle(), None):
        s = score_vulnerability(CVE, "cve", intel, None)
        assert comp(s, "greynoise").available is False
        assert s.score == 0 and s.inputs_available == 0


def test_kev_listed_in_sample_catalog_counts_but_absence_does_not():
    listed = score_vulnerability(CVE, "cve", bundle(kev="sample_listed"), None)
    assert comp(listed, "kev").points == 30 and comp(listed, "kev").available
    absent = score_vulnerability(CVE, "cve", bundle(kev="sample_absent"), None)
    assert comp(absent, "kev").available is False
    live_absent = score_vulnerability(CVE, "cve", bundle(kev="live_absent"), None)
    assert comp(live_absent, "kev").available is True and comp(live_absent, "kev").points == 0


def test_epss_unavailable_marker_is_unavailable():
    intel = bundle()
    intel.epss[CVE] = EPSSUnavailable(cve=CVE, reason="timeout")
    assert comp(score_vulnerability(CVE, "cve", intel, None), "epss").available is False


def test_quiet_greynoise_is_available_with_zero_points():
    s = score_vulnerability(CVE, "cve", bundle(gn="quiet"), None)
    assert comp(s, "greynoise").available is True and comp(s, "greynoise").points == 0


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"gn": "observed"}, True),
        ({"kev": "live_listed"}, True),
        ({"kev": "sample_listed"}, True),
        ({"gn": "quiet", "kev": "live_absent"}, False),
    ],
)
def test_exploited_now_from_either_signal(kwargs, expected):
    assert score_vulnerability(CVE, "cve", bundle(**kwargs), 1).exploited_now is expected


def finding(cves, plugin="1", fid="f1") -> Finding:
    return Finding(
        finding_id=fid, name="x", severity="high", cve_ids=cves, plugin_id=plugin,
        asset=Asset(asset_id="a1"),
    )  # fmt: skip


def test_multi_cve_finding_uses_best_and_names_it():
    intel = ThreatIntelBundle(
        cve_ids=[CVE, OTHER],
        collected_at=NOW,
        greynoise={CVE: GreyNoiseResult(cve=CVE, state="observed")},
        greynoise_source="greynoise",
    )
    f = finding([OTHER, CVE])
    record = build_investigation_record(f, intel)
    s = score_finding(f, record, {CVE: 2, OTHER: 2})
    assert s.vulnerability == CVE and s.vulnerability_kind == "cve" and s.exploited_now


def test_no_cve_finding_falls_back_to_plugin():
    f = finding([], plugin="155999")
    record = build_investigation_record(f, None)
    s = score_finding(f, record, {"plugin:155999": 12})
    assert (s.vulnerability, s.vulnerability_kind, s.affected_assets) == ("155999", "plugin", 12)
    assert comp(s, "affected_assets").points == 9  # 12 assets -> tier 5-19
    assert comp(s, "greynoise").available is False


def test_no_cve_no_plugin_scores_unknown():
    f = finding([], plugin=None)
    s = score_finding(f, build_investigation_record(f, None), {})
    assert s.vulnerability == "unknown" and s.score == 0 and s.inputs_available == 0


def test_ranking_exploited_first_even_with_lower_score():
    exploited = score_vulnerability(CVE, "cve", bundle(gn="observed"), 1)  # 32
    big = score_vulnerability(
        OTHER, "cve", bundle(OTHER, gn="quiet", kev="live_absent", epss=1.0), 100
    )  # 40
    assert exploited.score < big.score
    assert sorted([big, exploited], key=rank_key, reverse=True)[0] is exploited


def test_ranking_ties_break_on_score_then_assets():
    a = score_vulnerability(CVE, "cve", bundle(kev="live_listed"), 1)
    b = score_vulnerability(OTHER, "cve", bundle(OTHER, kev="live_listed"), 5)
    assert rank_key(b) > rank_key(a)


async def test_score_batch_counts_open_findings_only(services):
    services.findings.save_many(
        [
            Finding(finding_id="a", name="a", severity="high", cve_ids=[CVE],
                    asset=Asset(asset_id="h1")),
            Finding(finding_id="b", name="b", severity="high", cve_ids=[CVE],
                    asset=Asset(asset_id="h2"), raw={"state": "FIXED"}),
        ]
    )  # fmt: skip
    f = services.findings.get("a")
    record = build_investigation_record(f, None)
    (s,) = score_batch(services, [(f, record)])
    assert s.affected_assets == 1


async def test_investigate_output_has_risk_score_and_ranking(services):
    reports = await inv.investigate(services, fixture="findings_sample.json")
    summary = inv.summarize_reports(reports)
    for item in summary["investigations"]:
        rs = item["risk_score"]
        assert [c["name"] for c in rs["components"]] == [
            "greynoise", "kev", "epss", "affected_assets",
        ]  # fmt: skip
        assert 0 <= rs["score"] <= 100
    ids = {i["finding_id"] for i in summary["investigations"]}
    assert {r["finding_id"] for r in summary["ranking"]} == ids
    assert summary["ranking"][0]["finding_id"].endswith("155999-8080tcp")  # Log4Shell first
    assert [r["rank"] for r in summary["ranking"]] == list(range(1, len(ids) + 1))
    assert [i["finding_id"] for i in summary["investigations"]] == [r.finding_id for r in reports]


async def test_tool_investigate_finding_includes_risk_score(services):
    mcp = FastMCP("t")
    register_tools(mcp, services)
    result = await mcp.call_tool("investigate_finding", {"fixture": "findings_sample.json"})
    content = result[0] if isinstance(result, tuple) else result
    payload = json.loads(content[0].text)
    assert payload["ok"] is True
    assert payload["investigations"][0]["risk_score"]["components"]
    assert payload["ranking"]
    full = await mcp.call_tool(
        "investigate_finding", {"fixture": "findings_sample.json", "detail": "full"}
    )
    full_content = full[0] if isinstance(full, tuple) else full
    assert json.loads(full_content[0].text)["investigations"][0]["risk_score"]["score"] >= 0
