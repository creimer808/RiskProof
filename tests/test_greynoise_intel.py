"""GreyNoise in the intel step: enrichment, evidence, caveats, fixtures, ordering."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from riskproof.engine import investigation as inv
from riskproof.engine.evidence import GREYNOISE_CAVEAT, build_investigation_record
from riskproof.models.evidence import Confidence, EvidenceKind
from riskproof.models.findings import Asset, Finding, normalize_cve
from riskproof.models.intel import GreyNoiseResult, GreyNoiseTag
from riskproof.providers.base import ProviderError
from riskproof.providers.greynoise import GreyNoiseProvider

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
LOG4J = "CVE-2021-44228"
ZERO = "CVE-2020-1472"


class FakeGreyNoise:
    configured = True

    def __init__(self, results=None, error: Exception | None = None):
        self._results = results or {}
        self._error = error
        self.calls: list[list[str]] = []

    async def lookup(self, cves, now=None):
        self.calls.append(list(cves))
        if self._error:
            raise self._error
        return {c: self._results[c] for c in cves if c in self._results}


def observed(cve: str = LOG4J) -> GreyNoiseResult:
    return GreyNoiseResult(
        cve=cve,
        state="observed",
        tags=[GreyNoiseTag(id="t1", slug="log4j", name="Log4j RCE Attempt", intention="malicious")],
        malicious_ips_by_day={"2026-11-01": 11, "2026-11-02": 22},
        peak_malicious_ips=22,
        last_malicious_day="2026-11-02",
    )


@pytest.fixture()
def live(services, monkeypatch):
    """Services whose EPSS/KEV network calls are stubbed out (live code path)."""

    async def no_epss(cves):
        return {}

    async def no_kev(cves):
        return []

    monkeypatch.setattr(services.epss, "fetch", no_epss)
    monkeypatch.setattr(services.kev, "status_for", no_kev)
    return services


def finding(cve: str = LOG4J) -> Finding:
    return Finding(
        finding_id="f-1", name="x", severity="critical", cve_ids=[cve], asset=Asset(asset_id="a1")
    )


async def test_fixture_mode_adds_sample_greynoise(services):
    bundle = await inv.enrich_threat_intel(services, [LOG4J, ZERO, "CVE-2024-6387"], "fixture")
    assert bundle.greynoise_source == "sample-fixture"
    assert bundle.greynoise[LOG4J].state == "observed"
    assert bundle.greynoise[ZERO].state == "quiet"
    assert bundle.greynoise["CVE-2024-6387"].state == "no_data"
    assert bundle.degraded is True


async def test_live_mode_without_key_has_no_greynoise_and_no_evidence(live):
    live.greynoise = GreyNoiseProvider(api_key=None)
    bundle = await inv.enrich_threat_intel(live, [LOG4J], "live")
    assert bundle.greynoise == {} and bundle.greynoise_source == "unavailable"
    assert not any("GreyNoise" in n for n in bundle.notices)
    record = build_investigation_record(finding(), bundle)
    assert not any("GreyNoise" in e.statement for e in record.evidence)


async def test_live_mode_with_key_records_results_and_evidence(live):
    live.greynoise = FakeGreyNoise({LOG4J: observed()})
    bundle = await inv.enrich_threat_intel(live, [LOG4J], "live")
    assert bundle.greynoise_source == "greynoise"
    assert bundle.greynoise[LOG4J].state == "observed"
    record = build_investigation_record(finding(), bundle)
    gn = [e for e in record.evidence if "GreyNoise" in e.statement]
    assert len(gn) == 1
    assert gn[0].kind == EvidenceKind.THREAT_INTEL
    assert gn[0].confidence == Confidence.CONFIRMED
    assert gn[0].source == "greynoise"
    assert GREYNOISE_CAVEAT in gn[0].statement
    assert "22" in gn[0].statement  # peak distinct IPs is shown


async def test_greynoise_gap_is_reported_as_missing_evidence(live):
    gap = GreyNoiseResult(cve=LOG4J, state="not_checked", reason="call budget spent")
    live.greynoise = FakeGreyNoise({LOG4J: gap})
    bundle = await inv.enrich_threat_intel(live, [LOG4J], "live")
    record = build_investigation_record(finding(), bundle)
    (item,) = [e for e in record.evidence if "GreyNoise" in e.statement]
    assert item.confidence == Confidence.MISSING
    assert "call budget spent" in item.statement


async def test_greynoise_failure_adds_notice_not_degraded(live):
    live.greynoise = FakeGreyNoise(error=ProviderError("catalog HTTP 500"))
    bundle = await inv.enrich_threat_intel(live, [LOG4J], "live")
    assert any("GreyNoise" in n and "catalog HTTP 500" in n for n in bundle.notices)
    assert bundle.greynoise_source == "unavailable"
    assert bundle.greynoise[LOG4J].state == "not_checked"
    assert bundle.degraded is False  # an optional source never trips the degraded banner


async def test_source_live_never_uses_fixture_greynoise(live):
    assert live.settings.offline is True
    live.greynoise = GreyNoiseProvider(api_key=None)
    bundle = await inv.enrich_threat_intel(live, [LOG4J], "live")
    assert bundle.greynoise_source == "unavailable" and bundle.greynoise == {}


async def test_missing_greynoise_fixture_file_does_not_break_offline_use(services, tmp_path):
    from riskproof.providers.fixtures_source import FixtureIntelSource

    custom = tmp_path / "fx"
    custom.mkdir()
    for name in ("epss_sample.json", "kev_sample.json"):
        (custom / name).write_text((FIXTURES / name).read_text(encoding="utf-8"), encoding="utf-8")
    services.fixture_intel = FixtureIntelSource(custom)
    bundle = await inv.enrich_threat_intel(services, [LOG4J], "fixture")
    assert bundle.greynoise_source == "unavailable" and bundle.greynoise == {}
    assert bundle.epss_source == "sample-fixture"


async def test_summary_states_greynoise_caveat_once(services):
    reports = await inv.investigate(services, fixture="findings_sample.json")
    summary = inv.summarize_reports(reports)
    assert summary["intel_caveats"]["greynoise"] == GREYNOISE_CAVEAT
    assert all(p["greynoise_source"] == "sample-fixture" for p in summary["intel_provenance"])
    log4j = next(s for s in summary["investigations"] if LOG4J in s["cve_ids"])
    statements = [e["statement"] for e in log4j["evidence"]]
    assert any("GreyNoise" in s for s in statements)
    assert not any(GREYNOISE_CAVEAT in s for s in statements)


async def test_investigate_orders_cves_by_severity(services, monkeypatch):
    seen: list[list[str]] = []
    real = inv.enrich_threat_intel

    async def spy(svc, cve_ids, source="auto"):
        seen.append(list(cve_ids))
        return await real(svc, cve_ids, source)

    monkeypatch.setattr(inv, "enrich_threat_intel", spy)
    await inv.investigate(services, fixture="findings_sample.json")
    # critical (alphabetical), then high, then medium
    assert seen == [[ZERO, LOG4J, "CVE-2024-6387", "CVE-2023-48795"]]


def test_fixture_sample_cves_all_valid():
    data = json.loads((FIXTURES / "greynoise_sample.json").read_text(encoding="utf-8"))
    cves = {c for t in data["tags"] for c in t["cves"]}
    assert cves and all(normalize_cve(c) == c for c in cves)
    assert datetime.now(UTC)  # sample activity is relative (days_ago), never absolute dates
    assert all("days_ago" in b for buckets in data["activity"].values() for b in buckets)


async def test_no_data_statement_has_no_doubled_period(live):
    live.greynoise = FakeGreyNoise(
        {
            LOG4J: GreyNoiseResult(
                cve=LOG4J, state="no_data", reason="No GreyNoise tag maps to this CVE."
            )
        }
    )
    bundle = await inv.enrich_threat_intel(live, [LOG4J], "live")
    record = build_investigation_record(finding(), bundle)
    (item,) = [e for e in record.evidence if "GreyNoise" in e.statement]
    assert ".." not in item.statement
    assert item.statement.endswith(".")
