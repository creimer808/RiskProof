"""Distinct affected-asset counts per vulnerability (open findings only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from riskproof.models.findings import Asset, Finding, Severity
from riskproof.services import Services

T0 = datetime(2026, 11, 1, tzinfo=UTC)
LOG4J = "CVE-2021-44228"


def make(fid: str, asset: str, cves=None, plugin: str | None = None, state: str | None = None):
    return Finding(
        finding_id=fid,
        source="tenable",
        name=fid,
        severity=Severity.HIGH,
        cve_ids=cves or [],
        plugin_id=plugin,
        asset=Asset(asset_id=asset),
        raw={"state": state},
    )


def test_counts_distinct_assets_per_cve(services: Services) -> None:
    services.findings.save_many(
        [
            make("a", "host1", [LOG4J]),
            make("b", "host1", [LOG4J, "CVE-2020-1472"]),  # same asset twice: counts once
            make("c", "host2", [LOG4J]),
        ],
        now=T0,
    )
    counts = services.findings.affected_asset_counts([LOG4J, "CVE-2020-1472"], [])
    assert counts == {LOG4J: 2, "CVE-2020-1472": 1}


def test_resolved_and_not_seen_findings_are_not_counted(services: Services) -> None:
    services.findings.save_many(
        [
            make("a", "host1", [LOG4J]),
            make("b", "host2", [LOG4J], state="FIXED"),
            make("c", "host3", [LOG4J]),
        ],
        now=T0,
    )
    services.findings.save_many([make("a", "host1", [LOG4J])], now=T0 + timedelta(days=7))
    services.findings.reconcile_unseen(
        source="tenable",
        severities=["high"],
        seen_before=T0 + timedelta(days=1),
        apply=True,
        max_fraction=1.0,
    )  # host3 (c) was not re-seen -> not_seen
    assert services.findings.affected_asset_counts([LOG4J], []) == {LOG4J: 1}


def test_plugin_fallback_counts_only_cve_less_findings(services: Services) -> None:
    services.findings.save_many(
        [
            make("a", "host1", plugin="999"),
            make("b", "host2", plugin="999"),
            make("c", "host3", [LOG4J], plugin="999"),  # has a CVE: not a plugin-only finding
        ],
        now=T0,
    )
    assert services.findings.affected_asset_counts([], ["999"]) == {"plugin:999": 2}


def test_unknown_keys_omitted_and_empty_input_ok(services: Services) -> None:
    services.findings.save_many([make("a", "host1", [LOG4J])], now=T0)
    assert services.findings.affected_asset_counts(["CVE-2099-0001"], ["nope"]) == {}
    assert services.findings.affected_asset_counts([], []) == {}


def test_more_than_500_cves_chunked(services: Services) -> None:
    services.findings.save_many(
        [make("a", "host1", [LOG4J]), make("b", "host2", ["CVE-2020-1472"])], now=T0
    )
    wanted = [f"CVE-2000-{i:04d}" for i in range(1200)] + [LOG4J, "CVE-2020-1472"]
    assert services.findings.affected_asset_counts(wanted, []) == {
        LOG4J: 1,
        "CVE-2020-1472": 1,
    }
