"""Operator asset inventory: parsing, matching precedence, and pipeline effect."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from riskproof.engine import importer
from riskproof.engine import investigation as inv
from riskproof.errors import ConfigurationError
from riskproof.ingest.inventory import AssetInventory, AssetInventorySource
from riskproof.models.findings import Asset, Finding
from riskproof.models.policy import RiskPolicy

LOG4SHELL = "prod-web-01.demo.local-155999-8080tcp"
ZEROLOGON = "corp-db-02.demo.local-121080-445tcp"


def _finding(**asset: object) -> Finding:
    return Finding(
        finding_id="f-1",
        source="nessus",
        name="Test finding",
        severity="high",
        asset=Asset(asset_id="web01", **asset),  # type: ignore[arg-type]
    )


def _inventory(*rules: dict) -> AssetInventory:
    return AssetInventory.parse({"rules": list(rules)}, "test")


# --- parsing --------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        {"match": "web01", "internet_facting": True},  # typo must not be ignored
        {"match": "web01"},  # sets nothing
        {"match": "10.0.0.0/33", "internet_facing": True},  # bad CIDR
        {"match": "web 01", "internet_facing": True},  # not a hostname
        {"match": [], "internet_facing": True},
        {"match": "web01", "criticality": "extreme"},
    ],
)
def test_invalid_rules_are_rejected(rule):
    with pytest.raises(ConfigurationError):
        _inventory(rule)


def test_missing_rules_key_is_rejected():
    with pytest.raises(ConfigurationError):
        AssetInventory.parse({"rule": []}, "test")


# --- matching ---------------------------------------------------------------------


def test_most_specific_rule_wins_per_field():
    inventory = _inventory(
        {"match": "10.20.0.0/16", "environment": "corp", "internet_facing": False, "owner": "it"},
        {"match": "10.20.5.0/24", "environment": "dmz", "internet_facing": True},
        {"match": "WEB01", "criticality": "critical"},
    )
    finding, rules = inventory.apply(_finding(ip_address="10.20.5.9"))
    asset = finding.asset
    assert asset.criticality.value == "critical"  # host rule
    assert asset.environment == "dmz"  # /24 beats /16
    assert asset.internet_facing is True  # /24 beats /16
    assert asset.owner == "it"  # only the /16 sets it
    assert rules == ["WEB01", "10.20.5.0/24", "10.20.0.0/16"]


def test_earlier_rule_wins_a_tie():
    inventory = _inventory(
        {"match": "web01", "criticality": "high"},
        {"match": "web01", "criticality": "low"},
    )
    finding, _ = inventory.apply(_finding())
    assert finding.asset.criticality.value == "high"


def test_inventory_overrides_context_carried_on_the_finding():
    """An agent-supplied inline finding cannot argue its own asset down."""
    inventory = _inventory({"match": "web01", "criticality": "critical", "internet_facing": True})
    finding, _ = inventory.apply(_finding(criticality="low", internet_facing=False))
    assert finding.asset.criticality.value == "critical"
    assert finding.asset.internet_facing is True


def test_fqdn_label_matches():
    inventory = _inventory({"match": "web01.corp.example", "internet_facing": True})
    finding, rules = inventory.apply(
        _finding(hostname="WEB01", labels={"fqdn": "web01.corp.example"})
    )
    assert finding.asset.internet_facing is True
    assert rules == ["web01.corp.example"]


def test_no_match_leaves_finding_untouched():
    inventory = _inventory({"match": "192.168.0.0/16", "internet_facing": True})
    finding = _finding(ip_address="10.0.0.1")
    assert inventory.apply(finding) == (finding, [])


def test_sample_fixture_findings_are_never_matched():
    inventory = _inventory({"match": "web01", "internet_facing": True})
    finding = _finding().model_copy(update={"source": "fixture"})
    assert inventory.apply(finding) == (finding, [])


# --- file source -------------------------------------------------------------------


def test_source_missing_file_means_no_inventory(tmp_path: Path):
    assert AssetInventorySource(tmp_path / "absent.json").current() is None


def test_source_reloads_when_file_changes(tmp_path: Path):
    path = tmp_path / "assets.json"
    source = AssetInventorySource(path)
    path.write_text(json.dumps({"rules": [{"match": "a", "internet_facing": True}]}))
    first = source.current()
    assert first is not None and source.current() is first  # cached while unchanged
    path.write_text(json.dumps({"rules": [{"match": "abc", "internet_facing": False}]}))
    second = source.current()
    assert second is not None and second.rules[0].match == ["abc"]


def test_source_rejects_invalid_json(tmp_path: Path):
    path = tmp_path / "assets.json"
    path.write_text("{not json")
    with pytest.raises(ConfigurationError):
        AssetInventorySource(path).current()


# --- end to end ---------------------------------------------------------------------


def _write_inventory(services, *rules: dict) -> None:
    services.settings.effective_asset_inventory.write_text(json.dumps({"rules": list(rules)}))


async def test_imported_findings_reach_p1_with_operator_context(services):
    await importer.import_nessus(services, "sample_scan.nessus")
    ids = [LOG4SHELL, ZEROLOGON]

    without = {r.finding_id: r for r in await inv.investigate(services, finding_ids=ids)}
    assert without[LOG4SHELL].assessment.recommended_priority.value == "P2"
    assert any("RISKPROOF_ASSET_INVENTORY" in q for q in without[LOG4SHELL].record.open_questions)

    _write_inventory(
        services,
        {"match": "10.20.0.0/24", "environment": "production", "internet_facing": False},
        {"match": "prod-web-01.demo.local", "criticality": "critical", "internet_facing": True},
        {"match": "corp-db-02", "criticality": "critical"},
    )
    with_ctx = {r.finding_id: r for r in await inv.investigate(services, finding_ids=ids)}
    log4shell = with_ctx[LOG4SHELL]
    assert log4shell.assessment.recommended_priority.value == "P1"
    assert log4shell.finding.asset.internet_facing is True
    asset_ev = next(e for e in log4shell.record.evidence if e.kind == "asset_context")
    assert asset_ev.source == "operator-inventory"
    assert asset_ev.details["inventory_rules"] == ["prod-web-01.demo.local", "10.20.0.0/24"]
    assert with_ctx[ZEROLOGON].assessment.recommended_priority.value == "P1"  # KEV + critical

    # Stored findings stay as the scanner reported them...
    assert services.findings.get(LOG4SHELL).asset.internet_facing is None
    # ...while later steps assess with the operator's context.
    decisions = inv.execute_risk_policy(services, ids, RiskPolicy())
    assert [d.priority.value for d in decisions] == ["P1", "P1"]


async def test_invalid_inventory_fails_loudly(services):
    await importer.import_nessus(services, "sample_scan.nessus")
    services.settings.effective_asset_inventory.write_text('{"rules": [{"match": "x"}]}')
    with pytest.raises(ConfigurationError):
        await inv.investigate(services, finding_ids=[LOG4SHELL])


def test_inventory_label_is_kept_but_never_used_for_matching():
    inv = AssetInventory.parse(
        {"label": "DEMO: invented", "rules": [{"match": "web01", "criticality": "high"}]}, "t"
    )
    assert inv.label == "DEMO: invented"
    assert AssetInventory.parse({"rules": [{"match": "web01", "owner": "x"}]}, "t").label is None


def test_inventory_label_is_length_limited():
    with pytest.raises(ConfigurationError):
        AssetInventory.parse({"label": "x" * 301, "rules": [{"match": "web01", "owner": "x"}]}, "t")
