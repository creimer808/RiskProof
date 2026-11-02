"""Inventory rules that match on Tenable asset tags, and tags in the report.

A tag rule lets the operator say what a tag *means* ("Location: DMZ" is internet
facing) once, instead of listing every host. Tags come from Tenable; what they imply
comes only from the operator's inventory file, so an agent cannot assert it.
"""

from __future__ import annotations

import pytest

from riskproof.engine import investigation as inv
from riskproof.engine.report import build_report, render_html
from riskproof.errors import ConfigurationError
from riskproof.ingest.inventory import AssetInventory
from riskproof.models.findings import Asset, Finding


def finding(host="web01", ip=None, tags=None, source="tenable", cve=None):
    return Finding(
        finding_id=f"f-{host}",
        source=source,
        name="Test finding",
        severity="critical",
        cve_ids=[cve] if cve else [],
        asset=Asset(asset_id=host, ip_address=ip, tags=tags or {}),
    )


def inventory(*rules):
    return AssetInventory.parse({"rules": list(rules)}, "test")


def test_tag_rule_sets_context_for_every_asset_with_the_tag():
    inv_ = inventory({"tags": {"Location": "DMZ"}, "internet_facing": True, "environment": "dmz"})
    enriched, used = inv_.apply(finding(tags={"Location": ["DMZ"]}))
    assert enriched.asset.internet_facing is True and enriched.asset.environment == "dmz"
    assert used == ["tag:Location=DMZ"]


def test_tag_match_is_case_insensitive_and_any_listed_value_counts():
    inv_ = inventory({"tags": {"location": ["dmz", "edge"]}, "internet_facing": True})
    assert inv_.apply(finding(tags={"Location": ["EDGE"]}))[0].asset.internet_facing is True
    assert inv_.apply(finding(tags={"Location": ["Internal"]}))[0].asset.internet_facing is None


def test_all_tag_categories_in_a_rule_must_match():
    inv_ = inventory({"tags": {"Location": "DMZ", "Team": "Network"}, "criticality": "high"})
    assert inv_.apply(finding(tags={"Location": ["DMZ"]}))[1] == []
    both = finding(tags={"Location": ["DMZ"], "Team": ["Network"]})
    assert inv_.apply(both)[0].asset.criticality.value == "high"


def test_an_asset_without_tags_matches_no_tag_rule():
    inv_ = inventory({"tags": {"Location": "DMZ"}, "internet_facing": True})
    assert inv_.apply(finding())[1] == []


def test_match_and_tags_together_must_both_hold():
    inv_ = inventory({"match": "10.0.0.0/24", "tags": {"Team": "Db"}, "criticality": "critical"})
    assert inv_.apply(finding(ip="10.0.0.9", tags={"Team": ["Db"]}))[1]
    assert inv_.apply(finding(ip="10.0.0.9", tags={"Team": ["Web"]}))[1] == []
    assert inv_.apply(finding(ip="192.168.1.9", tags={"Team": ["Db"]}))[1] == []


def test_precedence_is_hostname_then_tag_then_cidr():
    inv_ = inventory(
        {"match": "10.0.0.0/8", "owner": "from-cidr", "environment": "cidr-env"},
        {"tags": {"Team": "Network"}, "owner": "from-tag", "criticality": "high"},
        {"match": "web01", "owner": "from-host"},
    )
    out = inv_.apply(finding(ip="10.1.1.1", tags={"Team": ["Network"]}))[0].asset
    assert out.owner == "from-host"  # hostname beats tag and CIDR
    assert out.criticality.value == "high"  # only the tag rule sets it
    assert out.environment == "cidr-env"  # only the CIDR rule sets it
    other = inv_.apply(finding(host="db9", ip="10.1.1.1", tags={"Team": ["Network"]}))[0].asset
    assert other.owner == "from-tag"  # tag beats CIDR


def test_fixture_findings_never_match_tag_rules():
    inv_ = inventory({"tags": {"Location": "DMZ"}, "internet_facing": True})
    assert inv_.apply(finding(tags={"Location": ["DMZ"]}, source="fixture"))[1] == []


@pytest.mark.parametrize(
    "rule",
    [
        {"tags": {"Location": "DMZ"}},  # sets no context
        {"tags": {}, "internet_facing": True},  # neither match nor tags
        {"tags": {"Location": []}, "internet_facing": True},
        {"tags": {"": "DMZ"}, "internet_facing": True},
        {"tags": {"Location": "DMZ"}, "internet_facting": True},  # typo
        {"tags": "DMZ", "internet_facing": True},
    ],
)
def test_invalid_tag_rules_are_rejected(rule):
    with pytest.raises(ConfigurationError):
        inventory(rule)


async def test_tag_rule_reaches_p1_through_the_pipeline(services, settings):
    import json

    settings.asset_inventory.write_text(
        json.dumps(
            {
                "rules": [
                    {"tags": {"Location": "DMZ"}, "internet_facing": True, "criticality": "high"}
                ]
            }
        )
    )
    services.findings.save(
        finding(host="dmz-web", tags={"Location": ["DMZ"]}, cve="CVE-2021-44228")
    )
    await inv.investigate(services, finding_id="f-dmz-web", intel_source="fixture")
    assessment = services.investigations.get("f-dmz-web")
    assert "tag:Location=DMZ" in json.dumps(assessment.model_dump(mode="json"))
    report = build_report(services)
    asset = report.assets[0]
    assert asset.internet_facing is True
    assert asset.tags == {"Location": ["DMZ"]}


async def test_report_shows_asset_tags_escaped(services):
    services.findings.save(
        finding(host="dmz-web", tags={"Location": ["<b>DMZ</b>"]}, cve="CVE-2021-44228")
    )
    await inv.investigate(services, finding_id="f-dmz-web", intel_source="fixture")
    page = render_html(build_report(services))
    assert "Location" in page
    assert "&lt;b&gt;DMZ&lt;/b&gt;" in page
    assert "<b>DMZ</b>" not in page


async def test_investigation_summary_shows_tags_only_when_present(services):
    services.findings.save(finding(host="tagged", tags={"Team": ["Network"]}))
    services.findings.save(finding(host="plain"))
    out = await inv.investigate(
        services, finding_ids=["f-tagged", "f-plain"], intel_source="fixture"
    )
    by_id = {r.summary()["finding_id"]: r.summary() for r in out}
    assert by_id["f-tagged"]["asset"]["tags"] == {"Team": ["Network"]}
    assert "tags" not in by_id["f-plain"]["asset"]
