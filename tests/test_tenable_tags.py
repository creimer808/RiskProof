"""Tenable asset tags: import filters, capture on findings, and tag discovery.

Mock transport only. Tenable documents the ``tag.<Category>`` export filter and the
``GET /tags/values`` listing; it does not document whether exported vulnerability
records carry the asset's tags, so the importer works either way: tags in the record
win, otherwise the tags the export was filtered on are recorded. These tests prove the
client and importer follow the documented request shapes. They do NOT prove
compatibility with a live tenant.
"""

from __future__ import annotations

import json

import httpx
import pytest

from riskproof.engine import importer
from riskproof.errors import InvalidInputError, ProviderUnavailable
from riskproof.ingest.tenable import finding_from_tenable_vuln
from riskproof.models.findings import Asset, Finding
from riskproof.providers.tenable import TenableClient

EXPORT_UUID = "a1b2c3d4-0000-1111-2222-333344445555"
BASE = "https://cloud.example.test"


def vuln(host="web-01", plugin_id=155999, **over):
    record = {
        "asset": {"uuid": f"uuid-{host}", "hostname": host, "ipv4": ["10.0.0.5"]},
        "plugin": {"id": plugin_id, "name": "Apache Log4j 2.x RCE", "cve": ["CVE-2021-44228"]},
        "port": {"port": 8080, "protocol": "TCP"},
        "severity": "critical",
        "severity_id": 4,
        "state": "OPEN",
        "last_found": "2026-10-27T14:14:20.000Z",
    }
    record.update(over)
    return record


class FakeTenable:
    def __init__(self, vulns, tag_pages=None):
        self.vulns = vulns
        self.tag_pages = tag_pages or []
        self.export_bodies: list[dict] = []
        self.tag_queries: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/vulns/export":
            self.export_bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"export_uuid": EXPORT_UUID})
        if path == f"/vulns/export/{EXPORT_UUID}/status":
            return httpx.Response(200, json={"status": "FINISHED", "chunks_available": [1]})
        if path == f"/vulns/export/{EXPORT_UUID}/chunks/1":
            return httpx.Response(200, json=self.vulns)
        if request.method == "GET" and path == "/tags/values":
            query = dict(request.url.params)
            self.tag_queries.append(query)
            offset = int(query.get("offset", 0))
            page = self.tag_pages[offset // 2] if offset // 2 < len(self.tag_pages) else []
            total = sum(len(p) for p in self.tag_pages)
            return httpx.Response(
                200, json={"values": page, "pagination": {"offset": offset, "total": total}}
            )
        return httpx.Response(404)


def make_client(fake: FakeTenable) -> TenableClient:
    async def no_sleep(_: float) -> None:
        return None

    return TenableClient(
        base_url=BASE,
        access_key="acc",
        secret_key="sec",
        transport=httpx.MockTransport(fake.handler),
        sleep=no_sleep,
    )


def tag_value(category, value):
    return {"uuid": f"u-{category}-{value}", "category_name": category, "value": value}


# --- filter building --------------------------------------------------------------


def test_tag_filters_use_the_documented_tag_dot_category_keys():
    filters = importer.build_tenable_filters(
        None, None, None, None, tags={"Location": ["DMZ"], "Team": ["Network", "Platform"]}
    )
    assert filters["tag.Location"] == ["DMZ"]
    assert filters["tag.Team"] == ["Network", "Platform"]
    assert filters["severity"] == ["critical", "high"]


def test_no_tags_leaves_filters_unchanged():
    assert importer.build_tenable_filters(None, None, None, None, tags=None) == (
        importer.build_tenable_filters(None, None, None, None)
    )
    assert not any(
        k.startswith("tag.")
        for k in importer.build_tenable_filters(None, None, None, None, tags={})
    )


@pytest.mark.parametrize(
    "tags",
    [
        {"": ["DMZ"]},
        {"Location": []},
        {"Location": [""]},
        {"Location": ["DMZ\nInternal"]},
        {"Loca\x00tion": ["DMZ"]},
        {"L" * 200: ["DMZ"]},
        {"Location": ["v" * 300]},
        {f"cat{i}": ["x"] for i in range(11)},
        {"Location": [f"v{i}" for i in range(51)]},
        {"Location": "DMZ"},
    ],
)
def test_bad_tag_filters_are_rejected(tags):
    with pytest.raises(InvalidInputError):
        importer.build_tenable_filters(None, None, None, None, tags=tags)


def test_tag_values_are_trimmed_and_deduplicated():
    filters = importer.build_tenable_filters(
        None, None, None, None, tags={" Location ": [" DMZ ", "DMZ", "Edge"]}
    )
    assert filters["tag.Location"] == ["DMZ", "Edge"]


# --- normalizer -------------------------------------------------------------------


def test_record_tags_as_key_value_objects_are_captured():
    record = vuln()
    record["asset"]["tags"] = [
        {"uuid": "t1", "key": "Location", "value": "DMZ"},
        {"uuid": "t2", "key": "Team", "value": "Network"},
        {"uuid": "t3", "key": "Team", "value": "Platform"},
    ]
    asset = finding_from_tenable_vuln(record).asset
    assert asset.tags == {"Location": ["DMZ"], "Team": ["Network", "Platform"]}


def test_record_tags_as_a_category_mapping_are_captured():
    record = vuln()
    record["asset"]["tags"] = {"Location": ["DMZ"], "Owner": "dbteam"}
    assert finding_from_tenable_vuln(record).asset.tags == {
        "Location": ["DMZ"],
        "Owner": ["dbteam"],
    }


@pytest.mark.parametrize(
    "junk",
    [
        None,
        "DMZ",
        7,
        [None, 3, "x", {"key": "k"}, {"value": "v"}, {"key": {}, "value": []}],
        {"a": {}},
    ],
)
def test_hostile_tag_shapes_never_break_the_record(junk):
    record = vuln()
    record["asset"]["tags"] = junk
    assert finding_from_tenable_vuln(record).asset.tags == {}


def test_tag_volume_is_bounded():
    record = vuln()
    record["asset"]["tags"] = [{"key": f"c{i}", "value": "v" * 999} for i in range(500)]
    tags = finding_from_tenable_vuln(record).asset.tags
    assert 0 < len(tags) <= 50
    assert all(len(v) <= 256 for vals in tags.values() for v in vals)


# --- import ---------------------------------------------------------------------


async def test_tag_filter_is_sent_to_tenable(services):
    fake = FakeTenable([vuln()])
    await importer.import_tenable(services, tags={"Location": ["DMZ"]}, client=make_client(fake))
    assert fake.export_bodies[0]["filters"]["tag.Location"] == ["DMZ"]
    assert fake.export_bodies[0]["filters"]["severity"] == ["critical", "high"]


async def test_filtered_tags_are_recorded_when_the_export_omits_them(services):
    fake = FakeTenable([vuln(), vuln(host="web-02")])
    summary = await importer.import_tenable(
        services, tags={"Location": ["DMZ"], "Team": ["Network"]}, client=make_client(fake)
    )
    stored = services.findings.get(finding_from_tenable_vuln(vuln()).finding_id)
    assert stored.asset.tags == {"Location": ["DMZ"], "Team": ["Network"]}
    assert stored.raw["tags_source"] == "import_filter"
    assert summary["tags"]["recorded_from_filter"] == 2
    assert any("did not include asset tags" in w for w in summary["warnings"])


async def test_multi_value_filter_does_not_guess_which_tag_applies(services):
    fake = FakeTenable([vuln()])
    summary = await importer.import_tenable(
        services, tags={"Location": ["DMZ", "Edge"], "Team": ["Network"]}, client=make_client(fake)
    )
    stored = services.findings.get(finding_from_tenable_vuln(vuln()).finding_id)
    assert stored.asset.tags == {"Team": ["Network"]}
    assert any("Location" in w and "several values" in w for w in summary["warnings"])


async def test_tags_in_the_record_win_over_the_filter(services):
    record = vuln()
    record["asset"]["tags"] = [{"key": "Location", "value": "DMZ"}, {"key": "Team", "value": "Db"}]
    fake = FakeTenable([record])
    summary = await importer.import_tenable(
        services, tags={"Location": ["DMZ"]}, client=make_client(fake)
    )
    stored = services.findings.get(finding_from_tenable_vuln(record).finding_id)
    assert stored.asset.tags == {"Location": ["DMZ"], "Team": ["Db"]}
    assert stored.raw["tags_source"] == "export"
    assert summary["tags"]["recorded_from_export"] == 1
    assert not any("did not include asset tags" in w for w in summary["warnings"])


async def test_unfiltered_import_without_tags_reports_nothing_about_tags(services):
    summary = await importer.import_tenable(services, client=make_client(FakeTenable([vuln()])))
    assert "tags" not in summary or summary["tags"]["recorded_from_filter"] == 0
    assert not any("tag" in w.lower() for w in summary["warnings"])


async def test_tags_survive_a_reimport_that_lacks_them(services):
    fid = finding_from_tenable_vuln(vuln()).finding_id
    await importer.import_tenable(
        services, tags={"Location": ["DMZ"]}, client=make_client(FakeTenable([vuln()]))
    )
    await importer.import_tenable(services, client=make_client(FakeTenable([vuln()])))
    assert services.findings.get(fid).asset.tags == {"Location": ["DMZ"]}


async def test_tags_in_a_later_export_replace_stored_ones(services):
    fid = finding_from_tenable_vuln(vuln()).finding_id
    await importer.import_tenable(
        services, tags={"Location": ["DMZ"]}, client=make_client(FakeTenable([vuln()]))
    )
    moved = vuln()
    moved["asset"]["tags"] = [{"key": "Location", "value": "Internal"}]
    await importer.import_tenable(services, client=make_client(FakeTenable([moved])))
    assert services.findings.get(fid).asset.tags == {"Location": ["Internal"]}


async def test_empty_tag_result_points_at_spelling_and_discovery(services):
    summary = await importer.import_tenable(
        services, tags={"Locaton": ["DMZ"]}, client=make_client(FakeTenable([]))
    )
    assert any("list_tenable_tags" in w for w in summary["warnings"])


async def test_tag_filtered_import_never_reconciles(services):
    await importer.import_tenable(
        services, client=make_client(FakeTenable([vuln(), vuln("web-02")]))
    )
    summary = await importer.import_tenable(
        services,
        tags={"Location": ["DMZ"]},
        reconcile=True,
        client=make_client(FakeTenable([vuln()])),
    )
    rec = summary["reconciliation"]
    assert rec["applied"] is False and "tag" in rec["skipped_reason"]
    other = finding_from_tenable_vuln(vuln("web-02")).finding_id
    row = services.db.query_one("SELECT status FROM findings WHERE finding_id = ?", (other,))
    assert row["status"] == "open"


# --- tag discovery ---------------------------------------------------------------


async def test_list_tag_values_groups_values_by_category():
    fake = FakeTenable(
        [],
        tag_pages=[
            [tag_value("Location", "DMZ"), tag_value("Location", "Internal")],
            [tag_value("Team", "Network"), {"category_name": "Empty"}],
        ],
    )
    result = await make_client(fake).list_tag_values(page_size=2)
    assert result.categories == {
        "Location": ["DMZ", "Internal"],
        "Team": ["Network"],
        "Empty": [],
    }
    assert result.total_values == 3  # "Empty" is a category with no values
    assert result.truncated is False
    assert [q["offset"] for q in fake.tag_queries] == ["0", "2", "4"]


async def test_list_tag_values_is_capped_and_says_so():
    pages = [[tag_value("C", f"v{i}"), tag_value("C", f"w{i}")] for i in range(5)]
    result = await make_client(FakeTenable([], tag_pages=pages)).list_tag_values(
        page_size=2, max_values=4
    )
    assert result.truncated is True
    assert len(result.categories["C"]) == 4


async def test_list_tag_values_ignores_hostile_entries():
    pages = [[None, 3, {"category_name": {}, "value": []}, tag_value("Ok", "yes")]]
    result = await make_client(FakeTenable([], tag_pages=pages)).list_tag_values(page_size=10)
    assert result.categories == {"Ok": ["yes"]}


async def test_list_tag_values_failure_is_provider_unavailable():
    def handler(request):
        return httpx.Response(500)

    client = TenableClient(
        base_url=BASE, access_key="a", secret_key="s", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ProviderUnavailable):
        await client.list_tag_values()


# --- model ---------------------------------------------------------------------


def test_asset_tags_default_empty_and_old_payloads_still_load():
    old = Finding(finding_id="x", name="n", asset=Asset(asset_id="a")).model_dump()
    old["asset"].pop("tags")
    assert Finding.model_validate(old).asset.tags == {}


# --- tools ---------------------------------------------------------------------


async def test_tools_expose_the_tag_filter_and_tag_listing(services):
    from mcp.server.fastmcp import FastMCP

    from riskproof.tools import register_tools

    mcp = FastMCP("t")
    register_tools(mcp, services)
    tools = {t.name: t for t in await mcp.list_tools()}
    assert "tags" in tools["import_tenable"].inputSchema["properties"]
    assert "list_tenable_tags" in tools
    assert tools["list_tenable_tags"].inputSchema.get("properties", {}) == {}


async def test_list_tenable_tags_tool_returns_categories(services, monkeypatch):
    from mcp.server.fastmcp import FastMCP

    from riskproof.tools import register_tools

    fake = FakeTenable([], tag_pages=[[tag_value("Location", "DMZ"), tag_value("Team", "Net")]])
    monkeypatch.setattr(
        importer.TenableClient, "from_env", classmethod(lambda cls, settings: make_client(fake))
    )
    mcp = FastMCP("t")
    register_tools(mcp, services)
    _, result = await mcp.call_tool("list_tenable_tags", {})
    assert result["ok"] is True
    assert result["categories"] == {"Location": ["DMZ"], "Team": ["Net"]}
    assert result["truncated"] is False
    assert "tag" in result["usage"]


async def test_list_tenable_tags_without_credentials_tells_the_operator(services, monkeypatch):
    from mcp.server.fastmcp import FastMCP

    from riskproof.tools import register_tools

    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    mcp = FastMCP("t")
    register_tools(mcp, services)
    _, result = await mcp.call_tool("list_tenable_tags", {})
    assert result["ok"] is False and "TENABLE_ACCESS_KEY" in result["error"]["message"]


async def test_bad_tags_through_the_tool_are_a_structured_error(services):
    from mcp.server.fastmcp import FastMCP

    from riskproof.tools import register_tools

    mcp = FastMCP("t")
    register_tools(mcp, services)
    _, result = await mcp.call_tool("import_tenable", {"tags": {"Location": []}})
    assert result["ok"] is False and result["error"]["code"] == "invalid_input"
