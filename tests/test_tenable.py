"""Tests for the Tenable VM export client and normalizer (mock transport only).

These tests prove the client follows the documented export flow and handles
failure modes safely. They do NOT prove compatibility with a live tenant.
"""

from __future__ import annotations

import json

import httpx
import pytest

from riskproof.engine import importer
from riskproof.errors import InvalidInputError, ProviderUnavailable
from riskproof.ingest.tenable import finding_from_tenable_vuln
from riskproof.providers.tenable import TenableBridge, TenableClient

SECRET = "s3cr3t-key-value"
ACCESS = "acc3ss-key-value"
EXPORT_UUID = "a1b2c3d4-0000-1111-2222-333344445555"
BASE = "https://cloud.example.test"


def vuln(**over):
    record = {
        "asset": {
            "uuid": "11111111-2222-3333-4444-555555555555",
            "hostname": "web-01",
            "fqdn": ["web-01.corp.example"],
            "ipv4": ["10.0.0.5"],
            "operating_system": ["Ubuntu 22.04"],
        },
        "output": "Installed version : 2.14.1",
        "plugin": {
            "id": 155999,
            "name": "Apache Log4j 2.x RCE",
            "family": "Web Servers",
            "description": "Log4Shell",
            "solution": "Upgrade",
            "cve": ["CVE-2021-44228", "not-a-cve"],
            "cvss3_base_score": 10.0,
            "cvss3_vector": {"raw": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
            "vpr": {"score": 9.9},
            "has_patch": True,
        },
        "port": {"port": 8080, "protocol": "TCP", "service": "www"},
        "scan": {"uuid": "scan-1"},
        "severity": "critical",
        "severity_id": 4,
        "state": "OPEN",
        "first_found": "2026-10-01T10:00:00.000Z",
        "last_found": "2026-10-27T14:14:20.000Z",
    }
    record.update(over)
    return record


class FakeTenable:
    """Scripted Tenable export endpoints behind an httpx MockTransport."""

    def __init__(self, chunks, statuses=None, post_status=200):
        self.chunks = chunks
        self.statuses = statuses or [
            {"status": "FINISHED", "chunks_available": list(range(1, len(chunks) + 1))}
        ]
        self.post_status = post_status
        self.requests: list[httpx.Request] = []
        self.cancelled = False
        self._status_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.method == "POST" and path == "/vulns/export":
            if self.post_status != 200:
                return httpx.Response(self.post_status, json={"error": "nope"})
            return httpx.Response(200, json={"export_uuid": EXPORT_UUID})
        if path == f"/vulns/export/{EXPORT_UUID}/status":
            idx = min(self._status_calls, len(self.statuses) - 1)
            self._status_calls += 1
            return httpx.Response(200, json=self.statuses[idx])
        if path.startswith(f"/vulns/export/{EXPORT_UUID}/chunks/"):
            return httpx.Response(200, json=self.chunks[int(path.rsplit("/", 1)[1]) - 1])
        if path == f"/vulns/export/{EXPORT_UUID}/cancel":
            self.cancelled = True
            return httpx.Response(200, json={})
        return httpx.Response(404)


def make_client(fake: FakeTenable) -> TenableClient:
    async def no_sleep(_: float) -> None:
        return None

    return TenableClient(
        base_url=BASE,
        access_key=ACCESS,
        secret_key=SECRET,
        transport=httpx.MockTransport(fake.handler),
        sleep=no_sleep,
    )


# --- normalizer --------------------------------------------------------------


def test_normalizer_maps_fields():
    f = finding_from_tenable_vuln(vuln())
    assert f.source == "tenable"
    assert f.severity.value == "critical"
    assert f.cve_ids == ["CVE-2021-44228"]  # invalid CVE dropped, not fatal
    assert f.raw["dropped_invalid_cves"] == ["not-a-cve"]
    assert f.cvss_v3.base_score == 10.0 and f.cvss_v3.vector.startswith("AV:N")
    assert f.vpr.score == 9.9
    assert f.port == 8080 and f.protocol == "tcp" and f.service == "www"
    assert f.asset.hostname == "web-01" and f.asset.ip_address == "10.0.0.5"
    assert f.asset.labels["tenable_asset_uuid"].startswith("11111111")
    assert f.scanned_at is not None
    assert f.finding_id.startswith("tenable-11111111")


def test_normalizer_tolerates_sparse_and_hostile_records():
    sparse = {"asset": {"hostname": "h"}, "plugin": {"id": 1, "name": "x"}, "severity": "weird"}
    f = finding_from_tenable_vuln(sparse)
    assert f.severity.value == "unknown" and f.port is None and f.cve_ids == []

    hostile = vuln(port={"port": 99999, "protocol": "ICMP"}, output={"a": 1})
    f = finding_from_tenable_vuln(hostile)
    assert f.port is None and f.protocol is None and f.plugin_output is None

    with pytest.raises(ValueError):
        finding_from_tenable_vuln({"plugin": {"id": 1}})  # no asset identity


# --- client ------------------------------------------------------------------


async def test_export_flow_and_headers():
    fake = FakeTenable([[vuln()], [vuln(plugin={"id": 2, "name": "other"})]])
    result = await make_client(fake).export_vulns(filters={"severity": ["high"]}, limit=100)
    assert len(result.vulns) == 2 and result.chunks_downloaded == 2 and not result.truncated
    post = next(r for r in fake.requests if r.method == "POST")
    assert json.loads(post.content)["filters"] == {"severity": ["high"]}
    for request in fake.requests:
        assert request.headers["X-ApiKeys"] == f"accessKey={ACCESS}; secretKey={SECRET};"
    assert not fake.cancelled


async def test_polls_until_finished():
    fake = FakeTenable(
        [[vuln()]],
        statuses=[
            {"status": "PROCESSING", "chunks_available": []},
            {"status": "PROCESSING", "chunks_available": [1]},
            {"status": "FINISHED", "chunks_available": [1]},
        ],
    )
    result = await make_client(fake).export_vulns(filters={}, limit=10)
    assert len(result.vulns) == 1
    assert sum(1 for r in fake.requests if r.url.path.endswith("/chunks/1")) == 1  # no re-download


async def test_limit_truncates_and_cancels():
    fake = FakeTenable([[vuln(), vuln()], [vuln()]])
    result = await make_client(fake).export_vulns(filters={}, limit=1)
    assert len(result.vulns) == 1 and result.truncated and fake.cancelled


async def test_export_error_status_raises_and_cancels():
    fake = FakeTenable([], statuses=[{"status": "ERROR", "chunks_available": []}])
    with pytest.raises(ProviderUnavailable, match="ERROR"):
        await make_client(fake).export_vulns(filters={}, limit=10)
    assert fake.cancelled


async def test_timeout_raises():
    fake = FakeTenable([], statuses=[{"status": "PROCESSING", "chunks_available": []}])
    with pytest.raises(ProviderUnavailable, match="did not finish"):
        await make_client(fake).export_vulns(filters={}, limit=10, timeout_seconds=0.0)


@pytest.mark.parametrize("status", [401, 403])
async def test_auth_failure_message_has_no_secrets(status):
    fake = FakeTenable([], post_status=status)
    with pytest.raises(ProviderUnavailable) as exc:
        await make_client(fake).export_vulns(filters={}, limit=10)
    assert SECRET not in str(exc.value) and ACCESS not in str(exc.value)
    assert str(status) in str(exc.value)


async def test_rate_limit_retries_then_succeeds():
    fake = FakeTenable([[vuln()]])
    original = fake.handler
    calls = {"n": 0}

    def flaky(request):
        if request.method == "POST":
            calls["n"] += 1
            if calls["n"] < 3:
                return httpx.Response(429, headers={"Retry-After": "1"})
        return original(request)

    client = TenableClient(
        base_url=BASE,
        access_key=ACCESS,
        secret_key=SECRET,
        transport=httpx.MockTransport(flaky),
        sleep=lambda _: _noop(),
    )
    result = await client.export_vulns(filters={}, limit=10)
    assert calls["n"] == 3 and len(result.vulns) == 1


async def _noop() -> None:
    return None


async def test_rejects_bad_export_uuid_from_server():
    def handler(request):
        return httpx.Response(200, json={"export_uuid": "../../admin"})

    client = TenableClient(
        base_url=BASE, access_key=ACCESS, secret_key=SECRET,
        transport=httpx.MockTransport(handler),
    )  # fmt: skip
    with pytest.raises(ProviderUnavailable, match="export_uuid"):
        await client.export_vulns(filters={}, limit=10)


async def test_redirects_are_not_followed_so_keys_stay_put():
    seen_hosts = []

    def handler(request):
        seen_hosts.append(request.url.host)
        return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

    client = TenableClient(
        base_url=BASE, access_key=ACCESS, secret_key=SECRET,
        transport=httpx.MockTransport(handler),
    )  # fmt: skip
    with pytest.raises(ProviderUnavailable):
        await client.export_vulns(filters={}, limit=10)
    assert seen_hosts == ["cloud.example.test"]


def test_http_base_url_refused_and_repr_hides_keys():
    with pytest.raises(ProviderUnavailable, match="https"):
        TenableClient(base_url="http://cloud.tenable.com", access_key="a", secret_key="b")
    client = make_client(FakeTenable([]))
    assert SECRET not in repr(client) and ACCESS not in repr(client)


def test_missing_credentials_tell_the_operator(settings, monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    with pytest.raises(ProviderUnavailable, match="TENABLE_ACCESS_KEY"):
        TenableClient.from_env(settings)


def test_bridge_status_reports_presence_only(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", ACCESS)
    monkeypatch.setenv("TENABLE_SECRET_KEY", SECRET)
    status = TenableBridge().integration_status()
    assert status["credentials_configured"] is True
    assert SECRET not in json.dumps(status) and ACCESS not in json.dumps(status)


# --- engine ------------------------------------------------------------------


def test_filter_validation():
    assert importer.build_tenable_filters(None, None, None, None) == {
        "severity": ["critical", "high"],
        "state": ["open", "reopened"],
    }
    assert importer.build_tenable_filters(["high"], ["fixed"], 7, "10.0.0.7/24")["cidr_range"] == (
        "10.0.0.0/24"
    )
    for bad in (
        {"severity": ["urgent"]},
        {"state": ["gone"]},
        {"since_days": 0},
        {"cidr_range": "not-a-cidr"},
    ):
        with pytest.raises(InvalidInputError):
            importer.build_tenable_filters(
                bad.get("severity"), bad.get("state"), bad.get("since_days"), bad.get("cidr_range")
            )


async def test_import_tenable_end_to_end(services):
    bad = {"asset": {}, "plugin": {"id": 7}}  # no identity: skipped with a warning
    fake = FakeTenable([[vuln(), bad], [vuln(plugin={"id": 2, "name": "SSH issue", "cve": []})]])
    summary = await importer.import_tenable(services, client=make_client(fake))
    assert summary["provenance"]["source"] == "tenable"
    assert summary["provenance"]["export_uuid"] == EXPORT_UUID
    assert summary["totals"]["parsed"] == 2
    assert sum("Skipped export record" in w for w in summary["warnings"]) == 1
    assert services.findings.count() == 2
    assert summary["candidates"][0]["cve_count"] == 1
    entry = next(e for e in services.audit.recent() if e["action"] == "import_tenable")
    assert SECRET not in json.dumps(entry) and ACCESS not in json.dumps(entry)


async def test_import_tenable_without_credentials_is_provider_unavailable(services, monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    with pytest.raises(ProviderUnavailable):
        await importer.import_tenable(services)
    assert services.findings.count() == 0


async def test_import_tenable_limit_validation(services):
    with pytest.raises(InvalidInputError):
        await importer.import_tenable(services, limit=0, client=make_client(FakeTenable([])))
