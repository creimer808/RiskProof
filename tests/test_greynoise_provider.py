"""GreyNoise provider: request shape, caching, call budget, and failure handling.

Mock transport only: these tests prove behavior against the documented API shape,
not compatibility with a live GreyNoise account.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from riskproof.config import Settings
from riskproof.errors import ProviderUnavailable
from riskproof.providers.base import ProviderError
from riskproof.providers.greynoise import GreyNoiseProvider
from riskproof.storage.db import Database
from riskproof.storage.repositories import IntelCacheRepository

KEY = "gn-secret-key-value"
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
LOG4J, ZERO, QUIET, UNTAGGED = "CVE-2021-44228", "CVE-2020-1472", "CVE-2019-0708", "CVE-2024-0001"


def tag(tag_id: str, cves: list[str], intention: str = "malicious") -> dict:
    return {
        "id": tag_id,
        "slug": tag_id,
        "name": f"Tag {tag_id}",
        "intention": intention,
        "cves": cves,
    }


def activity(ips_today: int, intention: str = "malicious") -> dict:
    return {
        "slug": "x",
        "activity": {
            intention: [
                {"timestamp": "2026-11-02T00:00:00Z", "active_ips": ips_today},
            ]
        },
        "aggregations": {"total_ips": ips_today},
    }


class FakeGreyNoise:
    def __init__(self, tags, activities, statuses=None, catalog_status=200):
        self.catalog = {"tags": tags}
        self.activities = activities
        self.statuses = statuses or {}
        self.catalog_status = catalog_status
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/v3/tags":
            if self.catalog_status != 200:
                return httpx.Response(self.catalog_status, text="nope")
            return httpx.Response(200, json=self.catalog)
        if path.startswith("/v3/tags/") and path.endswith("/activity"):
            tag_id = path.split("/")[3]
            status = self.statuses.get(tag_id, 200)
            if status != 200:
                return httpx.Response(status, json={"message": "err"})
            return httpx.Response(200, json=self.activities[tag_id])
        return httpx.Response(404)

    def activity_calls(self) -> int:
        return sum(r.url.path.endswith("/activity") for r in self.requests)


def make_fake() -> FakeGreyNoise:
    return FakeGreyNoise(
        tags=[
            tag("t-log4j", [LOG4J]),
            tag("t-zero", [ZERO]),
            tag("t-quiet", [QUIET]),
            tag("t-benign", [UNTAGGED], intention="benign"),
        ],
        activities={"t-log4j": activity(22), "t-zero": activity(7), "t-quiet": activity(0)},
    )


def make_provider(fake: FakeGreyNoise, cache=None, **kw) -> GreyNoiseProvider:
    return GreyNoiseProvider(
        api_key=KEY,
        transport=httpx.MockTransport(fake.handler),
        cache=cache,
        window_days=3,
        **kw,
    )


@pytest.fixture()
def cache(tmp_path: Path):
    db = Database(tmp_path / "g.db")
    yield IntelCacheRepository(db)
    db.close()


async def test_request_shape_and_key_header():
    fake = make_fake()
    await make_provider(fake).lookup([LOG4J], now=NOW)
    first, second = fake.requests
    assert str(first.url) == "https://api.greynoise.io/v3/tags"
    assert first.headers["key"] == KEY
    assert second.url.path == "/v3/tags/t-log4j/activity"
    for request in fake.requests:  # only tag ids leave: no CVE, host or body
        assert "CVE-" not in str(request.url) and not request.content
        assert request.method == "GET"


async def test_lookup_observed_quiet_and_no_data():
    results = await make_provider(make_fake()).lookup([LOG4J, QUIET, UNTAGGED], now=NOW)
    assert results[LOG4J].state == "observed"
    assert results[LOG4J].peak_malicious_ips == 22
    assert results[QUIET].state == "quiet"
    assert results[UNTAGGED].state == "no_data"  # benign-only tag is not kept


async def test_second_lookup_uses_cache_and_makes_no_calls(cache):
    fake = make_fake()
    provider = make_provider(fake, cache=cache)
    await provider.lookup([LOG4J, QUIET], now=NOW)
    calls = len(fake.requests)
    again = await provider.lookup([LOG4J, QUIET], now=NOW)
    assert len(fake.requests) == calls
    assert again[LOG4J].state == "observed"


async def test_catalog_downloaded_once_per_lookup():
    fake = make_fake()
    await make_provider(fake).lookup([LOG4J, ZERO, QUIET], now=NOW)
    assert sum(r.url.path == "/v3/tags" for r in fake.requests) == 1


async def test_budget_marks_remaining_not_checked_in_input_order():
    fake = make_fake()
    results = await make_provider(fake, max_calls=1).lookup([ZERO, LOG4J, QUIET], now=NOW)
    assert results[ZERO].state == "observed"
    assert results[LOG4J].state == "not_checked" and "budget" in results[LOG4J].reason
    assert results[QUIET].state == "not_checked"
    assert fake.activity_calls() == 1


async def test_zero_budget_makes_no_activity_calls_but_no_data_still_answers():
    fake = make_fake()
    results = await make_provider(fake, max_calls=0).lookup([LOG4J, UNTAGGED], now=NOW)
    assert results[LOG4J].state == "not_checked"
    assert results[UNTAGGED].state == "no_data"
    assert fake.activity_calls() == 0


async def test_cached_cves_still_answer_after_budget_is_spent(cache):
    fake = make_fake()
    await make_provider(fake, cache=cache).lookup([LOG4J], now=NOW)
    results = await make_provider(fake, cache=cache, max_calls=0).lookup([LOG4J, ZERO], now=NOW)
    assert results[LOG4J].state == "observed"
    assert results[ZERO].state == "not_checked"


async def test_429_stops_run_keeps_earlier_results():
    fake = make_fake()
    fake.statuses["t-zero"] = 429
    results = await make_provider(fake).lookup([LOG4J, ZERO, QUIET], now=NOW)
    assert results[LOG4J].state == "observed"
    assert results[ZERO].state == "not_checked" and "429" in results[ZERO].reason
    assert results[QUIET].state == "not_checked"
    assert fake.activity_calls() == 2  # nothing after the 429, no retry loop


async def test_auth_rejection_stops_run():
    fake = make_fake()
    fake.statuses["t-log4j"] = 401
    results = await make_provider(fake).lookup([LOG4J, ZERO], now=NOW)
    assert {r.state for r in results.values()} == {"not_checked"}
    assert fake.activity_calls() == 1
    assert KEY not in json.dumps([r.model_dump() for r in results.values()])


async def test_activity_error_marks_only_that_cve_not_checked():
    fake = make_fake()
    fake.statuses["t-zero"] = 500
    results = await make_provider(fake).lookup([ZERO, LOG4J], now=NOW)
    assert results[ZERO].state == "not_checked"
    assert results[LOG4J].state == "observed"


async def test_malformed_activity_payload_marks_not_checked():
    fake = make_fake()
    fake.activities["t-log4j"] = ["not", "an", "object"]
    results = await make_provider(fake).lookup([LOG4J], now=NOW)
    assert results[LOG4J].state == "not_checked"


@pytest.mark.parametrize("status", [500, 401])
async def test_catalog_http_failure_raises_provider_error(status):
    fake = make_fake()
    fake.catalog_status = status
    with pytest.raises(ProviderError) as exc:
        await make_provider(fake).lookup([LOG4J], now=NOW)
    assert KEY not in str(exc.value)


async def test_catalog_not_json_raises_provider_error():
    def handler(request):
        return httpx.Response(200, text="<html>not json</html>")

    provider = GreyNoiseProvider(api_key=KEY, transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderError):
        await provider.lookup([LOG4J], now=NOW)


async def test_oversize_catalog_raises_provider_error():
    fake = make_fake()
    provider = make_provider(fake, max_catalog_bytes=100)
    with pytest.raises(ProviderError, match="size"):
        await provider.lookup([LOG4J], now=NOW)


async def test_not_configured_lookup_raises_provider_error():
    provider = GreyNoiseProvider(api_key=None)
    assert provider.configured is False
    with pytest.raises(ProviderError, match="GREYNOISE_API_KEY"):
        await provider.lookup([LOG4J], now=NOW)


def test_configured_property_and_blank_key():
    assert GreyNoiseProvider(api_key=KEY).configured is True
    assert GreyNoiseProvider(api_key="  ").configured is False


async def test_redirects_not_followed():
    seen_hosts = []

    def handler(request):
        seen_hosts.append(request.url.host)
        return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

    provider = GreyNoiseProvider(api_key=KEY, transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderError):
        await provider.lookup([LOG4J], now=NOW)
    assert seen_hosts == ["api.greynoise.io"]


def test_http_base_url_refused_and_repr_hides_key():
    with pytest.raises(ProviderUnavailable, match="https"):
        GreyNoiseProvider(api_key=KEY, base_url="http://api.greynoise.io")
    assert KEY not in repr(GreyNoiseProvider(api_key=KEY))


def test_from_env_reads_key_only_from_environment(monkeypatch):
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
    assert GreyNoiseProvider.from_env(settings).configured is False
    monkeypatch.setenv("GREYNOISE_API_KEY", KEY)
    provider = GreyNoiseProvider.from_env(settings)
    assert provider.configured is True and KEY not in repr(provider)


def test_services_wire_greynoise_provider(services):
    assert isinstance(services.greynoise, GreyNoiseProvider)
