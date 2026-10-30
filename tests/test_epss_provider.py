"""Tests for the FIRST EPSS provider (strict parsing, batching, failure modes)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from riskproof.providers.base import ProviderError
from riskproof.providers.epss import EPSSProvider


def _mock(handler) -> httpx.AsyncBaseTransport:
    return httpx.MockTransport(handler)


NOW = datetime.now(UTC)


def test_parse_valid_response():
    payload = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "0.94182",
                "percentile": "0.99875",
                "date": "2026-01-02",
            },
            {"cve": "CVE-2024-6387", "epss": "0.16", "percentile": "0.94", "date": "2026-01-02"},
        ],
    }
    parsed = EPSSProvider.parse(payload, NOW)
    assert set(parsed) == {"CVE-2021-44228", "CVE-2024-6387"}
    assert parsed["CVE-2021-44228"].score == pytest.approx(0.94182)
    assert parsed["CVE-2021-44228"].percentile == pytest.approx(0.99875)
    assert parsed["CVE-2021-44228"].source == "first.org"


def test_parse_rejects_missing_data_array():
    with pytest.raises(ProviderError):
        EPSSProvider.parse({"nope": True}, NOW)


def test_parse_rejects_malformed_record():
    with pytest.raises(ProviderError):
        EPSSProvider.parse({"data": [{"cve": "CVE-2021-44228", "epss": "not-a-float"}]}, NOW)


async def test_fetch_batches_requests():
    seen_batches: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cves = request.url.params["cve"].split(",")
        seen_batches.append(cves)
        return httpx.Response(
            200,
            json={
                "data": [
                    {"cve": c, "epss": "0.5", "percentile": "0.9", "date": "2026-01-02"}
                    for c in cves
                ]
            },
        )

    provider = EPSSProvider(base_url="http://test/epss", transport=_mock(handler))
    cves = [f"CVE-2024-{i:04d}" for i in range(1, 151)]
    results = await provider.fetch(cves)
    assert len(results) == 150
    assert all(len(batch) <= 100 for batch in seen_batches)
    assert sum(len(b) for b in seen_batches) == 150


async def test_fetch_http_error_raises_provider_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    provider = EPSSProvider(base_url="http://test/epss", transport=_mock(handler))
    with pytest.raises(ProviderError):
        await provider.fetch(["CVE-2021-44228"])


async def test_fetch_invalid_json_raises_provider_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    provider = EPSSProvider(base_url="http://test/epss", transport=_mock(handler))
    with pytest.raises(ProviderError):
        await provider.fetch(["CVE-2021-44228"])


async def test_fetch_empty_input_short_circuits():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("network should not be touched")

    provider = EPSSProvider(base_url="http://test/epss", transport=_mock(handler))
    assert await provider.fetch([]) == {}
