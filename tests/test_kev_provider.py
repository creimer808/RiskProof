"""Tests for the CISA KEV provider (parsing, caching, status checks)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from riskproof.providers.base import ProviderError
from riskproof.providers.kev import KEVProvider
from riskproof.storage.db import Database
from riskproof.storage.repositories import IntelCacheRepository

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "kev_sample.json"


def _feed_payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_parse_valid_catalog():
    catalog = KEVProvider.parse(_feed_payload())
    assert catalog.catalog == "cisa-live"
    assert "CVE-2021-44228" in catalog.entries
    entry = catalog.entries["CVE-2021-44228"]
    assert entry.known_ransomware_campaign_use == "Known"
    assert entry.date_added == "2021-12-10"


def test_parse_rejects_missing_vulnerabilities():
    with pytest.raises(ProviderError):
        KEVProvider.parse({"count": 0})


def test_parse_rejects_malformed_entry():
    with pytest.raises(ProviderError):
        KEVProvider.parse({"vulnerabilities": [{"vendorProject": "no cve id"}]})


async def test_status_for_marks_kev_and_non_kev():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed_payload())

    provider = KEVProvider(transport=httpx.MockTransport(handler))
    statuses = {s.cve: s for s in await provider.status_for(["CVE-2021-44228", "CVE-2023-48795"])}
    assert statuses["CVE-2021-44228"].in_kev is True
    assert statuses["CVE-2021-44228"].catalog == "cisa-live"
    # Not in THIS catalog -> honest negative from the live feed.
    assert statuses["CVE-2023-48795"].in_kev is False
    assert statuses["CVE-2023-48795"].catalog == "cisa-live"


async def test_catalog_cached_in_sqlite_second_call_hits_no_network(tmp_path):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_feed_payload())

    db = Database(tmp_path / "kev.db")
    cache = IntelCacheRepository(db)
    provider = KEVProvider(transport=httpx.MockTransport(handler), cache=cache)

    await provider.status_for(["CVE-2021-44228"])
    await provider.status_for(["CVE-2021-44228"])
    assert calls["n"] == 1  # second call served from cache
    db.close()


async def test_force_refresh_bypasses_cache(tmp_path):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_feed_payload())

    db = Database(tmp_path / "kev.db")
    cache = IntelCacheRepository(db)
    provider = KEVProvider(transport=httpx.MockTransport(handler), cache=cache)
    await provider.load_catalog()
    await provider.load_catalog(force_refresh=True)
    assert calls["n"] == 2
    db.close()
