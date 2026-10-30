"""Tests for the fixture-backed intel source and its honesty labels."""

from __future__ import annotations

from pathlib import Path

import pytest

from riskproof.providers.base import ProviderError
from riskproof.providers.fixtures_source import FixtureIntelSource

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


async def test_epss_fixture_marks_sample_source():
    source = FixtureIntelSource(FIXTURES)
    result = await source.fetch_epss(["CVE-2021-44228", "CVE-9999-0001"])
    obs = result["CVE-2021-44228"]
    assert obs.source == "sample-fixture"
    assert 0.0 <= obs.score <= 1.0
    assert "CVE-9999-0001" not in result  # unknown CVEs are simply absent


async def test_kev_fixture_uses_sample_catalog_semantics():
    source = FixtureIntelSource(FIXTURES)
    statuses = {
        s.cve: s
        for s in await source.kev_status_for(["CVE-2021-44228", "CVE-2023-48795", "CVE-9999-0001"])
    }
    assert statuses["CVE-2021-44228"].in_kev is True
    assert statuses["CVE-2021-44228"].catalog == "sample"
    # Absence from the SAMPLE catalog must NOT be reported as live "not in KEV".
    assert statuses["CVE-2023-48795"].catalog == "sample"
    assert statuses["CVE-2023-48795"].in_kev is False
    assert statuses["CVE-9999-0001"].catalog == "sample"


async def test_missing_fixture_dir_raises_provider_error(tmp_path: Path):
    source = FixtureIntelSource(tmp_path / "nowhere")
    with pytest.raises(ProviderError):
        await source.fetch_epss(["CVE-2021-44228"])
