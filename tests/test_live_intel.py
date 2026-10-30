"""Live integration tests against real FIRST EPSS and CISA KEV feeds.

Opt-in: these hit the network, so they only run when RISKPROOF_LIVE_TESTS=1.
    RISKPROOF_LIVE_TESTS=1 uv run pytest tests/test_live_intel.py -v
"""

from __future__ import annotations

import os

import pytest

from riskproof.providers.epss import EPSSProvider
from riskproof.providers.kev import KEVProvider

pytestmark = pytest.mark.skipif(
    os.environ.get("RISKPROOF_LIVE_TESTS") != "1",
    reason="set RISKPROOF_LIVE_TESTS=1 to run live network tests",
)


async def test_live_epss_returns_real_score():
    provider = EPSSProvider()
    results = await provider.fetch(["CVE-2021-44228"])
    assert "CVE-2021-44228" in results
    score = results["CVE-2021-44228"].score
    assert 0.0 <= score <= 1.0
    assert results["CVE-2021-44228"].source == "first.org"


async def test_live_kev_contains_log4shell():
    provider = KEVProvider()
    statuses = {s.cve: s for s in await provider.status_for(["CVE-2021-44228"])}
    assert statuses["CVE-2021-44228"].in_kev is True
    assert statuses["CVE-2021-44228"].catalog == "cisa-live"
    assert statuses["CVE-2021-44228"].entry is not None
