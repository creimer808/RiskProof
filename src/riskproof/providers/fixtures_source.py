"""Fixture-backed intel source for offline use.

All fixture data is clearly labeled SAMPLE data. In particular, KEV fixture
data covers only the sample CVEs: absence from the sample catalog is NOT
evidence that a CVE is absent from the real CISA KEV catalog. This honesty
requirement is enforced by ``KEVStatus.catalog == "sample"``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from riskproof.models.intel import EPSSObservation, KEVCatalog, KEVStatus
from riskproof.providers.base import ProviderError
from riskproof.providers.epss import EPSSProvider
from riskproof.providers.kev import KEVProvider

EPSS_FIXTURE = "epss_sample.json"
KEV_FIXTURE = "kev_sample.json"
SAMPLE_NOTICE = "SAMPLE fixture data for offline demonstration — not live threat intelligence."


class FixtureIntelSource:
    """Same interface as the live providers, backed by bundled sample files."""

    name = "fixtures"

    def __init__(self, fixtures_dir: Path) -> None:
        self._dir = fixtures_dir

    def _load(self, filename: str) -> dict[str, Any]:
        path = self._dir / filename
        if not path.is_file():
            raise ProviderError(
                f"Fixture file not found: {path}. Fixtures are bundled with the "
                "repository; set RISKPROOF_FIXTURES_DIR if you moved them."
            )
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Cannot read fixture {path}: {exc}") from exc

    async def fetch_epss(self, cves: Sequence[str]) -> dict[str, EPSSObservation]:
        """Parse the sample EPSS file in the same shape as the live API."""
        payload = self._load(EPSS_FIXTURE)
        now = datetime.now(UTC)
        parsed = EPSSProvider.parse(payload, now)  # reuse strict parsing
        wanted = set(cves)
        return {
            cve: obs.model_copy(update={"source": "sample-fixture"})
            for cve, obs in parsed.items()
            if cve in wanted
        }

    async def load_kev_catalog(self) -> KEVCatalog:
        payload = self._load(KEV_FIXTURE)
        return KEVProvider.parse(payload, catalog="sample")

    async def kev_status_for(self, cves: Sequence[str]) -> list[KEVStatus]:
        catalog = await self.load_kev_catalog()
        now = datetime.now(UTC)
        return [
            KEVStatus(
                cve=cve,
                in_kev=cve in catalog.entries,
                catalog="sample",
                entry=catalog.entries.get(cve),
                checked_at=now,
            )
            for cve in dict.fromkeys(cves)
        ]
