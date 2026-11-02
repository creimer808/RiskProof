"""Fixture-backed intel source for offline use.

All fixture data is clearly labeled SAMPLE data. In particular, KEV fixture
data covers only the sample CVEs: absence from the sample catalog is NOT
evidence that a CVE is absent from the real CISA KEV catalog. This honesty
requirement is enforced by ``KEVStatus.catalog == "sample"``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from riskproof.models.intel import EPSSObservation, GreyNoiseResult, KEVCatalog, KEVStatus
from riskproof.providers.base import ProviderError
from riskproof.providers.epss import EPSSProvider
from riskproof.providers.greynoise_parse import evaluate_cve, parse_activity, parse_tag_catalog
from riskproof.providers.kev import KEVProvider

EPSS_FIXTURE = "epss_sample.json"
KEV_FIXTURE = "kev_sample.json"
GREYNOISE_FIXTURE = "greynoise_sample.json"
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

    async def greynoise_for(
        self, cves: Sequence[str], now: datetime | None = None, window_days: int = 3
    ) -> dict[str, GreyNoiseResult]:
        """SAMPLE GreyNoise readings, parsed with the same code as live payloads.

        Fixture activity is stored as ``days_ago`` so it never ages out of the window.
        """
        payload = self._load(GREYNOISE_FIXTURE)
        today = (now or datetime.now(UTC)).astimezone(UTC).date()
        tag_map = parse_tag_catalog(payload)
        activity: dict[str, dict[str, dict[str, int]]] = {}
        raw_activity = payload.get("activity")
        for tag_id, buckets in (raw_activity if isinstance(raw_activity, dict) else {}).items():
            grouped: dict[str, list[dict[str, Any]]] = {}
            for bucket in buckets if isinstance(buckets, list) else []:
                day = today - timedelta(days=int(bucket.get("days_ago", 0)))
                grouped.setdefault(str(bucket.get("intention")), []).append(
                    {
                        "timestamp": f"{day.isoformat()}T00:00:00Z",
                        "active_ips": bucket.get("active_ips"),
                    }
                )
            activity[tag_id] = parse_activity({"activity": grouped})
        return {
            cve: evaluate_cve(
                cve, tag_map.get(cve, []), activity, today=today, window_days=window_days
            )
            for cve in dict.fromkeys(cves)
        }
