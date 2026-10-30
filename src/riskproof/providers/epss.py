"""FIRST EPSS provider (https://api.first.org/data/v1/epss).

EPSS returns a *statistical* probability that a CVE is exploited in the wild
within the next 30 days. It is a property of the CVE, not of any specific
system. RiskProof never phrases EPSS as "this machine is exploitable".
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import httpx

from riskproof.models.intel import EPSSObservation
from riskproof.providers.base import ProviderError, build_client, fetch_json

BATCH_SIZE = 100  # FIRST API allows up to 100 CVEs per query


class EPSSProvider:
    """Client for the FIRST EPSS API. Transport is injectable for tests."""

    name = "first-epss"

    def __init__(
        self,
        base_url: str = "https://api.first.org/data/v1/epss",
        timeout: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url
        self._timeout = timeout
        self._transport = transport

    async def fetch(self, cves: Sequence[str]) -> dict[str, EPSSObservation]:
        """Fetch EPSS observations. Raises ProviderError on any failure."""
        if not cves:
            return {}
        results: dict[str, EPSSObservation] = {}
        unique = list(dict.fromkeys(cves))
        now = datetime.now(UTC)
        for offset in range(0, len(unique), BATCH_SIZE):
            batch = unique[offset : offset + BATCH_SIZE]
            results.update(await self._fetch_batch(batch, now))
        return results

    async def _fetch_batch(self, batch: list[str], now: datetime) -> dict[str, EPSSObservation]:
        async with build_client(self._base_url, self._timeout, self._transport) as client:
            payload = await fetch_json(client, "", params={"cve": ",".join(batch)})
        return self.parse(payload, now)

    @staticmethod
    def parse(payload: Any, now: datetime) -> dict[str, EPSSObservation]:
        """Strictly parse an EPSS API response into observations."""
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ProviderError("EPSS response missing 'data' array")
        parsed: dict[str, EPSSObservation] = {}
        for item in payload["data"]:
            try:
                observation = EPSSObservation(
                    cve=str(item["cve"]),
                    score=float(item["epss"]),
                    percentile=float(item["percentile"]) if item.get("percentile") else None,
                    date=str(item.get("date")) if item.get("date") else None,
                    collected_at=now,
                    source="first.org",
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ProviderError(f"Malformed EPSS record {item!r}: {exc}") from exc
            parsed[observation.cve] = observation
        return parsed
