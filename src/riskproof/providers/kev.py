"""CISA Known Exploited Vulnerabilities (KEV) feed provider.

The full catalog is downloaded, validated, and cached in SQLite with a TTL so
repeated checks do not hammer CISA's CDN. Only CVEs present in the *live*
catalog may be reported as KEV-listed.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from riskproof.models.intel import KEVCatalog, KEVEntry, KEVStatus
from riskproof.providers.base import ProviderError, build_client, fetch_json
from riskproof.storage.repositories import IntelCacheRepository

CACHE_KEY = "kev:catalog"


class KEVProvider:
    """Client for the CISA KEV feed, with SQLite-backed TTL caching."""

    name = "cisa-kev"

    def __init__(
        self,
        feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
        cache: IntelCacheRepository | None = None,
        max_age_hours: float = 24.0,
    ) -> None:
        self._feed_url = feed_url
        self._timeout = timeout
        self._transport = transport
        self._cache = cache
        self._max_age = timedelta(hours=max_age_hours)

    async def load_catalog(self, force_refresh: bool = False) -> KEVCatalog:
        """Load the catalog from cache when fresh, otherwise from CISA."""
        now = datetime.now(UTC)
        if not force_refresh and self._cache is not None:
            cached = self._cache.get_fresh(CACHE_KEY, now)
            if cached is not None:
                payload, _expires = cached
                return self.parse(payload, catalog="cisa-live")
        payload = await self._download()
        if self._cache is not None:
            self._cache.put(
                CACHE_KEY,
                "kev",
                payload,
                fetched_at=now,
                expires_at=now + self._max_age,
            )
        return self.parse(payload, catalog="cisa-live")

    async def _download(self) -> dict[str, Any]:
        async with build_client(None, self._timeout, self._transport) as client:
            return await fetch_json(client, self._feed_url)

    @staticmethod
    def parse(payload: Any, catalog: str = "cisa-live") -> KEVCatalog:
        """Parse and validate a KEV feed document."""
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise ProviderError("KEV feed missing 'vulnerabilities' array")
        entries: dict[str, KEVEntry] = {}
        for item in payload["vulnerabilities"]:
            try:
                entry = KEVEntry(
                    cve=str(item["cveID"]),
                    vendor_project=item.get("vendorProject"),
                    product=item.get("product"),
                    vulnerability_name=item.get("vulnerabilityName"),
                    date_added=item.get("dateAdded"),
                    due_date=item.get("dueDate"),
                    required_action=item.get("requiredAction"),
                    known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse"),
                    notes=item.get("notes"),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ProviderError(f"Malformed KEV entry {item!r}: {exc}") from exc
            entries[entry.cve] = entry
        return KEVCatalog(
            entries=entries,
            catalog_version=payload.get("catalogVersion"),
            date_released=payload.get("dateReleased"),
            catalog=catalog,  # type: ignore[arg-type]
            fetched_at=datetime.now(UTC),
        )

    async def status_for(self, cves: Sequence[str], force_refresh: bool = False) -> list[KEVStatus]:
        """KEV status for each requested CVE (absence means not in this catalog)."""
        catalog = await self.load_catalog(force_refresh=force_refresh)
        now = datetime.now(UTC)
        return [
            KEVStatus(
                cve=cve,
                in_kev=cve in catalog.entries,
                catalog=catalog.catalog,
                entry=catalog.entries.get(cve),
                checked_at=now,
            )
            for cve in dict.fromkeys(cves)
        ]
