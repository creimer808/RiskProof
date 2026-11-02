"""GreyNoise exploitation signal (optional, free-tier friendly, call-budgeted).

GreyNoise tags describe scanning and exploitation attempts seen by GreyNoise's own
sensors. One request returns the whole tag catalog, which is cached and inverted
locally into CVE -> tags; per-tag daily activity is then fetched only for CVEs
under investigation, cached, and capped per run. Only tag ids are ever sent.

The API key is read from the server environment only and never appears in
reprs, errors, results, or the audit log. Redirects are not followed.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from riskproof.errors import ProviderUnavailable
from riskproof.models.intel import GreyNoiseResult, GreyNoiseTag
from riskproof.providers.base import ProviderError, build_client
from riskproof.providers.greynoise_parse import (
    evaluate_cve,
    parse_activity,
    parse_tag_catalog,
)
from riskproof.storage.repositories import IntelCacheRepository

if TYPE_CHECKING:
    from riskproof.config import Settings

API_KEY_ENV = "GREYNOISE_API_KEY"
TAGMAP_CACHE_KEY = "greynoise:tagmap"
TAGMAP_TTL = timedelta(hours=24)
ACTIVITY_TTL = timedelta(hours=8)
MAX_CATALOG_BYTES = 32 * 1024 * 1024
MAX_ACTIVITY_BYTES = 2 * 1024 * 1024


class _RunStopped(Exception):
    """A response means no further requests should be made this run."""


class GreyNoiseProvider:
    name = "greynoise"

    def __init__(
        self,
        api_key: str | None,
        base_url: str = "https://api.greynoise.io",
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        cache: IntelCacheRepository | None = None,
        window_days: int = 3,
        max_calls: int = 100,
        max_catalog_bytes: int = MAX_CATALOG_BYTES,
    ) -> None:
        self._api_key = (api_key or "").strip() or None
        if self._api_key:
            parts = urlsplit(base_url)
            if parts.scheme != "https" or not parts.hostname:
                raise ProviderUnavailable(
                    "RISKPROOF_GREYNOISE_BASE_URL must be an https URL "
                    "(e.g. https://api.greynoise.io); the API key is never sent over http."
                )
        self._base_url = base_url.rstrip("/")
        self._host = urlsplit(base_url).hostname
        self._timeout = timeout
        self._transport = transport
        self._cache = cache
        self._window_days = window_days
        self._max_calls = max_calls
        self._max_catalog_bytes = max_catalog_bytes

    def __repr__(self) -> str:  # never expose the key
        return f"GreyNoiseProvider(host={self._host!r}, configured={self.configured})"

    @classmethod
    def from_env(
        cls, settings: Settings, cache: IntelCacheRepository | None = None
    ) -> GreyNoiseProvider:
        return cls(
            api_key=os.environ.get(API_KEY_ENV),
            base_url=settings.greynoise_base_url,
            timeout=max(settings.http_timeout_seconds, 30.0),
            cache=cache,
            window_days=settings.greynoise_window_days,
            max_calls=settings.greynoise_max_calls_per_run,
        )

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    async def lookup(
        self, cves: Sequence[str], now: datetime | None = None
    ) -> dict[str, GreyNoiseResult]:
        """One result per CVE, processed in the given order.

        Raises ``ProviderError`` only when the tag catalog cannot be obtained.
        Activity failures, rate limits, and the call budget produce
        ``not_checked`` results instead, so earlier results are never lost.
        """
        if not self.configured:
            raise ProviderError(
                f"GreyNoise is not configured: set {API_KEY_ENV} in the server environment."
            )
        now = (now or datetime.now(UTC)).astimezone(UTC)
        today = now.date()
        results: dict[str, GreyNoiseResult] = {}
        activity: dict[str, dict[str, dict[str, int]]] = {}
        calls = 0
        stop_reason: str | None = None
        async with build_client(
            None, self._timeout, self._transport, follow_redirects=False
        ) as client:
            tag_map = await self._tag_map(client, now)
            for cve in dict.fromkeys(cves):
                tags = tag_map.get(cve, [])
                missing = [
                    t for t in tags if t.id not in activity and not self._load(t.id, now, activity)
                ]
                if missing and stop_reason is not None:
                    results[cve] = _not_checked(cve, stop_reason)
                    continue
                if len(missing) > self._max_calls - calls:
                    results[cve] = _not_checked(
                        cve, "GreyNoise call budget for this run is spent; not checked."
                    )
                    continue
                try:
                    for tag in missing:
                        calls += 1
                        payload = await self._get(
                            client, f"/v3/tags/{tag.id}/activity", MAX_ACTIVITY_BYTES
                        )
                        activity[tag.id] = parse_activity(payload)
                        self._store(tag.id, activity[tag.id], now)
                except _RunStopped as stop:
                    stop_reason = str(stop)
                    results[cve] = _not_checked(cve, stop_reason)
                    continue
                except ProviderError as exc:
                    results[cve] = _not_checked(cve, f"GreyNoise activity lookup failed: {exc}")
                    continue
                results[cve] = evaluate_cve(
                    cve, tags, activity, today=today, window_days=self._window_days
                )
        return results

    # -- caching ---------------------------------------------------------------

    def _load(self, tag_id: str, now: datetime, into: dict[str, dict[str, dict[str, int]]]) -> bool:
        """Fill ``into`` from the cache; True when the tag's activity was cached."""
        if self._cache is None:
            return False
        cached = self._cache.get_fresh(f"greynoise:activity:{tag_id}", now)
        if cached is None:
            return False
        payload, _ = cached
        data = payload.get("activity")
        if not isinstance(data, dict):
            return False
        into[tag_id] = data
        return True

    def _store(self, tag_id: str, data: dict[str, dict[str, int]], now: datetime) -> None:
        if self._cache is not None:
            self._cache.put(
                f"greynoise:activity:{tag_id}",
                "greynoise",
                {"activity": data},
                fetched_at=now,
                expires_at=now + ACTIVITY_TTL,
            )

    async def _tag_map(
        self, client: httpx.AsyncClient, now: datetime
    ) -> dict[str, list[GreyNoiseTag]]:
        if self._cache is not None:
            cached = self._cache.get_fresh(TAGMAP_CACHE_KEY, now)
            if cached is not None:
                try:
                    raw = cached[0]["tags_by_cve"]
                    return {
                        c: [GreyNoiseTag.model_validate(t) for t in ts] for c, ts in raw.items()
                    }
                except (KeyError, TypeError, AttributeError, ValidationError):
                    pass  # unreadable cache entry: download again
        try:
            payload = await self._get(client, "/v3/tags", self._max_catalog_bytes)
        except _RunStopped as stop:
            raise ProviderError(str(stop)) from None
        tag_map = parse_tag_catalog(payload)
        if self._cache is not None:
            self._cache.put(
                TAGMAP_CACHE_KEY,
                "greynoise",
                {"tags_by_cve": {c: [t.model_dump() for t in ts] for c, ts in tag_map.items()}},
                fetched_at=now,
                expires_at=now + TAGMAP_TTL,
            )
        return tag_map

    # -- HTTP --------------------------------------------------------------------

    async def _get(self, client: httpx.AsyncClient, path: str, max_bytes: int) -> Any:
        assert self._api_key is not None
        try:
            async with client.stream(
                "GET", f"{self._base_url}{path}", headers={"key": self._api_key}
            ) as response:
                status = response.status_code
                if status == 429:
                    raise _RunStopped("GreyNoise rate limit (HTTP 429); remaining lookups skipped.")
                if status in (401, 403):
                    raise _RunStopped(
                        f"GreyNoise rejected the API key (HTTP {status}); "
                        "remaining lookups skipped."
                    )
                if status != 200:
                    raise ProviderError(f"GreyNoise returned HTTP {status}")
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise ProviderError(
                        f"GreyNoise response exceeds the size limit ({max_bytes} bytes)"
                    )
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise ProviderError(
                            f"GreyNoise response exceeds the size limit ({max_bytes} bytes)"
                        )
        except httpx.HTTPError as exc:
            raise ProviderError(f"GreyNoise request failed: {type(exc).__name__}") from exc
        try:
            return json.loads(bytes(body))
        except ValueError as exc:
            raise ProviderError("GreyNoise response is not valid JSON") from exc


def _not_checked(cve: str, reason: str) -> GreyNoiseResult:
    return GreyNoiseResult(cve=cve, state="not_checked", reason=reason)
