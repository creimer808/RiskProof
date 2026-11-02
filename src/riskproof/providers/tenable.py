"""Tenable Vulnerability Management (Tenable.io / Tenable One) API client.

Read-only vulnerability export, per Tenable's documented flow:

1. ``POST /vulns/export``                       -> ``export_uuid``
2. ``GET  /vulns/export/{uuid}/status``         -> poll; ``chunks_available``
3. ``GET  /vulns/export/{uuid}/chunks/{id}``    -> JSON array of vuln records

Design rules:

* Credentials come ONLY from ``TENABLE_ACCESS_KEY`` / ``TENABLE_SECRET_KEY`` in
  the server's environment. They are never accepted from tool input, never
  logged, never written to the audit trail, and never shown in ``repr``.
* The base URL is operator configuration (``RISKPROOF_TENABLE_BASE_URL``) and
  must be https. Redirects are NOT followed, so the API-key header can never be
  forwarded to another host.
* Every response is untrusted: identifiers taken from responses are validated
  before being placed in a URL path, and records are normalized by
  :mod:`riskproof.ingest.tenable`.
* Tenable's official Hexa MCP remains the preferred bridge when the host agent
  offers it (see PLAN.md); this client is the direct-API fallback.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from riskproof.config import Settings
from riskproof.errors import ProviderUnavailable
from riskproof.models.tags import MAX_CATEGORY_CHARS, MAX_VALUE_CHARS, clean_text
from riskproof.providers.base import build_client

ACCESS_KEY_ENV = "TENABLE_ACCESS_KEY"
SECRET_KEY_ENV = "TENABLE_SECRET_KEY"
_TENABLE_ENV_VARS = (ACCESS_KEY_ENV, SECRET_KEY_ENV)

_UUID_RE = re.compile(r"^[0-9A-Za-z-]{8,64}$")
_MAX_RETRIES = 3
_MAX_RETRY_WAIT = 30.0
_TERMINAL_BAD = {"ERROR", "CANCELLED"}


def _env_present(name: str) -> bool:
    value = os.environ.get(name)
    return bool(value and value.strip())


class TenableBridge:
    """Reports integration status; never fabricates Tenable data."""

    name = "tenable"

    def __init__(self, base_url: str = "https://cloud.tenable.com") -> None:
        self._base_url = base_url

    def integration_status(self) -> dict:
        configured = [name for name in _TENABLE_ENV_VARS if _env_present(name)]
        return {
            "live_api_supported": True,
            "base_url": self._base_url,
            "credentials_configured": len(configured) == len(_TENABLE_ENV_VARS),
            "tenable_env_vars_detected": configured,
            "hexa_mcp_preferred": True,
            "ingestion_paths": [".nessus XML", "normalized JSON fixtures", "Tenable VM API export"],
            "note": (
                "Direct Tenable VM export is the fallback; delegate to Tenable's Hexa MCP "
                "when the host agent provides it."
            ),
        }


@dataclass
class TagValues:
    """Tag categories and their values as defined in the tenant."""

    categories: dict[str, list[str]]
    total_values: int
    truncated: bool = False


@dataclass
class ExportResult:
    """Outcome of one vulnerability export."""

    vulns: list[dict[str, Any]]
    export_uuid: str
    chunks_downloaded: int
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)


class TenableClient:
    """Minimal async client for the vulnerability-export endpoints."""

    def __init__(
        self,
        *,
        base_url: str,
        access_key: str,
        secret_key: str,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https" or not parts.hostname:
            raise ProviderUnavailable(
                "RISKPROOF_TENABLE_BASE_URL must be an https URL "
                "(e.g. https://cloud.tenable.com); API keys are never sent over http."
            )
        self._base_url = base_url.rstrip("/")
        self._host = parts.hostname
        self._headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key};"}
        self._timeout = timeout
        self._transport = transport
        self._sleep = sleep

    def __repr__(self) -> str:  # never expose the key header
        return f"TenableClient(host={self._host!r})"

    @classmethod
    def from_env(
        cls, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> TenableClient:
        access = (os.environ.get(ACCESS_KEY_ENV) or "").strip()
        secret = (os.environ.get(SECRET_KEY_ENV) or "").strip()
        if not access or not secret:
            raise ProviderUnavailable(
                f"Tenable API credentials are not configured. A human operator must set "
                f"{ACCESS_KEY_ENV} and {SECRET_KEY_ENV} in the RiskProof server's "
                "environment (e.g. `claude mcp add -e ...`) and restart it. Credentials "
                "cannot be supplied through tool input. Meanwhile, use import_nessus."
            )
        return cls(
            base_url=settings.tenable_base_url,
            access_key=access,
            secret_key=secret,
            timeout=settings.http_timeout_seconds,
            transport=transport,
        )

    async def _request(
        self, client: httpx.AsyncClient, method: str, path: str, json: dict | None = None
    ) -> Any:
        url = f"{self._base_url}{path}"
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = await client.request(method, url, json=json, headers=self._headers)
            except httpx.HTTPError as exc:
                raise ProviderUnavailable(
                    f"Tenable request {method} {path} failed: {type(exc).__name__}"
                ) from exc
            status = response.status_code
            if status == 429 and attempt < _MAX_RETRIES:
                wait = _retry_after(response)
                await self._sleep(wait)
                continue
            if status in (401, 403):
                raise ProviderUnavailable(
                    f"Tenable rejected the API keys (HTTP {status}). Check the key pair and "
                    "that its user has permission to export vulnerabilities."
                )
            if status == 429:
                raise ProviderUnavailable("Tenable rate limit (HTTP 429) persisted after retries.")
            if not 200 <= status < 300:
                raise ProviderUnavailable(f"Tenable {method} {path} returned HTTP {status}.")
            try:
                return response.json()
            except ValueError as exc:
                raise ProviderUnavailable(
                    f"Tenable {method} {path} returned invalid JSON."
                ) from exc
        raise ProviderUnavailable("unreachable")  # pragma: no cover

    async def export_vulns(
        self,
        *,
        filters: dict[str, Any],
        limit: int,
        chunk_size: int = 500,
        timeout_seconds: float = 300.0,
        poll_seconds: float = 3.0,
    ) -> ExportResult:
        """Run a vulnerability export and collect up to ``limit`` records."""
        warnings: list[str] = []
        async with build_client(
            timeout=self._timeout, transport=self._transport, follow_redirects=False
        ) as client:
            started = await self._request(
                client,
                "POST",
                "/vulns/export",
                json={"num_assets": chunk_size, "filters": filters},
            )
            export_uuid = started.get("export_uuid") if isinstance(started, dict) else None
            if not isinstance(export_uuid, str) or not _UUID_RE.match(export_uuid):
                raise ProviderUnavailable("Tenable did not return a valid export_uuid.")

            vulns: list[dict[str, Any]] = []
            downloaded: set[int] = set()
            truncated = False
            deadline = time.monotonic() + timeout_seconds
            try:
                while True:
                    status = await self._request(
                        client, "GET", f"/vulns/export/{export_uuid}/status"
                    )
                    if not isinstance(status, dict):
                        raise ProviderUnavailable("Tenable export status was not an object.")
                    state = str(status.get("status", "")).upper()
                    if state in _TERMINAL_BAD:
                        raise ProviderUnavailable(f"Tenable export ended with status {state}.")
                    available = [
                        c for c in (status.get("chunks_available") or []) if isinstance(c, int)
                    ]
                    for chunk_id in sorted(available):
                        if chunk_id in downloaded:
                            continue
                        chunk = await self._request(
                            client, "GET", f"/vulns/export/{export_uuid}/chunks/{chunk_id}"
                        )
                        downloaded.add(chunk_id)
                        if not isinstance(chunk, list):
                            raise ProviderUnavailable(f"Tenable chunk {chunk_id} was not a list.")
                        vulns.extend(item for item in chunk if isinstance(item, dict))
                        if len(vulns) >= limit:
                            truncated = (
                                len(vulns) > limit
                                or state != "FINISHED"
                                or not set(available) <= downloaded
                            )
                            vulns = vulns[:limit]
                            raise _LimitReached
                    if state == "FINISHED" and downloaded >= set(available):
                        failed = status.get("chunks_failed") or []
                        if failed:
                            warnings.append(
                                f"{len(failed)} export chunk(s) failed on Tenable's side."
                            )
                        break
                    if time.monotonic() > deadline:
                        raise ProviderUnavailable(
                            f"Tenable export did not finish within {timeout_seconds:.0f}s; "
                            "narrow the filters (severity, since_days, cidr_range) and retry."
                        )
                    await self._sleep(poll_seconds)
            except _LimitReached:
                await self._cancel(client, export_uuid)
            except ProviderUnavailable:
                await self._cancel(client, export_uuid)
                raise
            return ExportResult(
                vulns=vulns,
                export_uuid=export_uuid,
                chunks_downloaded=len(downloaded),
                truncated=truncated,
                warnings=warnings,
            )

    async def list_tag_values(self, *, page_size: int = 1000, max_values: int = 5000) -> TagValues:
        """List the tenant's tag categories and values (``GET /tags/values``).

        Read-only. Used to resolve a human phrase like "the DMZ" to the exact
        category and value an export filter needs.
        """
        categories: dict[str, list[str]] = {}
        seen = 0
        offset = 0
        truncated = False
        async with build_client(
            timeout=self._timeout, transport=self._transport, follow_redirects=False
        ) as client:
            while True:
                data = await self._request(
                    client, "GET", f"/tags/values?limit={page_size}&offset={offset}"
                )
                page = data.get("values") if isinstance(data, dict) else None
                if not isinstance(page, list):
                    raise ProviderUnavailable("Tenable tag listing was not in the expected shape.")
                for entry in page:
                    category = (
                        clean_text(entry.get("category_name"), MAX_CATEGORY_CHARS)
                        if isinstance(entry, dict)
                        else None
                    )
                    if category is None:
                        continue
                    values = categories.setdefault(category, [])
                    value = clean_text(entry.get("value"), MAX_VALUE_CHARS)
                    if value is None:
                        continue
                    if seen >= max_values:
                        truncated = True
                        break
                    values.append(value)
                    seen += 1
                if truncated or len(page) < page_size:
                    break
                offset += page_size
        return TagValues(categories=categories, total_values=seen, truncated=truncated)

    async def _cancel(self, client: httpx.AsyncClient, export_uuid: str) -> None:
        """Best-effort: stop Tenable generating chunks we will not download."""
        with contextlib.suppress(httpx.HTTPError):
            await client.post(
                f"{self._base_url}/vulns/export/{export_uuid}/cancel", headers=self._headers
            )


class _LimitReached(Exception):
    """Internal control flow: the caller's record limit was met."""


def _retry_after(response: httpx.Response) -> float:
    try:
        return min(max(float(response.headers.get("Retry-After", "2")), 0.0), _MAX_RETRY_WAIT)
    except ValueError:
        return 2.0
