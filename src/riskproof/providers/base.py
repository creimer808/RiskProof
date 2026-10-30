"""Shared provider plumbing: HTTP client factory and typed errors.

All external responses are treated as untrusted data: fetched with strict
timeouts, validated with Pydantic, and never trusted for control flow beyond
the documented schemas.
"""

from __future__ import annotations

from typing import Any

import httpx

from riskproof import __version__
from riskproof.errors import ProviderUnavailable

USER_AGENT = f"RiskProof/{__version__} (vulnerability-investigation)"


class ProviderError(RuntimeError):
    """An external provider failed (network, HTTP status, or bad payload)."""


def build_client(
    base_url: str | None = None,
    timeout: float = 15.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """Create an httpx client. ``transport`` is injectable for tests."""
    kwargs: dict = {
        "timeout": httpx.Timeout(timeout),
        "transport": transport,
        "headers": {"User-Agent": USER_AGENT, "Accept": "application/json"},
        "follow_redirects": True,
    }
    if base_url:
        kwargs["base_url"] = base_url
    return httpx.AsyncClient(**kwargs)


async def fetch_json(client: httpx.AsyncClient, url: str, params: dict | None = None) -> Any:
    """GET a URL and return parsed JSON, raising ProviderError on failure."""
    try:
        response = await client.get(url, params=params)
    except httpx.HTTPError as exc:
        raise ProviderError(f"Request to {url} failed: {exc}") from exc
    if response.status_code != 200:
        raise ProviderError(f"Request to {url} returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise ProviderError(f"Response from {url} is not valid JSON") from exc


def provider_unavailable(name: str, reason: str) -> ProviderUnavailable:
    return ProviderUnavailable(f"{name} unavailable: {reason}")
