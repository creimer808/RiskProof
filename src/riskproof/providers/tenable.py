"""Tenable integration bridge.

Milestone 0 (this scaffold) ingests Tenable/Nessus data through two supported
paths:

1. ``.nessus`` XML files (see :mod:`riskproof.ingest.nessus`)
2. normalized JSON fixtures (see :mod:`riskproof.ingest.fixtures`)

Live Tenable One API access is deliberately NOT implemented here. When
Tenable's official Hexa MCP server is available in the host agent, RiskProof
should delegate Tenable queries to it rather than duplicating that
functionality (see PLAN.md). This module exists so that decision is visible in
the code and so credential presence can be reported *without ever reading the
secret values*.
"""

from __future__ import annotations

from riskproof.errors import ProviderUnavailable

_TENABLE_ENV_VARS = ("TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY")


class TenableBridge:
    """Reports integration status; never fabricates Tenable data."""

    name = "tenable"

    def integration_status(self) -> dict:
        configured = [name for name in _TENABLE_ENV_VARS if _env_present(name)]
        return {
            "live_api_supported": False,
            "hexa_mcp_preferred": True,
            "ingestion_paths": [".nessus XML", "normalized JSON fixtures"],
            "tenable_env_vars_detected": configured,
            "note": (
                "Live Tenable One API access is planned for P1 and should bridge to "
                "Tenable's Hexa MCP when available. Use .nessus import meanwhile."
            ),
        }

    def require_live_api(self) -> None:
        """Explicit refusal until P1 — keeps tools honest."""
        raise ProviderUnavailable(
            "Live Tenable One API access is not implemented in milestone 0. "
            "Ingest .nessus files or fixtures instead; see PLAN.md for the "
            "Hexa MCP bridge plan."
        )


def _env_present(name: str) -> bool:
    import os

    value = os.environ.get(name)
    return bool(value and value.strip())
