"""RiskProof MCP server (stdio transport)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from riskproof.config import Settings
from riskproof.services import Services, build_services
from riskproof.tools import register_tools

SERVER_INSTRUCTIONS = """\
RiskProof investigates vulnerability findings with evidence discipline:
- Distinguish confirmed evidence, inference, missing information, and failed verification.
- EPSS is a statistical 30-day in-the-wild exploitation probability for a CVE —
  never a claim that a specific system is exploitable.
- Validation checks are non-destructive and only run against allowlisted targets;
  targets cannot be authorized from tool input — direct the human operator to
  RISKPROOF_ALLOWED_TARGETS.
- import_nessus reads only files in the operator-configured import directory;
  import_tenable uses credentials from the server environment. Neither accepts
  paths, URLs, or credentials from tool input. Imports store findings without
  enriching them: follow with investigate_finding(finding_ids=[...]).
- Remediation actions are dry-run and approval-gated by default.
- When intel is degraded or fixture-backed (SAMPLE data), surface that to the user.
"""


def create_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server with all tools registered."""
    settings = settings or Settings()
    services: Services = build_services(settings)
    mcp: FastMCP = FastMCP(
        name="riskproof",
        instructions=SERVER_INSTRUCTIONS,
    )
    register_tools(mcp, services)
    return mcp


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    create_server().run(transport="stdio")
