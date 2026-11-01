"""End-to-end test: RiskProof MCP server over stdio with the official client.

This is the milestone-0 acceptance test: connect an MCP client, list tools,
submit a CVE, and get structured EPSS/KEV intel back (fixture-backed so it runs
offline in CI; live feeds are exercised by test_live_intel.py).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_TOOLS = {
    "investigate_finding",
    "enrich_threat_intel",
    "verify_applicability",
    "validate_exposure",
    "analyze_exploit_scenario",
    "simulate_remediation",
    "execute_risk_policy",
    "import_nessus",
    "import_tenable",
}


def _server_params(tmp_path: Path) -> StdioServerParameters:
    env = dict(os.environ)
    env.update(
        {
            "RISKPROOF_OFFLINE": "true",
            "RISKPROOF_DB_PATH": str(tmp_path / "stdio-test.db"),
            "RISKPROOF_FIXTURES_DIR": str(REPO_ROOT / "fixtures"),
            "RISKPROOF_IMPORT_DIR": str(REPO_ROOT / "fixtures"),
            "RISKPROOF_ASSET_INVENTORY": str(tmp_path / "assets.json"),  # absent
            "TENABLE_ACCESS_KEY": "",
            "TENABLE_SECRET_KEY": "",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "riskproof", "serve"],
        env=env,
        cwd=str(REPO_ROOT),
    )


def _payload(result) -> dict:
    """Extract the JSON payload from a CallToolResult or its TextContent."""
    obj = result.content[0] if hasattr(result, "content") else result
    return json.loads(obj.text)


async def test_stdio_server_full_workflow(tmp_path: Path):
    with anyio.fail_after(90):
        async with (
            stdio_client(_server_params(tmp_path)) as (read, write),
            ClientSession(read, write) as session,
        ):
            init = await session.initialize()
            assert init.serverInfo.name == "riskproof"

            tools = await session.list_tools()
            assert {t.name for t in tools.tools} >= EXPECTED_TOOLS

            # 1. Enrich a CVE with (fixture) intelligence.
            result = _payload(
                (
                    await session.call_tool(
                        "enrich_threat_intel",
                        {"cve_ids": ["CVE-2021-44228"], "source": "fixture"},
                    )
                ).content[0]
            )
            assert result["ok"] is True
            intel = result["intel"]
            assert intel["epss"]["CVE-2021-44228"]["kind"] == "observation"
            assert intel["epss"]["CVE-2021-44228"]["source"] == "sample-fixture"
            kev = next(s for s in intel["kev_status"] if s["cve"] == "CVE-2021-44228")
            assert kev["in_kev"] is True
            assert kev["catalog"] == "sample"

            # 2. Full investigation over the demo fixture dataset.
            result = _payload(
                (
                    await session.call_tool(
                        "investigate_finding",
                        {"fixture": "findings_sample.json"},
                    )
                ).content[0]
            )
            assert result["ok"] is True
            assert result["count"] >= 5
            first = result["investigations"][0]
            assert first["record"]["evidence"]
            assert first["assessment"]["recommended_priority"] in ("P1", "P2", "P3", "P4")

            # 3. Scenario + remediation + policy on the Log4Shell finding.
            log4shell = next(
                inv["finding_id"]
                for inv in result["investigations"]
                if inv["finding_id"].endswith("155999-8080tcp")
            )
            scenario = _payload(
                (
                    await session.call_tool("analyze_exploit_scenario", {"finding_id": log4shell})
                ).content[0]
            )
            assert scenario["ok"] is True
            assert scenario["scenario"]["exploit_prerequisites"]

            simulation = _payload(
                (
                    await session.call_tool("simulate_remediation", {"finding_id": log4shell})
                ).content[0]
            )
            assert simulation["ok"] is True
            assert simulation["simulation"]["recommended_option_id"]

            policy = _payload(
                (
                    await session.call_tool("execute_risk_policy", {"finding_ids": [log4shell]})
                ).content[0]
            )
            assert policy["ok"] is True
            assert policy["dry_run"] is True
            decision = policy["decisions"][0]
            assert decision["priority"] == "P1"
            assert decision["approved_actions"] == []  # approval required

            # 4. validate_exposure must refuse a non-allowlisted target.
            denied = _payload(
                (
                    await session.call_tool(
                        "validate_exposure",
                        {"host": "203.0.113.9", "port": 443, "method": "tcp_connect"},
                    )
                ).content[0]
            )
            assert denied["ok"] is False
            assert denied["error"]["code"] == "authorization_denied"
            assert "RISKPROOF_ALLOWED_TARGETS" in denied["error"]["message"]


async def test_stdio_invalid_fixture_name_returns_structured_error(tmp_path: Path):
    with anyio.fail_after(60):
        async with (
            stdio_client(_server_params(tmp_path)) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = _payload(
                (
                    await session.call_tool("investigate_finding", {"fixture": "../etc/passwd"})
                ).content[0]
            )
            assert result["ok"] is False
            assert result["error"]["code"] == "invalid_input"


async def test_stdio_import_nessus_then_batch_investigate(tmp_path: Path):
    with anyio.fail_after(90):
        async with (
            stdio_client(_server_params(tmp_path)) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()

            imported = _payload(
                (
                    await session.call_tool(
                        "import_nessus", {"file": "sample_scan.nessus", "min_severity": "medium"}
                    )
                ).content[0]
            )
            assert imported["ok"] is True
            assert imported["provenance"]["source"] == "nessus"
            ids = [c["finding_id"] for c in imported["candidates"]]
            assert ids

            investigated = _payload(
                (
                    await session.call_tool(
                        "investigate_finding",
                        {"finding_ids": ids, "intel_source": "fixture"},
                    )
                ).content[0]
            )
            assert investigated["ok"] is True
            assert investigated["count"] == len(ids)

            # Paths are refused: the agent cannot point the server elsewhere.
            refused = _payload(
                (await session.call_tool("import_nessus", {"file": "../pyproject.toml"})).content[0]
            )
            assert refused["ok"] is False
            assert refused["error"]["code"] == "invalid_input"

            # No credentials in the environment: a clear operator instruction, no data.
            no_creds = _payload((await session.call_tool("import_tenable", {})).content[0])
            assert no_creds["ok"] is False
            assert no_creds["error"]["code"] == "provider_unavailable"
            assert "TENABLE_ACCESS_KEY" in no_creds["error"]["message"]
