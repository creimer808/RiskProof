"""MCP tools: thin, agent-facing wrappers over RiskProof services.

Design rules:
* Tools NEVER relax authorization: allowlists, approvals, and dry-run mode come
  from server settings only. There is no parameter that can grant access.
* Every tool returns a structured payload; expected failures return
  ``{"ok": false, "error": {code, message}}`` instead of raising, so an agent
  can understand and recover.
* Data provenance is explicit in the output (live vs SAMPLE fixture).
"""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from riskproof.engine import investigation as inv
from riskproof.engine import policy_engine, remediation, scenario
from riskproof.errors import RiskProofError, error_payload
from riskproof.models.findings import Finding, ServiceObservation
from riskproof.models.policy import RiskPolicy
from riskproof.services import Services

IntelSource = Literal["auto", "live", "fixture"]


def register_tools(mcp: FastMCP, services: Services) -> None:
    """Attach all RiskProof tools to the MCP server."""

    @mcp.tool()
    async def enrich_threat_intel(
        cve_ids: list[str],
        source: IntelSource = "auto",
    ) -> dict[str, Any]:
        """Retrieve real EPSS scores and CISA KEV status for CVEs.

        Args:
            cve_ids: CVE identifiers, e.g. ["CVE-2021-44228"].
            source: "auto" tries live feeds and falls back to clearly-labeled
                SAMPLE fixtures when unreachable; "live" never substitutes
                fixtures; "fixture" uses bundled sample data only (offline).

        Returns a structured bundle with per-CVE EPSS observations (a
        statistical 30-day in-the-wild exploitation probability — never a claim
        about a specific system), KEV status, provenance, and any degradation
        notices.
        """
        try:
            bundle = await inv.enrich_threat_intel(services, cve_ids, source)
            return {"ok": True, "intel": bundle.model_dump(mode="json")}
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def investigate_finding(
        finding: Finding | None = None,
        fixture: str | None = None,
        finding_id: str | None = None,
        include_intel: bool = True,
        intel_source: IntelSource = "auto",
    ) -> dict[str, Any]:
        """Collect and normalize evidence for vulnerability finding(s).

        Provide EXACTLY ONE of:
        - `finding`: an inline normalized finding object (untrusted input;
          validated server-side)
        - `fixture`: a fixture file name in the fixtures directory, e.g.
          "findings_sample.json" (ingests all findings in it)
        - `finding_id`: re-open a previously ingested finding

        Builds the investigation record: scanner evidence, EPSS/KEV intel,
        asset context, open questions, applicability status, and the risk
        dimension assessment. Use fixture="findings_sample.json" for the demo.
        """
        try:
            reports = await inv.investigate(
                services,
                finding=finding,
                fixture=fixture,
                finding_id=finding_id,
                include_intel=include_intel,
                intel_source=intel_source,
            )
            return {
                "ok": True,
                "investigations": [r.model_dump(mode="json") for r in reports],
                "count": len(reports),
            }
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def verify_applicability(
        finding_id: str,
        observed_service: ServiceObservation | None = None,
    ) -> dict[str, Any]:
        """Evaluate whether the vulnerability actually affects the target system.

        Compares recorded evidence (scanner claims, plugin output) and, when
        provided, an observed service banner against the affected-version
        evidence. A mismatch yields SUSPECTED_NOT_AFFECTED — a lead for human
        review that never automatically suppresses the finding.

        Args:
            finding_id: a finding previously processed by investigate_finding.
            observed_service: optional ServiceObservation (e.g. from
                validate_exposure output) to cross-check versions.
        """
        try:
            record = inv.verify_applicability(services, finding_id, observed_service)
            return {
                "ok": True,
                "finding_id": finding_id,
                "applicability": record.applicability.value,
                "rationale": record.applicability_rationale,
                "open_questions": record.open_questions,
            }
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def validate_exposure(
        host: str,
        port: int,
        method: Literal["tcp_connect", "http_banner", "tls_cert_dates"] = "tcp_connect",
        finding_id: str | None = None,
    ) -> dict[str, Any]:
        """Authorized, NON-DESTRUCTIVE exposure verification.

        Performs only allowlisted connectivity/banner checks against allowlisted
        targets. Results never claim exploitability; inconclusive outcomes do
        not suppress findings. To validate a new target, a human operator must
        add it to RISKPROOF_ALLOWED_TARGETS — you cannot self-authorize.

        Args:
            host: target hostname or IP (must be allowlisted server-side).
            port: TCP port to observe.
            method: approved non-destructive check type.
            finding_id: optional finding to attach the evidence to.
        """
        try:
            result = await inv.validate_exposure(
                services, host=host, port=port, method=method, finding_id=finding_id
            )
            return {"ok": True, "validation": result.model_dump(mode="json")}
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def analyze_exploit_scenario(finding_id: str) -> dict[str, Any]:
        """Evaluate exploit prerequisites, exposure, consequences, uncertainties.

        Deterministic analysis derived strictly from the investigation record:
        CVSS-vector prerequisites, environmental exposure, KEV/EPSS-grounded
        consequences, and explicit uncertainties. Never claims successful
        exploitation or compromise without direct evidence.

        Args:
            finding_id: a finding previously processed by investigate_finding.
        """
        try:
            finding, record, assessment = inv.recompute_assessment(services, finding_id)
            exploit_scenario = scenario.build_exploit_scenario(finding, record, assessment)
            return {"ok": True, "scenario": exploit_scenario.model_dump(mode="json")}
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def simulate_remediation(finding_id: str) -> dict[str, Any]:
        """Compare remediation options and their expected risk effects (what-if).

        Deterministic simulation over the investigation record: vendor fix,
        exposure restriction, verification re-scan. Nothing is executed; effects
        are expectations, not guarantees.

        Args:
            finding_id: a finding previously processed by investigate_finding.
        """
        try:
            finding, record, assessment = inv.recompute_assessment(services, finding_id)
            simulation = remediation.simulate_remediation(finding, record, assessment)
            return {"ok": True, "simulation": simulation.model_dump(mode="json")}
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def execute_risk_policy(
        finding_ids: list[str],
        policy_name: str = "default",
    ) -> dict[str, Any]:
        """Evaluate policy thresholds and initiate PERMITTED remediation workflows.

        Transparent decision-table priorities (P1-P4) with rationale. All actions
        are recorded in the audit trail; by default they run dry-run and require
        human approval — ticketing integrations are not active in milestone 0.

        Args:
            finding_ids: findings previously processed by investigate_finding.
            policy_name: policy to apply (only the default policy exists in M0).
        """
        try:
            policy = RiskPolicy(name=policy_name)
            decisions = []
            for fid in finding_ids:
                finding, record, assessment = inv.recompute_assessment(services, fid)
                decision = policy_engine.evaluate_policy(
                    finding,
                    record,
                    assessment,
                    policy,
                    services.settings,
                    services.audit,
                    services.pending,
                )
                decisions.append(decision.model_dump(mode="json"))
            return {
                "ok": True,
                "decisions": decisions,
                "dry_run": services.settings.dry_run,
                "note": (
                    "Milestone 0 records actions for human execution; no external "
                    "ticketing system is contacted."
                ),
            }
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}
