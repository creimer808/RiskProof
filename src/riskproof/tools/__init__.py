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

from riskproof.engine import importer, remediation, scenario
from riskproof.engine import investigation as inv
from riskproof.engine.risk import RiskAssessment
from riskproof.errors import InvalidInputError, RiskProofError, error_payload
from riskproof.models.evidence import InvestigationRecord
from riskproof.models.findings import Finding, ServiceObservation
from riskproof.models.policy import RiskPolicy
from riskproof.services import Services

IntelSource = Literal["auto", "live", "fixture"]
SeverityName = Literal["critical", "high", "medium", "low", "info"]
MAX_AUDIT_ENTRIES = 200
FindingState = Literal["open", "reopened", "fixed"]


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
    async def import_nessus(
        file: str,
        min_severity: SeverityName = "low",
        only_with_cve: bool = False,
        top_n: int = 25,
    ) -> dict[str, Any]:
        """Import a .nessus (v2 XML) report and summarize it for triage.

        Args:
            file: bare file name (e.g. "Weekly_Network_Scan.nessus") inside the
                server's import directory. Paths are refused; a human operator
                controls the directory via RISKPROOF_IMPORT_DIR.
            min_severity: drop findings below this scanner severity ("low"
                excludes informational plugin noise).
            only_with_cve: keep only findings that reference at least one CVE.
            top_n: how many ranked candidates to return (max 100).

        Stores findings and returns totals, severity counts, worst hosts,
        most widespread plugins, and ranked candidate finding_ids. Findings are
        NOT enriched or assessed yet: pass candidates to investigate_finding
        (finding_ids=[...]) for EPSS/KEV intel and the risk assessment. Candidate
        ranking is scanner severity/VPR/CVSS, not exploitation intelligence.
        """
        try:
            summary = await importer.import_nessus(
                services, file, min_severity, only_with_cve, top_n
            )
            return {"ok": True, **summary}
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def import_tenable(
        severity: list[SeverityName] | None = None,
        state: list[FindingState] | None = None,
        since_days: int | None = None,
        cidr_range: str | None = None,
        limit: int = 5000,
        only_with_cve: bool = False,
        top_n: int = 25,
    ) -> dict[str, Any]:
        """Import findings from Tenable Vulnerability Management (Tenable One) via API.

        Runs a read-only vulnerability export. Credentials come from the
        server's environment (TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY) and can
        never be supplied or changed through this tool; if they are missing the
        error tells the human operator what to set.

        Args:
            severity: severities to export (default ["critical", "high"]).
            state: finding states (default ["open", "reopened"]).
            since_days: only findings last seen in the past N days (1-3650).
            cidr_range: restrict to assets in this CIDR, e.g. "10.0.0.0/24".
            limit: max findings to import (default 5000, max 50000).
            only_with_cve: keep only findings that reference a CVE.
            top_n: how many ranked candidates to return (max 100).

        Returns the same triage summary as import_nessus, with provenance
        source="tenable". Findings are stored but not yet enriched or assessed.
        """
        try:
            summary = await importer.import_tenable(
                services,
                severity=severity,
                state=state,
                since_days=since_days,
                cidr_range=cidr_range,
                limit=limit,
                only_with_cve=only_with_cve,
                top_n=top_n,
            )
            return {"ok": True, **summary}
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def investigate_finding(
        finding: Finding | None = None,
        fixture: str | None = None,
        finding_id: str | None = None,
        include_intel: bool = True,
        intel_source: IntelSource = "auto",
        finding_ids: list[str] | None = None,
        detail: Literal["summary", "full"] = "summary",
    ) -> dict[str, Any]:
        """Collect and normalize evidence for vulnerability finding(s).

        Provide EXACTLY ONE of:
        - `finding`: an inline normalized finding object (untrusted input;
          validated server-side)
        - `fixture`: a fixture file name in the fixtures directory, e.g.
          "findings_sample.json" (ingests all findings in it)
        - `finding_id`: re-open a previously ingested finding (including ones
          stored by import_nessus / import_tenable)
        - `finding_ids`: up to 25 previously stored findings in one call

        Builds the investigation record: scanner evidence, EPSS/KEV intel,
        asset context, open questions, applicability status, and the risk
        dimension assessment. Use fixture="findings_sample.json" for the demo.

        detail="summary" (default) returns per finding: priority + rationale,
        the risk dimensions, asset context, every evidence statement with its
        confidence label, and open questions; intel provenance/notices are
        stated once for the batch. detail="full" adds description, plugin
        output, solution, raw intel, and per-dimension basis lines — use it for
        a single finding when you need that text (e.g. version evidence).
        """
        try:
            reports = await inv.investigate(
                services,
                finding=finding,
                fixture=fixture,
                finding_id=finding_id,
                finding_ids=finding_ids,
                include_intel=include_intel,
                intel_source=intel_source,
            )
            if detail == "full":
                body = {
                    "investigations": [r.model_dump(mode="json") for r in reports],
                    "detail": "full",
                }
            else:
                body = inv.summarize_reports(reports)
            return {"ok": True, **body, "count": len(reports)}
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

    def _selected(
        finding_id: str | None, finding_ids: list[str] | None
    ) -> list[tuple[Finding, InvestigationRecord, RiskAssessment]]:
        if (finding_id is None) == (finding_ids is None):
            raise InvalidInputError("Provide exactly one of `finding_id` or `finding_ids`.")
        if finding_id is not None:
            return [inv.recompute_assessment(services, finding_id)]
        assert finding_ids is not None
        return inv.recompute_assessments(services, finding_ids, inv.MAX_BATCH_FINDINGS)

    @mcp.tool()
    async def analyze_exploit_scenario(
        finding_id: str | None = None,
        finding_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Evaluate exploit prerequisites, exposure, consequences, uncertainties.

        Deterministic analysis derived strictly from the investigation record:
        CVSS-vector prerequisites, environmental exposure, KEV/EPSS-grounded
        consequences, and explicit uncertainties. Never claims successful
        exploitation or compromise without direct evidence.

        Provide EXACTLY ONE of:
            finding_id: one finding processed by investigate_finding
                (returns `scenario`).
            finding_ids: up to 25 such findings in one call (returns
                `scenarios`; all-or-nothing if any id is unknown).
        """
        try:
            selected = _selected(finding_id, finding_ids)
            scenarios = [
                scenario.build_exploit_scenario(f, r, a).model_dump(mode="json")
                for f, r, a in selected
            ]
            if finding_id is not None:
                return {"ok": True, "scenario": scenarios[0]}
            return {"ok": True, "scenarios": scenarios, "count": len(scenarios)}
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def simulate_remediation(
        finding_id: str | None = None,
        finding_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Compare remediation options and their expected risk effects (what-if).

        Deterministic simulation over the investigation record: vendor fix,
        exposure restriction, verification re-scan. Nothing is executed; effects
        are expectations, not guarantees.

        Provide EXACTLY ONE of:
            finding_id: one finding processed by investigate_finding
                (returns `simulation`).
            finding_ids: up to 25 such findings in one call (returns
                `simulations`; all-or-nothing if any id is unknown).
        """
        try:
            selected = _selected(finding_id, finding_ids)
            simulations = [
                remediation.simulate_remediation(f, r, a).model_dump(mode="json")
                for f, r, a in selected
            ]
            if finding_id is not None:
                return {"ok": True, "simulation": simulations[0]}
            return {"ok": True, "simulations": simulations, "count": len(simulations)}
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

        Safe to re-run: an identical outstanding action is reused (listed in
        `existing_action_ids`), not recorded twice. All-or-nothing: if any id
        has no investigation record, nothing is recorded and the error lists
        every missing id.

        Args:
            finding_ids: findings previously processed by investigate_finding.
            policy_name: policy to apply (only the default policy exists in M0).
        """
        try:
            decisions = inv.execute_risk_policy(services, finding_ids, RiskPolicy(name=policy_name))
            return {
                "ok": True,
                "decisions": [d.model_dump(mode="json") for d in decisions],
                "dry_run": services.settings.dry_run,
                "note": (
                    "Milestone 0 records actions for human execution; no external "
                    "ticketing system is contacted."
                ),
            }
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}

    @mcp.tool()
    async def get_audit_trail(
        finding_id: str | None = None,
        limit: int = 50,
        include_pending_actions: bool = True,
    ) -> dict[str, Any]:
        """Read the append-only audit trail (read-only; changes nothing).

        Use it to reconstruct how a finding was handled — investigation and
        priority, applicability checks, validation attempts (including
        refusals), policy decisions — or to review recent activity.

        Args:
            finding_id: only entries about this finding (omit for all activity).
            limit: newest entries to return (1-200).
            include_pending_actions: also list policy actions recorded for
                human approval/execution, with their status.
        """
        try:
            limit = max(1, min(int(limit), MAX_AUDIT_ENTRIES))
            entries = services.audit.recent(limit=limit, finding_id=finding_id)
            if finding_id is not None and not entries:
                services.findings.get(finding_id)  # unknown id -> not_found, not silence
            result: dict[str, Any] = {
                "ok": True,
                "finding_id": finding_id,
                "entries": entries,
                "count": len(entries),
                "order": "newest first",
            }
            if include_pending_actions:
                result["pending_actions"] = services.pending.list_open(finding_id, limit)
            return result
        except RiskProofError as exc:
            return {"ok": False, "error": error_payload(exc)}
