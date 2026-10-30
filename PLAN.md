# RiskProof — Product & Delivery Plan

Vision: an **autonomous vulnerability investigator** for Tenable One and Nessus
data — not another scanner, not a CVSS calculator. RiskProof investigates what
findings mean for *this* organization, recommends remediation with evidence,
and executes approved actions under policy, with an auditable history.

North-star demo (Tenable SWARM Global 2026): paste/import a Nessus scan, ask
"what actually matters and why", watch the agent investigate — enriching with
EPSS/KEV, questioning applicability, verifying exposure where authorized — and
finish with a policy-driven, fully auditable remediation plan.

---

## Milestone 0 — Foundation (COMPLETE)

Working scaffold, all demonstrated by `uv run riskproof demo` and the
end-to-end stdio test (`tests/test_server_stdio.py`):

- [x] Repository, `uv` project, directory structure, MIT license, CI
- [x] Local MCP server (official SDK FastMCP, stdio) with 7 registered tools
- [x] FIRST EPSS integration (batched, strict parsing) — live-verified
- [x] CISA KEV integration (TTL-cached in SQLite) — live-verified
- [x] Normalized vulnerability + asset models (Pydantic v2)
- [x] Ingestion: `.nessus` v2 XML (defusedxml) + normalized JSON fixtures
- [x] `enrich_threat_intel` returning real EPSS/KEV intelligence
- [x] All 7 tools functional at M0 scope (no fake placeholders)
- [x] Claude Agent Skill (`skills/riskproof-investigator/SKILL.md`)
- [x] Realistic labeled fixtures + 83 tests (unit, integration, e2e stdio)
- [x] Docs: installation, configuration, MCP client setup, methodology, security
- [x] `ruff check` clean

Explicitly deferred (per scope): frontend, graph visualization, production
deployment infrastructure, full autonomous remediation.

---

## P0 — SWARM Global 2026 launch requirements

The bar for the conference demo. Each item has explicit completion criteria.

### P0.1 Live Tenable data in (Hexa MCP bridge)
Import findings directly from Tenable One at demo time.
- [ ] Detect Tenable Hexa MCP availability from the host agent and delegate
      Tenable queries to it (documented handshake in `providers/tenable.py`).
- [ ] Fallback: read-only Tenable.io `vulns` export via API when Hexa is
      unavailable (credentials from env, never logged).
- **Done when:** a scan from a real Tenable container appears in
  `investigate_finding` output within 60s, with provenance recorded as
  `source="tenable"` in the audit log.

### P0.2 Applicability verification upgrade
Beyond heuristics: CPE/KEV-product matching and software-inventory cross-check.
- [ ] CPE dictionary lookup for CVE↔product/version range matching (NVD API or
      bundled corpus with clear freshness labeling).
- [ ] `verify_applicability` consumes package inventory evidence
      (config observation) when provided.
- **Done when:** for the demo dataset, applicability statuses are correct with
  cited evidence, and at least one confirmed false positive and one confirmed
  true positive are demonstrated live.

### P0.3 Authorized exposure validation, demo-grade
- [ ] Service-banner capture for HTTP/SSH/SMTP to feed applicability
      cross-checks automatically from `validate_exposure` results.
- [ ] Allowlist management CLI (`riskproof allowlist add/remove`) that edits
      the same config the server reads, with audit entries.
- **Done when:** the live demo validates one allowlisted host end-to-end and
  correctly refuses one non-allowlisted host, both audit-logged.

### P0.4 Policy pack + remediation workflow
- [ ] Load policy packs from YAML/JSON (thresholds, asset criticality
      overrides, action routing) instead of the single built-in policy.
- [ ] Ticketing executor behind the approval gate (GitHub Issues or Jira) with
      dry-run output identical in structure to execution output.
- **Done when:** `execute_risk_policy` with an approved policy creates exactly
  the expected tickets for the demo dataset, and the audit log reconstructs the
  full decision chain.

### P0.5 Investigation continuity
- [ ] Cross-finding correlation: shared asset/critical-asset rollups in
      `execute_risk_policy` output.
- [ ] Investigation resume: re-open a prior session's records deterministically.
- **Done when:** a killed and restarted server resumes with all prior evidence
  intact (idempotent re-investigation produces identical assessments).

### P0 launch gate (all must hold)
- [ ] `uv sync && uv run riskproof demo --live` works on a clean machine.
- [ ] Full test suite green; `ruff check` clean.
- [ ] 20-minute live demo script rehearsed end-to-end (import → investigate →
      validate → simulate → policy → audit review) without manual DB edits.
- [ ] Security review pass against `docs/security.md` commitments.

## P1 — Post-launch enhancements

- **More scanners:** Qualys, OpenVAS, Wiz import adapters (normalized `Finding`
  emitters).
- **More intel:** NVD enrichment (references, CWE), Exploit-DB PoC existence,
  vendor advisory cross-links — each with provenance labels and honest
  unavailability records.
- **CVSS v4 + CISA coordinates:** parse v4 vectors; use KEV ransomware metadata
  in scenario consequences.
- **Attack-surface hints:** lightweight reachability reasoning from asset
  services + validation evidence (still not a full attack-path graph).
- **Server transports:** authenticated streamable-HTTP transport for team use;
  per-actor audit identities.
- **Policy analytics:** drift reports (priority changes over time), SLA
  tracking against KEV due dates.
- **Remediation integrations:** change-management systems, IaC pull requests
  (e.g., version bumps), rescan scheduling via Tenable API.
- **MCP SDK v2 migration:** evaluate the renamed `MCPServer` API once the
  ecosystem settles; keep the tools layer thin so migration is contained.

## P2 / backlog

- Multi-tenant storage, SSO, RBAC on investigations.
- Compensating-control effectiveness tracking (control → finding suppression
  with human sign-off, always reversible).
- Executive reporting exports (board-style risk narrative from evidence).
- Plugin marketplace for community validation checks (sandboxed, signed).

## Risk register

| Risk | Mitigation |
| --- | --- |
| Hexa MCP unavailable at demo time | P0.1 includes direct API fallback; `.nessus` import always works |
| Feed outage during demo | `source="auto"` degrades to labeled fixtures with explicit notices; rehearse offline path |
| Data honesty failures (fixture-as-live) | Provenance is structural (`source`, `catalog`, `degraded`), tests assert labels |
| LLM policy bypass attempts | Server-side authorization only; no tool parameter grants access; denials audit-logged |
| Scope creep toward "another scanner" | Non-goals: no scanning engine, no agent deployment, no signature/plugin execution |
