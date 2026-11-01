# RiskProof

**Agentic vulnerability investigation and remediation platform for Tenable One
and Nessus data.** Built for Tenable SWARM Global 2026.

RiskProof goes beyond CVSS-based prioritization by combining real scanner
findings with FIRST EPSS exploitation intelligence, the CISA KEV catalog,
environmental context, authorized non-destructive validation, and AI-assisted
reasoning — every conclusion backed by evidence, timestamps, and an explainable
rationale.

RiskProof is **not** a vulnerability scanner and **not** a generic CVSS
calculator. It is an autonomous vulnerability investigator: it evaluates what a
finding *actually means for your organization*, recommends remediation, and
performs approved actions according to your policy.

## What it does

1. **Vulnerability Reality Checker** — investigates Nessus findings, enriches
   CVEs with real-time threat intelligence, verifies affected software, and
   performs authorized, non-destructive exposure checks.
2. **Risk & Exploitation Scenario Analyst** — evaluates exploit prerequisites,
   business impact, environmental exposure, and compensating controls; supports
   what-if remediation simulation without requiring a full attack-path graph.
3. **Autonomous Remediation Agent** — applies configurable risk policies,
   creates remediation tickets, recommends changes, requests additional scans,
   and maintains an auditable history of every decision.

## Architecture

Python MCP server (official MCP SDK / FastMCP, stdio transport) plus a reusable
Claude Agent Skill. Claude handles orchestration and reasoning; Python handles
deterministic risk evaluation, evidence processing, validation, policy
enforcement, and authorized actions.

- Works **without Tenable One credentials**: import `.nessus` files or use the
  bundled, clearly-labeled demo fixtures.
- Integrates with Tenable's official **Hexa MCP** when available
  (`providers/tenable.py` is the deliberate bridge point).
- Modular by design: additional scanners, enrichment providers, and remediation
  integrations plug into defined extension points.

See [docs/architecture.md](docs/architecture.md) for the full picture.

## Quickstart

```bash
git clone <this-repo> && cd RiskProof
uv sync                # Python 3.12+; creates .venv
uv run riskproof demo  # full pipeline offline on SAMPLE fixtures
uv run riskproof demo --live   # same pipeline, live EPSS + KEV feeds
```

Run the MCP server and connect an agent:

```bash
uv run riskproof serve
```

Claude Code (recommended): run the setup script. It creates the import
directory (`~/.riskproof/imports`, mode 700), prompts for Tenable API keys
with hidden input (Enter skips Tenable), and registers the server, replacing any
existing local `riskproof` registration:

```bash
./scripts/setup-mcp.sh
```

Restart Claude Code afterwards. The Tenable keys are passed to the server's
process environment only and are never written to `.env`; use a read-only API
key. If `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY` are already exported, the
script uses them instead of prompting.

Or register manually:

```bash
claude mcp add riskproof -- uv --directory /absolute/path/to/RiskProof run riskproof serve
```

Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "riskproof": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/RiskProof", "run", "riskproof", "serve"]
    }
  }
}
```

Then ask: *"Investigate the demo scan (`findings_sample.json`) and tell me what
actually matters and why."* Configuration details: [docs/usage.md](docs/usage.md).

## MCP tools

| Tool | Status (milestone 0) | What it does |
| --- | --- | --- |
| `enrich_threat_intel` | **Working (live + fixture)** | Real FIRST EPSS scores, CISA KEV status, provenance and degradation notices |
| `import_nessus` | **Working** | Import a `.nessus` report from the operator's import directory; stores findings and returns a KEV-aware triage summary |
| `import_tenable` | **Working (mock-tested; not yet run against a live tenant)** | Read-only Tenable VM vulnerability export via API; same triage summary |
| `investigate_finding` | **Working** | Ingest fixtures, inline findings, or stored `finding_ids` (batch of 25); builds the evidence record + assessment |
| `verify_applicability` | **Working (heuristic)** | Cross-checks scanner claims against observed versions; flags suspected false positives without suppressing |
| `validate_exposure` | **Working (authorized only)** | Non-destructive connectivity/banner/cert checks on allowlisted targets; audit-logged |
| `analyze_exploit_scenario` | **Working** | CVSS-vector prerequisites, exposure, KEV-grounded consequences, explicit uncertainties |
| `simulate_remediation` | **Working (what-if)** | Compares vendor fix / exposure restriction / verification re-scan with expected effects |
| `execute_risk_policy` | **Working (dry-run)** | Transparent P1–P4 decision table; records approval-gated actions in the audit trail |

Not implemented yet (deliberately): delegating to Tenable's Hexa MCP (direct API export
is the fallback), ticketing executors, attack-path graphs. See [PLAN.md](PLAN.md).

## Risk methodology (no black-box scores)

Every finding is assessed on separated, explainable dimensions — severity,
exploitation likelihood, environmental exposure, verified applicability,
business impact, evidence confidence — and one documented decision table maps
them to a P1–P4 remediation priority with rationale lines.

- EPSS is always a *statistical* prediction (30-day in-the-wild probability for
  the CVE), never a claim that a specific system is exploitable.
- Evidence is labeled `confirmed` / `inferred` / `missing` /
  `verification_failed`; negative validation never auto-suppresses a finding.
- SAMPLE fixture data is never presented as live intelligence.

Full methodology: [docs/risk-methodology.md](docs/risk-methodology.md).

## Security by default

- No intrusive testing is possible: only three read-only checks exist.
- Validation targets require a server-side allowlist (hosts/IPs/CIDRs); the
  agent cannot self-authorize, and denials are audit-logged.
- Remediation actions are dry-run and approval-gated by default.
- Scanner files, feed responses, and tool inputs are treated as untrusted data
  (defusedxml, strict Pydantic validation, no shell execution).
- Every investigation, validation, and policy action is recorded in an
  append-only SQLite audit trail.

Details: [docs/security.md](docs/security.md).

## Repository layout

```
src/riskproof/            application code + MCP server
  tools/                  MCP tools (thin wrappers)
  providers/              EPSS, KEV, fixtures, Tenable bridge
  models/                 Pydantic schemas
  engine/                 risk, evidence, scenario, policy logic
  validation/             allowlist + restricted non-destructive checks
  storage/                SQLite persistence + audit log
  ingest/                 .nessus XML + normalized JSON ingestion
skills/riskproof-investigator/SKILL.md   Claude Agent Skill
scripts/setup-mcp.sh      registers the MCP server with Claude Code
fixtures/                 clearly-labeled SAMPLE data (.nessus, JSON, EPSS, KEV)
tests/                    unit + integration (incl. end-to-end stdio MCP test)
docs/                     architecture, security, methodology, usage
```

## Development

```bash
uv sync
uv run pytest                                   # full offline suite
RISKPROOF_LIVE_TESTS=1 uv run pytest tests/test_live_intel.py   # real feeds
uv run ruff check . && uv run ruff format --check .
```

CI runs lint + tests on Python 3.12 and 3.14 via GitHub Actions.

## Roadmap

See [PLAN.md](PLAN.md) for P0 launch requirements (Tenable SWARM Global 2026),
P1 enhancements, and completion criteria.

## License

[MIT](LICENSE) — © 2026 RiskProof Contributors.
