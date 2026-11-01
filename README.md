# RiskProof

**An agentic vulnerability investigator for Tenable One and Nessus data.**
Built for Tenable SWARM Global 2026.

RiskProof is an MCP server that turns raw scanner output into defensible
remediation decisions. It combines real findings with FIRST EPSS exploitation
intelligence, the CISA KEV catalog, your business context, authorized
non-destructive validation, and AI-assisted reasoning — every conclusion backed
by evidence, timestamps, and an explainable rationale.

RiskProof is **not** a vulnerability scanner and **not** a generic CVSS
calculator. It is an investigator: it evaluates what a finding *actually means
for your organization*, recommends remediation, and records approved actions
according to your policy.

---

## Why this exists

A scanner hands you 17,000 findings sorted by CVSS. That is not a to-do list.
CVSS says "bad in the abstract" — it cannot tell you what to patch Monday
morning, and it knows nothing about which of your servers matter.

RiskProof answers the three questions that actually drive remediation:

1. **Does this finding matter for THIS organization?** — exploitation
   intelligence + your asset context, not just the vendor's severity.
2. **How do we know?** — every claim is labeled confirmed / inferred / missing
   / verification-failed, with its source attached.
3. **What should we do about it?** — a prioritized, simulated, approval-gated
   plan, with an audit receipt for every decision.

### What that accomplishes

| Without RiskProof | With RiskProof |
| --- | --- |
| Sort by CVSS, eyeball the top of the list | P1–P4 priorities from KEV, EPSS, exposure, and asset criticality — each with cited rationale |
| "Critical" findings on hosts that aren't actually vulnerable | False-positive *leads* from applicability checks — surfaced for human review, never auto-suppressed |
| Scanner has no idea which servers matter | Your asset inventory (criticality, internet-facing, owner) feeds the decision table |
| Remediation debates from memory and intuition | What-if simulation: vendor fix vs. restrict exposure vs. verify by re-scan |
| "Why did you patch this but not that?" | Append-only audit trail reconstructs every decision and refusal |
| AI agents feel too risky to point at vuln data | Allowlist-gated checks, dry-run by default, human approval required, priorities computed by code — not the model |

---

## How it works

Claude orchestrates the investigation; Python does the deterministic work.

```
 You: "what actually matters?"
        │
        ▼
 Claude (orchestration + reasoning, guided by the bundled Agent Skill)
        │  MCP over stdio
        ▼
 RiskProof MCP server — 11 tools over deterministic engines
 ┌──────────────────────────────────────────────────────────┐
 │ 1 IMPORT   .nessus files or Tenable VM API (read-only)    │
 │ 2 ENRICH   FIRST EPSS scores + CISA KEV catalog (cached)  │
 │ 3 EVIDENCE per-finding evidence file w/ confidence labels │
 │ 4 ASSESS   6 risk dimensions → documented P1–P4 table     │
 │ 5 VERIFY   applicability + allowlisted exposure checks    │
 │ 6 SIMULATE exploit scenarios + remediation what-ifs       │
 │ 7 POLICY    decision → recorded actions (dry-run default) │
 │ 8 AUDIT     append-only SQLite trail of everything        │
 └──────────────────────────────────────────────────────────┘
        │
        ▼
 Priorities, evidence, plan, receipts — in chat and in an HTML report
```

The key design rule: **priorities are code, not model opinion.** The decision
table that maps risk dimensions to P1–P4 is deterministic Python with its
rationale attached. The agent can investigate, question, and verify — it cannot
nudge a P1 down to a P3.

### The tools

| Phase | Tool | What it does |
| --- | --- | --- |
| Import | `import_nessus` | Ingest a `.nessus` report; KEV-aware triage summary with ranked candidates |
| Import | `import_tenable` | Read-only Tenable VM vulnerability export via API (same summary) |
| Investigate | `investigate_finding` | Build the evidence record + risk assessment (batches of 25) |
| Investigate | `enrich_threat_intel` | Real EPSS scores + KEV status with provenance |
| Investigate | `verify_applicability` | Cross-check scanner claims vs. observed versions; flags suspected false positives |
| Investigate | `validate_exposure` | Non-destructive connectivity/banner/cert checks on allowlisted targets only |
| Decide | `analyze_exploit_scenario` | Prerequisites, exposure, KEV-grounded consequences, explicit uncertainties |
| Decide | `simulate_remediation` | Compare fix / restrict / verify options and expected effects |
| Decide | `execute_risk_policy` | P1–P4 decision table → recorded, approval-gated actions (dry-run default) |
| Review | `get_audit_trail` | Per-finding or recent history plus pending actions |
| Review | `generate_report` | Self-contained HTML report (rollup, queue, evidence, audit) written 0600 |

---

## Get running in 5 minutes

You need Python 3.12+, [uv](https://docs.astral.sh/uv/), and an MCP client
(Claude Code or Claude Desktop). **No Tenable credentials required to start.**

```bash
git clone <this-repo> && cd RiskProof
uv sync                 # creates .venv, installs everything
uv run riskproof demo   # full pipeline on bundled SAMPLE data, offline
```

The demo investigates five synthetic findings (Log4Shell, regreSSHion,
Zerologon, Terrapin, and an informational) and prints the whole pipeline's
output: dimensions, priorities, scenarios, and policy decisions — clearly
labeled SAMPLE, never pretending to be live intelligence.
`uv run riskproof demo --live` runs the same pipeline against the real EPSS
and KEV feeds.

### Connect Claude

Claude Code (recommended) — registers the server, creates the import directory:

```bash
./scripts/setup-mcp.sh
```

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

Restart Claude Code / Claude Desktop afterwards.

### Start analyzing

Open Claude and paste:

> **Investigate the demo scan (`findings_sample.json`) and tell me what
> actually matters and why.**

You'll get a per-finding breakdown with priorities and rationale, scenario
analysis for the worst findings, remediation options, and a dry-run policy
plan — all from bundled SAMPLE data. Follow up with:

> **Generate a report of that investigation.**

…to write the same analysis to a self-contained HTML file you can keep or
share. From there, move on to your own scans (below).

---

## Example prompts

Copy-paste these once the server is connected. Everything before "Feeding it
your data" also works entirely on the offline demo dataset.

**Triage a real scan**

> Import `Weekly_Network_Scan.nessus` from my imports folder and give me a
> triage summary.
>
> Investigate the top 20 candidates from that import.
>
> Generate a P2 report I can attach to the remediation ticket.

**Understand a specific CVE or finding**

> What do you know about CVE-2024-6387?
>
> What's the exploit scenario for the Zerologon finding on corp-db-02?
>
> Is the regreSSHion finding on prod-web-01 real? The plugin output says the
> host runs OpenSSH 9.6p1.

**Verify before you commit** *(targets must be allowlisted — see below)*

> Check whether 10.20.99.7:8080 is reachable and attach the result to the
> Log4Shell finding.

**Plan the work**

> We can't patch corp-db-02 until the next change window — simulate our
> options and what each one buys us.
>
> Apply the risk policy to everything we investigated and tell me what actions
> would be recorded.
>
> What actions are still pending human execution?

**Accountability**

> Why is the Log4Shell finding a P1? Show me the evidence.
>
> Show me the audit trail for prod-web-01's findings.

---

## What an answer looks like

Real (trimmed) demo output for the Log4Shell finding:

```json
{
  "finding_id": "prod-web-01.demo.local-155999-8080tcp",
  "cves": ["CVE-2021-44228"],
  "assessment": {
    "severity_label": "critical",
    "exploitation_likelihood": "observed_in_the_wild",
    "likelihood_basis": [
      "CVE-2021-44228 is listed in CISA KEV ... exploited in the wild.",
      "EPSS 0.942 for CVE-2021-44228 is very high. EPSS is a statistical prediction that the CVE is exploited somewhere in the wild within 30 days — not a claim about this system."
    ],
    "environmental_exposure": "internet_facing",
    "business_impact": "severe",
    "recommended_priority": "P1",
    "priority_rationale": ["KEV-listed (exploited in the wild) AND internet-facing."]
  },
  "recommended_remediation": "opt-vendor-fix",
  "policy_rationale": ["Dry-run mode: all actions were recorded for human execution only."]
}
```

Notice the shape: no naked scores. Every dimension carries its basis, the EPSS
statistic is explicitly *not* a claim about this system, and the policy action
is recorded rather than executed.

---

## Feeding it your data

### Scan output — pick either

- **`.nessus` files:** drop the file into `~/.riskproof/imports` (created by
  the setup script; configurable via `RISKPROOF_IMPORT_DIR`), then ask Claude
  to import it by name. A 77 MB report with ~17k findings imports in a couple
  of seconds.
- **Tenable Vulnerability Management:** set `TENABLE_ACCESS_KEY` /
  `TENABLE_SECRET_KEY` in the server's environment (the setup script prompts
  for them; use a read-only key). `import_tenable` runs a read-only export —
  keys are never logged and never accepted as tool input. *Status: covered by
  mock-transport tests; verify against a real tenant before relying on it.*

### Business context — the piece scanners can't know

Record which assets matter in `~/.riskproof/assets.json`:

```json
{
  "rules": [
    {"match": "10.20.0.0/16", "environment": "production", "internet_facing": false},
    {"match": ["web01", "web01.corp.example"], "criticality": "critical",
     "owner": "platform-team", "note": "customer checkout"}
  ]
}
```

Without this file, RiskProof cannot know criticality or exposure — and a
KEV-listed finding on your most critical server will stop at **P2** instead of
P1. Edits take effect on the next tool call; no re-import needed. The file is
operator configuration: no tool can edit it.

### Validation targets — explicit, human-controlled

`validate_exposure` only works on hosts you allowlist in
`RISKPROOF_ALLOWED_TARGETS` (hosts/IPs/CIDRs, comma-separated; empty = deny
all). The agent cannot self-authorize, and refusals are audit-logged.

---

## The investigation loop

The bundled Agent Skill (`skills/riskproof-investigator/SKILL.md`) drives this
loop automatically — you just talk. Knowing the steps helps you read the output:

1. **Import** a scan (`.nessus` or Tenable API) → ranked triage candidates.
2. **Investigate** candidates in batches → evidence record + assessment.
3. **Read the six dimensions** — severity, exploitation likelihood, exposure,
   applicability, business impact, evidence confidence — never collapsed into
   one number.
4. **Verify applicability** when version evidence exists → false-positive leads.
5. **Validate exposure** on allowlisted targets → confirmed reachability.
6. **Analyze & simulate** → scenario, options, expected effects.
7. **Apply policy** → P1–P4 with rationale, dry-run recorded actions.
8. **Review & report** → audit trail, HTML report.

---

## Risk methodology (no black-box scores)

Every finding is assessed on separated, explainable dimensions — severity,
exploitation likelihood, environmental exposure, verified applicability,
business impact, evidence confidence — and one documented decision table maps
them to P1–P4 with rationale lines.

- EPSS is always a *statistical* prediction (30-day in-the-wild probability for
  the CVE), never a claim that a specific system is exploitable.
- KEV listing means the *vulnerability* is exploited in the wild — not that
  this asset was compromised.
- Evidence is labeled `confirmed` / `inferred` / `missing` /
  `verification_failed`; negative validation never auto-suppresses a finding.
- SAMPLE fixture data is never presented as live intelligence.

Full methodology: [docs/risk-methodology.md](docs/risk-methodology.md).

## Security by default

- Only three non-destructive check types exist; nothing intrusive is possible.
- Validation targets require a server-side allowlist; the agent cannot
  self-authorize, and denials are audit-logged.
- Remediation actions are dry-run and approval-gated by default.
- Scanner files, feed responses, and tool inputs are treated as untrusted data
  (defusedxml, strict Pydantic validation, no shell execution).
- Every investigation, validation, and policy action is recorded in an
  append-only SQLite audit trail.
- Reports are written owner-only (mode 0600); import directories, report
  directories, and API credentials are all operator configuration that no tool
  argument can override.

Details: [docs/security.md](docs/security.md).

---

## Documentation

| Doc | Contents |
| --- | --- |
| [docs/usage.md](docs/usage.md) | Configuration, MCP client setup, imports, asset inventory, reports |
| [docs/architecture.md](docs/architecture.md) | Module layout, design principles, data flow, extension points |
| [docs/risk-methodology.md](docs/risk-methodology.md) | The six dimensions and the P1–P4 decision table |
| [docs/security.md](docs/security.md) | Trust boundaries, authorization model, threat analysis |
| [PLAN.md](PLAN.md) | Roadmap: P0 launch gates, P1 enhancements, P2 backlog |

## Repository layout

```
src/riskproof/            application code + MCP server
  tools/                  MCP tools (thin wrappers)
  providers/              EPSS, KEV, fixtures, Tenable bridge
  models/                 Pydantic schemas
  engine/                 risk, evidence, scenario, policy, report logic
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
P1 enhancements (more scanners, Hexa MCP delegation, ticketing executors, SLA
tracking), and P2 backlog.

## License

[MIT](LICENSE) — © 2026 RiskProof Contributors.
