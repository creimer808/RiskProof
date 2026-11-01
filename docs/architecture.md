# Architecture

RiskProof is a **Python MCP server with a reusable Claude Agent Skill**. Claude
handles investigation orchestration, reasoning, and tool selection; Python
handles deterministic risk evaluation, evidence processing, validation, policy
enforcement, and authorized actions.

```
┌──────────────────────────── MCP client (Claude) ┐
│  skills/riskproof-investigator/SKILL.md          │
│  orchestrates: which tool, which finding, when   │
└──────────────┬───────────────────────────────────┘
               │ MCP (stdio)
┌──────────────▼───────────────────────────────────┐
│ riskproof.server  (FastMCP)                      │
│ riskproof.tools    11 tools = thin wrappers      │
├──────────────────────────────────────────────────┤
│ riskproof.engine    deterministic logic          │
│   risk.py        dimensions + decision table     │
│   evidence.py    evidence file construction      │
│   scenario.py    exploit scenario analysis       │
│   remediation.py what-if simulation              │
│   policy_engine.py priorities + authorized acts  │
│   investigation.py  orchestration service        │
├──────────────────────────────────────────────────┤
│ riskproof.providers   external data              │
│   epss.py    FIRST EPSS API (live)               │
│   kev.py     CISA KEV feed (live, cached)        │
│   fixtures_source.py  SAMPLE data (offline)      │
│   tenable.py Hexa MCP bridge point (P1)          │
├──────────────────────────────────────────────────┤
│ riskproof.ingest      .nessus XML / JSON         │
│ riskproof.validation  allowlist + safe checks    │
│ riskproof.storage     SQLite (findings, intel    │
│                       cache, audit, actions)     │
│ riskproof.models      Pydantic schemas           │
└──────────────────────────────────────────────────┘
```

## Design principles

1. **Tools are thin.** `tools/` only translates MCP calls into service calls and
   wraps expected errors as structured `{"ok": false, "error": {...}}`
   payloads. All logic lives in `engine/`, `providers/`, `ingest/`, and
   `validation/` — all of it testable without MCP.
2. **Determinism where it matters.** Priorities, evidence classification, and
   policy outcomes are pure functions of recorded state. An agent cannot nudge
   the priority: the decision table is code, with its rationale attached.
3. **Untrusted data at every boundary.** Scanner XML (defusedxml, Pydantic
   validation, length limits), HTTP feeds (strict schemas, timeouts), and MCP
   tool inputs (Pydantic models) are validated before use.
4. **Honest degradation.** Live fetch failures degrade explicitly: bundles carry
   `degraded`, per-item `unavailable` records, and SAMPLE-fixture provenance
   labels. Nothing pretends to be live data.
5. **Authorization is server-side.** Allowlists, approvals, and dry-run come
   from `Settings` (environment), never from tool arguments.

## Data flow (milestone 0)

1. **Ingest** — `.nessus` file or normalized JSON → `Finding` models
   (`ingest/`), asset context merged from the asset catalog.
2. **Enrich** — `enrich_threat_intel` fetches EPSS scores and KEV status
   (`providers/`), caches the KEV catalog in SQLite with a TTL, and records an
   audit entry. Fixture fallback is labeled.
3. **Evidence** — `engine/evidence.py` builds the `InvestigationRecord`:
   scanner evidence, per-CVE EPSS/KEV statements, asset context, open questions,
   initial applicability.
4. **Assess** — `engine/risk.py` computes the separated risk dimensions and the
   documented P1–P4 decision table.
5. **Analyze / simulate** — scenario and remediation modules derive structured
   analyses strictly from the record.
6. **Enforce policy** — `policy_engine.py` maps priority to permitted actions,
   records each action in `pending_actions` + `audit_log` (dry-run by default).

## Storage schema (SQLite, WAL)

| Table | Purpose |
| --- | --- |
| `findings` | Normalized findings (JSON payload + metadata) |
| `investigations` | Investigation records per finding |
| `intel_cache` | TTL cache (KEV catalog today, more later) |
| `audit_log` | Append-only: every enrich/validate/policy action and refusal |
| `pending_actions` | Policy-authorized actions awaiting human execution |
| `meta` | Schema version |

## Extension points

- **New scanner** — emit `Finding` models (see `ingest/fixtures.py` for the
  normalized shape) or write a parser module next to `nessus.py`.
- **New intel provider** — follow `providers/epss.py`: strict parse, typed
  errors (`ProviderError`), injectable httpx transport for tests, provenance
  labels in the output model.
- **New validation check** — add a pure-async function in
  `validation/checks.py` and register it in `CHECK_METHODS`. The registry is
  the only gate; nothing else can execute.
- **Tenable One** — `providers/tenable.py` is the deliberate bridge point.
  When Tenable's official Hexa MCP server is available, delegate live Tenable
  queries to it rather than duplicating API access; otherwise implement the
  Tenable.io API client there in P1.
- **Remediation integrations** — implement executors that consume
  `pending_actions` rows (ticketing, IaC PRs, scan scheduling). Keep them
  behind the approval gate.
