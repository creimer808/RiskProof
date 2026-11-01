# Security model

RiskProof investigates vulnerabilities; it must never become one. This document
is the contract for how RiskProof stays safe by default.

## Secure defaults

| Control | Default | Enforced by |
| --- | --- | --- |
| Intrusive testing | **Never available** | Only 3 read-only check methods exist (`validation/checks.py`); there is no plugin/shell execution path |
| Validation targets | **Deny all** (empty allowlist) | `validation/targets.py` fails closed |
| Remediation execution | **Dry-run** | `Settings.dry_run=true`; actions are recorded, not executed |
| Human approval | **Required** | `Settings.require_approval=true`; `RiskPolicy.allow_ticket_creation=false` |
| Credentials | **Never logged or committed** | `.env` is git-ignored; the audit log stores references, never secrets |

## Preventing agent bypass

The language model is treated as an untrusted component:

- **No tool parameter can grant access.** Allowlists, approved methods, dry-run,
  and approval requirements are read from server-side `Settings` at call time.
  There is no "authorize=yes" argument anywhere in the tool schemas.
- **Target authorization is structural.** `TargetAuthorizer` resolves hostnames
  and requires *every* resolved address to match the allowlist (IP, CIDR, or
  hostname rule) — blocking hostname-dressing of internal addresses — and fails
  closed on resolution failure. Denied attempts are recorded in the audit log
  with the human steps required to authorize properly.
- **Method authorization is a registry.** `CHECK_METHODS` is a closed set of
  three non-destructive checks. Unknown methods raise `AuthorizationDenied`
  before any network activity. Nothing can inject new methods at runtime.
- **Priority cannot be negotiated.** `assess()` and `evaluate_policy()` are pure
  functions over stored evidence. Tool input selects *what* to evaluate, never
  *what the result is*.

## Non-destructive validation contract

The three permitted checks are read-only by construction:

- `tcp_connect` — open a TCP connection, close it
- `http_banner` — one benign `HEAD` request, record status line/headers
- `tls_cert_dates` — TLS handshake, record certificate validity dates

No exploit payloads, no credential spraying, no service crashing. Every result
carries the disclaimer that it does **not** demonstrate exploitability and that
inconclusive results do **not** suppress findings.

## Import confinement and Tenable credentials

- `import_nessus` takes a bare file name only. It must match a strict
  `*.nessus` pattern, resolve **directly inside** the operator-configured
  `RISKPROOF_IMPORT_DIR` (so `..`, separators, and symlinks that escape are
  refused), and be under `RISKPROOF_MAX_IMPORT_BYTES`.
- `import_tenable` reads `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY` from the
  server environment only. They are not accepted from tool input, not stored in
  the DB or audit log, not included in errors or `repr`, and the base URL must
  be https. Redirects are **not followed**, so the key header can never be
  forwarded to another host.
- The client is read-only against Tenable (create/poll/download/cancel an
  export job). Export identifiers from responses are validated before use in a
  URL path, and every record is normalized through length-limited models.
- Importing stores findings only. Enrichment and assessment still happen in
  `investigate_finding`, and candidate ranking states what it used.

## Untrusted data handling

- `.nessus` files are parsed with `defusedxml` (entity-expansion/XXE safe); a
  malformed `ReportItem` is skipped with a warning, not trusted.
- All external payloads are validated into Pydantic models with field
  constraints (length caps, ranges, enum membership) before use.
- Plugin outputs and banners are stored as data, truncated, and never
  interpolated into commands (RiskProof executes no shells).
- CVE identifiers are normalized and pattern-validated before enrichment.

## EPSS / KEV honesty

- EPSS statements always carry the statistical caveat (30-day in-the-wild
  probability for the CVE, not a claim about a system).
- SAMPLE fixture intelligence is stamped `source="sample-fixture"` /
  `catalog="sample"`; absence from the sample KEV catalog is never reported as
  "not exploited". `source="live"` never substitutes fixtures.
- Degraded bundles set `degraded=true` and explain why in `notices`.

## Credentials and data hygiene

- Configuration via `RISKPROOF_*` environment variables / `.env` (git-ignored).
- The Tenable bridge reports only *whether* credential env vars are set — never
  their values.
- The SQLite database contains findings, evidence, intel, audit records, and
  pending actions — treat the DB file as sensitive operational data.
- The audit trail (`audit_log`) is append-only and records: timestamp, actor,
  action, subject, outcome, rationale, and details — for enrichment, validation
  (including refusals), and every policy action.

## Known limitations (milestone 0)

- No multi-user auth on the MCP server itself: run it locally, per analyst.
  Transport hardening (e.g., authenticated HTTP transport) is a P1 item.
- The KEV cache TTL is time-based only; there is no feed-integrity signature
  check yet.
- Remediation "executors" do not exist yet; nothing can change a system.
