# Usage guide

## Install

```bash
cd RiskProof
uv sync            # creates .venv and installs riskproof + deps
```

## Configure

```bash
cp .env.example .env
# Edit .env: at minimum, set RISKPROOF_ALLOWED_TARGETS if you plan to use
# validate_exposure. Everything works without Tenable credentials.
```

Key settings (all optional, secure defaults):

| Variable | Default | Purpose |
| --- | --- | --- |
| `RISKPROOF_DB_PATH` | `~/.riskproof/riskproof.db` | SQLite storage |
| `RISKPROOF_OFFLINE` | `false` | Force SAMPLE fixture intel |
| `RISKPROOF_IMPORT_DIR` | `~/.riskproof/imports` | Only directory `import_nessus` reads from |
| `RISKPROOF_ASSET_INVENTORY` | `~/.riskproof/assets.json` | Operator asset context (criticality, exposure) for real findings |
| `RISKPROOF_REPORTS_DIR` | `~/.riskproof/reports` | Where `generate_report` writes HTML reports (tool input cannot choose paths) |
| `RISKPROOF_MAX_IMPORT_BYTES` | `536870912` | Largest `.nessus` file accepted |
| `RISKPROOF_TENABLE_BASE_URL` | `https://cloud.tenable.com` | Tenable VM API host (https only) |
| `RISKPROOF_ALLOWED_TARGETS` | *(empty = deny all)* | Validation allowlist (hosts/IPs/CIDRs, comma-separated) |
| `RISKPROOF_DRY_RUN` | `true` | Record actions instead of executing |
| `RISKPROOF_REQUIRE_APPROVAL` | `true` | All policy actions need human approval |

### Guided setup for Claude Code

`./scripts/setup-mcp.sh` walks through the settings above (folders, allowlist,
offline mode) plus the optional Tenable and GreyNoise keys (hidden input, stored
only in Claude Code's server config, never in `.env`). It starts the server once
against a throwaway database to prove it works before registering anything, then
offers to open Claude Code. Use `--yes` for no prompts (exported variables and
defaults) and `--no-launch` to skip the final offer. Re-running replaces the
registration, so re-enter or re-export your keys.

## Smoke test (no MCP client needed)

```bash
uv run riskproof demo            # offline, SAMPLE data, full pipeline
uv run riskproof demo --live     # live FIRST EPSS + CISA KEV feeds
```

## Run the MCP server

```bash
uv run riskproof serve           # MCP over stdio (the default)
# equivalent: uv run python -m riskproof serve
```

## Connect an MCP client

### Claude Desktop / Claude Code (stdio)

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

With Claude Code you can also run:

```bash
claude mcp add riskproof -- uv --directory /absolute/path/to/RiskProof run riskproof serve
```

### Any MCP-compatible client

The server exposes twelve tools over stdio:
`import_nessus`, `import_tenable`, `list_tenable_tags`, `investigate_finding`, `enrich_threat_intel`,
`verify_applicability`, `validate_exposure`, `analyze_exploit_scenario`,
`simulate_remediation`, `execute_risk_policy`, `get_audit_trail`,
`generate_report`.

## Import a real scan

### From a `.nessus` file

Put the file in the import directory (or point `RISKPROOF_IMPORT_DIR` at the
folder that holds it), then ask the agent to import it:

```bash
claude mcp add riskproof -e RISKPROOF_IMPORT_DIR=/path/to/scans -- \
  uv --directory /absolute/path/to/RiskProof run riskproof serve
```

`import_nessus(file="Weekly_Network_Scan.nessus", min_severity="high")` stores
the findings and returns totals, worst hosts, widest plugins, and ranked
candidate `finding_id`s (live CISA KEV first, then severity/VPR/CVSS). A
77 MB report with ~17k findings imports in a couple of seconds. Then:
`investigate_finding(finding_ids=[...])` (max 25 per call) adds EPSS/KEV intel
and the risk assessment.

### Generate an HTML report

Once findings are investigated, produce a durable artifact:

```bash
uv run riskproof report                    # all investigated findings
uv run riskproof report --min-priority P2  # only P1/P2
uv run riskproof report --output out.html  # default: ./riskproof-report-<timestamp>.html
uv run riskproof report --include-resolved # also list resolved / not-seen findings
```

Or from an MCP session, ask for `generate_report` (same engine; the file lands
in `RISKPROOF_REPORTS_DIR`, default `~/.riskproof/reports`, written with
owner-only permissions). The report is read-only aggregation, laid out top-down:

1. **Dashboard** cards: assets analysed, assets with exploited-now
   vulnerabilities, findings exploited now (GreyNoise or KEV), CVEs GreyNoise sees
   actively exploited, KEV, P1/P2 counts, pending actions.
2. **Asset prioritization**: a chart of each system's highest risk score stacked by
   component, then one row per system with its priority, findings, CVEs,
   **GreyNoise-active CVEs**, KEV CVEs and top score. Expand a system for its
   findings, score bars and signals. Systems are ordered by most urgent priority,
   then top risk score, then GreyNoise-active CVEs.
3. **Exploited-now vulnerabilities**: CVEs GreyNoise saw attacked or CISA lists, by
   how many assets carry them.
4. **Signal coverage**: what GreyNoise said about every distinct CVE (observed,
   quiet, no tag, not checked). "No tag" is a gap, not safety.
5. Collapsed by default: **finding detail** (ranked table plus the top 40 cards,
   each with the full score table, dimensions, evidence counts and recommended
   fix), not-yet-investigated rollup, pending actions, recent audit, and how scores
   are computed.

It stays small on large databases: a 5,000-finding import renders to a few
hundred KB because only the highest-ranked findings get a detail card and every
cut is stated on the page. Priority filters are disclosed in the header,
un-investigated imports are rolled up as counts, and SAMPLE-fixture provenance is
carried into the page. If an asset inventory is configured its optional `label` is
printed as an "Asset context" note (use it to flag an illustrative inventory).
Resolved and not-seen findings are excluded by default and the header states how
many (`--include-resolved` / `include_resolved=True` restores them). The asset view
covers investigated findings only, and says how many imported findings are not.
Reports contain vulnerability data — share them accordingly.

To investigate a whole import (instead of 25 findings per MCP call), run the
sweep in your own terminal so keys come from your environment:

```bash
uv run riskproof investigate-pending              # all open, uninvestigated findings
uv run riskproof investigate-pending --limit 500  # the 500 best candidates first
```

Run it where `GREYNOISE_API_KEY` is exported; without it the command warns and the
records get no GreyNoise reading (scores show "3 of 4 inputs"). Once the key is set,
`--refresh-greynoise` re-investigates findings whose stored intel lacks a live
GreyNoise reading.

It ranks like an import (KEV-listed first, then severity, VPR, CVSS), works in
batches of 25, keeps everything finished if it is interrupted, and resumes with
what is still pending. GreyNoise lookups are capped per batch by
`RISKPROOF_GREYNOISE_MAX_CALLS_PER_RUN` and cached.

### From Tenable Vulnerability Management (Tenable One)

Set the API keys in the **server's environment** (never in tool input, never
in `.env`):

```bash
claude mcp add riskproof -e TENABLE_ACCESS_KEY=... -e TENABLE_SECRET_KEY=... -- \
  uv --directory /absolute/path/to/RiskProof run riskproof serve
```

`import_tenable(severity=["critical","high"], since_days=30, cidr_range="10.0.0.0/24")`
runs a read-only vulnerability export (`POST /vulns/export`, poll status,
download chunks) and returns the same summary. Findings are stored with
`source="tenable"`; the audit log records the export UUID and filters, never
the keys. The key pair's Tenable user needs permission to export
vulnerabilities. Status: covered by mock-transport tests only — verify against
a real tenant before relying on it.

#### Scoping an import by Tenable asset tags

Tags let you ask for a slice of the estate ("criticals from the DMZ", "the
network team's assets") instead of everything:

1. `list_tenable_tags()` shows the tenant's tag categories and values (read-only,
   `GET /tags/values`). Names must match Tenable exactly.
2. `import_tenable(severity=["critical"], tags={"Location": ["DMZ"]})` adds
   Tenable's documented `tag.Location` export filter. Values within a category
   are OR-ed (`{"Team": ["Network","Edge"]}`); separate categories are AND-ed.
3. The asset keeps its tags (`asset.tags`), shown on the report's asset lines and in
   investigation output. Tenable does not document whether exported records carry
   an asset's tags, so RiskProof uses them when present and otherwise records the
   tags you filtered on (only categories with a single value; a multi-value
   category is not guessed). The import warnings say which happened, and
   `tags.recorded_from_export` / `recorded_from_filter` count it. Tags are kept when a
   later import lacks them and replaced when one includes them.
4. A tag-filtered import is a partial listing: it **never reconciles**.
5. What a tag *means* for risk is yours to say, in the inventory (below):
   `{"tags": {"Location": "DMZ"}, "internet_facing": true}` makes every DMZ
   asset internet-facing, so a KEV finding there reaches P1.

Status: the filter and tag-listing requests follow Tenable's documentation and are
covered by mock-transport tests only. Run `list_tenable_tags` and a small tagged
import (`limit=20`) against your tenant before relying on them.

#### Weekly workflow

Re-importing the same Tenable scope each week keeps the database current:

1. `import_tenable(limit=50000)` with the default filters (severity critical/high,
   state open/reopened).
2. Read `changes` (new / updated / reopened / resolved) and `reconciliation`:
   findings stored from earlier imports that this complete export no longer
   lists. The default is a **preview**; nothing is changed.
3. If the preview looks right, re-run with `reconcile=True` to mark them
   `not_seen`. That is an inference from absence, not proof of a fix, and it is
   reversible: a finding that reappears becomes `open` again (counted as
   `reopened`). Reconciliation is skipped (with a `skipped_reason`) for
   truncated, empty, or partial-scope exports (`since_days`, `cidr_range`,
   `only_with_cve`, `tags`, or a state filter without both open and reopened), and when
   more than `RISKPROOF_RECONCILE_MAX_MISSING_FRACTION` (default 0.5) of
   in-scope open findings would be flagged. Only `source="tenable"` findings of
   the imported severities are ever reconciled.
4. Optionally import `state=["fixed"]` with `since_days=14` to record fixes
   Tenable has confirmed (`resolved`). This import never reconciles.
5. Investigate the top candidates.
6. Generate the report.

Nothing is deleted: investigations, the audit log, and pending actions are kept
for resolved and not-seen findings. Existing databases upgrade in place on next
start (schema v2); copy the file first, e.g.
`cp ~/.riskproof/riskproof.db ~/.riskproof/riskproof.db.bak-v1`.

### GreyNoise exploitation signal (optional)

GreyNoise shows whether a CVE is being scanned for or exploited on the internet
**right now**, which EPSS (a 30-day statistic) and KEV (curated, so it lags)
cannot. A free GreyNoise key is enough. Set it in the **server's environment**,
never in `.env` or tool input, and restart the server:

```bash
claude mcp add riskproof -e GREYNOISE_API_KEY=... -- \
  uv --directory /absolute/path/to/RiskProof run riskproof serve
```

`investigate_finding` then adds a GreyNoise reading per CVE: `observed`
(malicious-tagged scanning seen in the last `RISKPROOF_GREYNOISE_WINDOW_DAYS`,
default 3), `quiet` (tags exist, no recent activity), `no_data` (GreyNoise has no
tag for the CVE) or `not_checked` (call budget, rate limit, or error).
**`no_data` and `not_checked` are gaps, not low risk.** The reading means
attempts against GreyNoise's own sensors; it is not evidence that your asset was
targeted or compromised.

Calls are kept small: one download of GreyNoise's tag catalog (cached 24 h),
then per-tag activity only for CVEs under investigation (cached 8 h), capped at
`RISKPROOF_GREYNOISE_MAX_CALLS_PER_RUN` (default 100). A rate-limit response
stops the run. Only GreyNoise tag ids are sent; your CVEs, hosts and IPs never
leave. Without a key nothing changes. Offline mode uses a clearly labeled
SAMPLE fixture.

### Add business context (asset inventory)

Scanners don't know which assets matter. Without that, imported findings
have *unknown* exposure and business impact, and the decision-table rows
that reach P1 through internet exposure or asset criticality never fire —
even a KEV-listed finding on a crown-jewel server stops at P2. Record that
context in
`~/.riskproof/assets.json` (or the path in `RISKPROOF_ASSET_INVENTORY`):

```json
{
  "rules": [
    {"match": "10.20.0.0/16", "environment": "production", "internet_facing": false},
    {"match": "10.20.99.0/24", "environment": "dmz", "internet_facing": true},
    {"match": ["web01", "web01.corp.example"], "criticality": "critical",
     "owner": "platform-team", "note": "customer checkout"}
  ]
}
```

- `match`: hostnames, FQDNs or asset ids (exact, case-insensitive), IPs, or
  CIDR ranges. List every name your scanner reports — Nessus usually reports
  the NetBIOS name (`web01`); RiskProof also matches the FQDN when the scan
  includes it.
- `tags`: match Tenable asset tags instead of (or as well as) names, e.g.
  `{"tags": {"Location": "DMZ"}, "internet_facing": true, "environment": "dmz"}` or
  `{"tags": {"Team": ["Network", "Edge"]}, "owner": "network-team"}`. Categories and
  values are case-insensitive; every listed category must be on the asset, with any
  one of its listed values. With both `match` and `tags`, both must hold. A rule needs
  `match`, `tags`, or both. Tags are captured when findings are imported (see
  "Scoping an import by Tenable asset tags").
- Optional top-level `"label"` (up to 300 characters) is printed in the report as
  an "Asset context" note; it is never used for matching. Use it to say an
  inventory is illustrative, e.g. `"label": "DEMO inventory: invented for lab data"`.
- Fields: `criticality` (`critical`/`high`/`medium`/`low`), `environment`,
  `internet_facing`, `owner`, plus a free-text `note`. Each rule must set at
  least one; unknown keys are rejected so typos cannot silently drop context.
- Each field comes from the **most specific** matching rule that sets it:
  hostname/asset-id rules beat tag rules, tag rules beat CIDRs, longer prefixes
  beat shorter ones, and earlier rules win ties. Above, `web01` at `10.20.99.7` is critical, in the
  DMZ, and internet-facing.
- Applied whenever findings are assessed: edits take effect on the next tool
  call, no re-import needed. Stored findings keep what the scanner reported.
- A missing file means "no inventory". An invalid file makes investigations
  fail with `configuration_error` until a human fixes it.
- The inventory is operator configuration: no tool can edit it, it overrides
  asset context carried on a finding, and it never applies to SAMPLE fixtures.

## Example session

> User: "Investigate the demo scan and tell me what actually matters."

1. Agent calls `investigate_finding(fixture="findings_sample.json")`
2. Agent reads the per-finding assessments (dimensions + priorities)
3. Agent calls `analyze_exploit_scenario` on the top P1
4. Agent calls `simulate_remediation` and reports options with expected effects
5. Agent calls `execute_risk_policy(finding_ids=[...])` and reports the recorded
   (dry-run) actions

> User: "What do you know about CVE-2021-44228?"

Agent calls `enrich_threat_intel(cve_ids=["CVE-2021-44228"], source="auto")`
and reports EPSS (with the statistical caveat), KEV status, and provenance.

## Offline demo data

All files in `fixtures/` are clearly-labeled SAMPLE data (see
`fixtures/README.md`). The demo dataset covers: a KEV-listed internet-facing
critical (Log4Shell), a high-EPSS non-KEV finding (regreSSHion), a KEV-listed
internal critical with modest CVSS (Zerologon), a medium noise finding
(Terrapin), and a CVE-less informational finding — exercising the full decision
table.

## Development

```bash
uv run pytest                    # tests (offline; live tests opt-in)
RISKPROOF_LIVE_TESTS=1 uv run pytest tests/test_live_intel.py   # real feeds
uv run ruff check .              # lint
uv run ruff format .             # format
```
