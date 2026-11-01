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
| `RISKPROOF_MAX_IMPORT_BYTES` | `536870912` | Largest `.nessus` file accepted |
| `RISKPROOF_TENABLE_BASE_URL` | `https://cloud.tenable.com` | Tenable VM API host (https only) |
| `RISKPROOF_ALLOWED_TARGETS` | *(empty = deny all)* | Validation allowlist (hosts/IPs/CIDRs, comma-separated) |
| `RISKPROOF_DRY_RUN` | `true` | Record actions instead of executing |
| `RISKPROOF_REQUIRE_APPROVAL` | `true` | All policy actions need human approval |

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

The server exposes seven tools over stdio:
`investigate_finding`, `enrich_threat_intel`, `verify_applicability`,
`validate_exposure`, `analyze_exploit_scenario`, `simulate_remediation`,
`execute_risk_policy`.

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
